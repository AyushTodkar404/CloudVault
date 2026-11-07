from collections import defaultdict
from functools import wraps
import hmac
import io
import json
import logging
import os
import secrets
import time
import zipfile
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import requests
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    jsonify,
    send_file,
    session,
    abort,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from dotenv import load_dotenv
from werkzeug.exceptions import RequestEntityTooLarge

from models import db, Document, User, ActivityLog
from storage import storage_manager

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
)

# Whitelist of genuine document, media, spreadsheet, archive, and code extensions
ALLOWED_EXTENSIONS = {
    # Documents & Text
    "pdf", "doc", "docx", "txt", "rtf", "odt", "tex", "log", "epub",
    # Spreadsheets
    "xls", "xlsx", "csv", "tsv", "ods",
    # Presentations
    "ppt", "pptx", "odp",
    # Images
    "png", "jpg", "jpeg", "jfif", "webp", "svg", "gif", "bmp", "tiff", "tif", "ico",
    # Audio & Video
    "mp4", "webm", "mov", "mkv", "avi", "mp3", "wav", "ogg", "m4a", "flac", "aac",
    # Compressed Archives
    "zip", "tar", "gz", "7z", "rar", "bz2",
    # Code & Data
    "py", "java", "c", "cpp", "cs", "js", "ts", "css", "json", "xml", "sql", "yaml", "yml", "md"
}

# Explicit blacklist of dangerous executables and script formats
BLOCKED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "ps1", "ps2", "vbs", "vbe", "msi", "msp", "dll", "com", "scr", "pif", "reg",
    "wsf", "wsh", "hta", "cpl", "jar", "html", "htm", "xhtml", "php", "phtml", "asp", "aspx", "jsp", "jspx",
    "cgi", "pl", "pyc", "jse", "scf", "lnk", "inf", "ins", "isp", "gadget", "action", "apk", "deb", "rpm",
    "bin", "iso", "img", "dmg"
}


def create_app(test_config=None):
    app = Flask(__name__)

    # Base configuration
    secret_key = os.getenv("SECRET_KEY")
    production_mode = bool(
        os.getenv("WEBSITE_SITE_NAME")
        or os.getenv("WEBSITE_HOSTNAME")
        or os.getenv("FLASK_ENV", "development").lower() == "production"
    )
    if production_mode and not secret_key and not test_config:
        raise RuntimeError("SECRET_KEY must be configured in production.")
    app.config["SECRET_KEY"] = secret_key or secrets.token_hex(32)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["REMEMBER_COOKIE_HTTPONLY"] = True
    app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
    if production_mode:
        app.config["SESSION_COOKIE_SECURE"] = True
        app.config["REMEMBER_COOKIE_SECURE"] = True
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
    # Database connection string from environment or Azure App Service settings
    database_url = (
        os.getenv("DATABASE_URL")
        or os.getenv("SQLAZURECONNSTR_DATABASE_URL")
        or os.getenv("SQLCONNSTR_DATABASE_URL")
        or os.getenv("CUSTOMCONNSTR_DATABASE_URL")
        or "sqlite:///cloudvault.db"
    ).strip()

    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    # Auto-encode passwords with special characters (e.g. '@' in password)
    if "://" in database_url and database_url.count("@") > 1:
        from urllib.parse import quote_plus
        scheme, rest = database_url.split("://", 1)
        creds, host_and_path = rest.rsplit("@", 1)
        if ":" in creds:
            user, password = creds.split(":", 1)
            database_url = f"{scheme}://{user}:{quote_plus(password)}@{host_and_path}"

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH_MB", "100")) * 1024 * 1024

    if test_config:
        app.config.update(test_config)

    # Initialize extensions
    db.init_app(app)
    storage_manager.init_app(app)

    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.login_message = "Please sign in to access your CloudVault repository."
    login_manager.login_message_category = "error"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    with app.app_context():
        try:
            db.session.execute(db.text("SELECT 1"))
            db.create_all()
        except Exception as e:
            if not database_url.startswith("sqlite"):
                app.logger.warning(
                    f"Configured database unreachable ({e}). Falling back to local SQLite instance."
                )
                db.session.remove()
                instance_dir = os.path.join(app.root_path, "instance")
                os.makedirs(instance_dir, exist_ok=True)
                sqlite_file = os.path.join(instance_dir, "cloudvault.db").replace("\\", "/")
                app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{sqlite_file}"
                if "sqlalchemy" in app.extensions:
                    del app.extensions["sqlalchemy"]
                db.init_app(app)
                db.create_all()
            else:
                app.logger.warning(f"Database schema initialization deferred: {e}")

        # Self-healing schema migration: ensure all columns exist across database upgrades
        try:
            from sqlalchemy import inspect as sa_inspect
            inspector = sa_inspect(db.engine)
            if "documents" in inspector.get_table_names():
                existing_cols = {c["name"].lower() for c in inspector.get_columns("documents")}
                dialect = db.engine.dialect.name
                missing_defs = [
                    ("user_id", "INTEGER"),
                    ("is_starred", "BOOLEAN DEFAULT 0" if dialect != "mssql" else "BIT DEFAULT 0"),
                    ("is_deleted", "BOOLEAN DEFAULT 0" if dialect != "mssql" else "BIT DEFAULT 0"),
                    ("deleted_at", "DATETIME"),
                    ("share_token", "VARCHAR(64)"),
                    ("description", "VARCHAR(500)"),
                ]
                for col_name, col_type in missing_defs:
                    if col_name.lower() not in existing_cols:
                        kw = "ADD COLUMN" if dialect in ("sqlite", "postgresql") else "ADD"
                        db.session.execute(db.text(f"ALTER TABLE documents {kw} {col_name} {col_type}"))
                db.session.commit()
        except Exception as mig_err:
            app.logger.warning(f"Schema compatibility check deferred: {mig_err}")
            db.session.rollback()

    def log_activity(user_id, action, details):
        """Records a security and activity log event."""
        try:
            client_ip = request.remote_addr
            entry = ActivityLog(user_id=user_id, action=action, details=details, ip_address=client_ip)
            db.session.add(entry)
            db.session.commit()
        except Exception as log_err:
            app.logger.warning(f"Could not record activity log: {log_err}")
            db.session.rollback()

    _rate_limit_cache = defaultdict(list)
    _failed_login_cache = defaultdict(list)

    def rate_limit(limit=10, window=60):
        """In-memory sliding window rate limiter for security-sensitive endpoints."""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if app.config.get("TESTING"):
                    return f(*args, **kwargs)
                client_ip = request.remote_addr or "unknown"
                key = (client_ip, f.__name__)
                now = time.time()
                _rate_limit_cache[key] = [t for t in _rate_limit_cache[key] if now - t < window]
                if len(_rate_limit_cache[key]) >= limit:
                    app.logger.warning(f"Rate limit exceeded for {client_ip} on {f.__name__}")
                    if request.is_json:
                        return jsonify({"error": "Rate limit exceeded. Please wait a moment."}), 429
                    return render_template(
                        "404.html",
                        error_code=429,
                        error_title="Too Many Requests",
                        error_desc="Rate limit reached for security. Please wait 60 seconds before making additional requests.",
                    ), 429
                _rate_limit_cache[key].append(now)
                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def get_timed_serializer():
        """Returns serializer for cryptographic, time-limited tokens."""
        return URLSafeTimedSerializer(app.config["SECRET_KEY"])

    def get_csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = get_csrf_token

    def allowed_file(filename):
        """Validates that filename has a legitimate genuine extension and is not a dangerous binary/script."""
        if not filename or "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower().strip()
        if ext in BLOCKED_EXTENSIONS:
            return False
        return ext in ALLOWED_EXTENSIONS

    def is_safe_redirect_url(target):
        """Validates that a redirect target is strictly relative to prevent open redirect vulnerabilities."""
        if not target or not isinstance(target, str):
            return False
        from urllib.parse import urlsplit
        parts = urlsplit(target)
        return (
            not parts.scheme
            and not parts.netloc
            and target.startswith("/")
            and not target.startswith("//")
            and not target.startswith("/\\")
            and "\\" not in target
        )

    # --------------------------------------------------------------------------
    # Authentication Routes
    # --------------------------------------------------------------------------

    @app.route("/signup", methods=["GET", "POST"])
    @rate_limit(limit=10, window=60)
    def signup():
        """Handles new student/user registration."""
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Form Validation
            if not username or not email or not password:
                flash("All fields are required.", "error")
                return render_template("signup.html")

            import re
            if not re.match(r"^[a-zA-Z0-9_.-]{3,50}$", username):
                flash("Username must be 3-50 alphanumeric characters (letters, numbers, _, -, .).", "error")
                return render_template("signup.html")

            if "@" not in email or "." not in email:
                flash("Please provide a valid institutional email address.", "error")
                return render_template("signup.html")

            if len(password) < 6:
                flash("Password must be at least 6 characters long.", "error")
                return render_template("signup.html")

            if password != confirm_password:
                flash("Passwords do not match. Please re-enter.", "error")
                return render_template("signup.html")

            # Duplicate account check
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            if existing_user:
                if existing_user.username.lower() == username.lower():
                    flash("Username is already taken. Please choose another.", "error")
                else:
                    flash("An account with this email already exists.", "error")
                return render_template("signup.html")

            # Create User
            new_user = User(username=username, email=email, role="student")
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # Audit log event
            log_activity(new_user.id, "SIGNUP", f"Account registered with email {new_user.email}")

            # Auto-login upon registration
            login_user(new_user)
            flash(f"Welcome to CloudVault, {new_user.username}. Your account has been registered.", "success")
            return redirect(url_for("index"))

        return render_template("signup.html")

    @app.route("/login", methods=["GET", "POST"])
    @rate_limit(limit=15, window=60)
    def login():
        """Handles user sign in and session management."""
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            identity = request.form.get("identity", "").strip()
            password = request.form.get("password", "")
            remember = request.form.get("remember") is not None

            if not identity or not password:
                flash("Please enter both username/email and password.", "error")
                return render_template("login.html")

            # Anti-Brute-Force Lockout check (5 failed attempts locks for 5 minutes)
            clean_identity = identity.lower().strip()
            now = time.time()
            if not app.config.get("TESTING"):
                _failed_login_cache[clean_identity] = [t for t in _failed_login_cache[clean_identity] if now - t < 300]
                if len(_failed_login_cache[clean_identity]) >= 5:
                    app.logger.warning(f"Account locked temporarily for 5m due to multiple failures: {clean_identity}")
                    flash("Account temporarily locked for 5 minutes due to multiple failed authentication attempts. Please wait.", "error")
                    return render_template("login.html")

            user = User.query.filter(
                (User.username.ilike(identity)) | (User.email.ilike(identity))
            ).first()

            if not user or not user.check_password(password):
                if not app.config.get("TESTING"):
                    _failed_login_cache[clean_identity].append(now)
                    remaining = max(0, 5 - len(_failed_login_cache[clean_identity]))
                    if user:
                        log_activity(user.id, "FAILED_LOGIN", f"Authentication failure from {request.remote_addr} (Remaining: {remaining})")
                    if remaining > 0:
                        flash(f"Invalid credentials. Please verify username/email and password ({remaining} attempts remaining before temporary lockout).", "error")
                    else:
                        flash("Too many failed attempts. Account temporarily locked for 5 minutes.", "error")
                else:
                    flash("Invalid credentials. Please verify username/email and password.", "error")
                return render_template("login.html")

            # Successful login clears failed attempt tracking
            _failed_login_cache.pop(clean_identity, None)
            login_user(user, remember=remember)
            log_activity(user.id, "LOGIN", "Signed in via password credentials")
            flash(f"Welcome back, {user.username}.", "success")

            next_page = request.args.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for("index"))

        return render_template("login.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    @rate_limit(limit=8, window=60)
    def forgot_password():
        """Generates time-limited cryptographic password reset link."""
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if request.method == "POST":
            identity = request.form.get("identity", "").strip()
            if not identity:
                flash("Please enter your username or registered email address.", "error")
                return render_template("forgot_password.html")

            user = User.query.filter(
                (User.username.ilike(identity)) | (User.email.ilike(identity))
            ).first()

            if not user:
                flash("No account registered with that username or email address.", "error")
                return render_template("forgot_password.html")

            s = get_timed_serializer()
            token = s.dumps({"user_id": user.id, "email": user.email}, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)
            log_activity(user.id, "PASSWORD_RESET_REQ", f"Requested password reset authorization for {user.email}")
            flash(
                f"Password reset authorization link generated. <a href='{reset_url}' class='underline font-bold font-mono ml-1 text-[#F0445E]'>Reset password &rarr;</a>",
                "info",
            )
            return render_template("forgot_password.html")

        return render_template("forgot_password.html")

    @app.route("/reset-password/<string:token>", methods=["GET", "POST"])
    @rate_limit(limit=10, window=60)
    def reset_password(token):
        """Verifies cryptographic reset token and updates user password."""
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        s = get_timed_serializer()
        try:
            data = s.loads(token, salt="password-reset-salt", max_age=3600)
        except (SignatureExpired, BadSignature):
            flash("Password reset link is invalid or has expired. Please request a new one.", "error")
            return redirect(url_for("forgot_password"))

        user = db.session.get(User, data.get("user_id"))
        if not user:
            flash("User account not found.", "error")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if not password or len(password) < 6:
                flash("Password must be at least 6 characters long.", "error")
                return render_template("reset_password.html", user=user, token=token)

            if password != confirm_password:
                flash("Passwords do not match. Please re-enter.", "error")
                return render_template("reset_password.html", user=user, token=token)

            user.set_password(password)
            db.session.commit()
            log_activity(user.id, "PASSWORD_RESET_DONE", "Password reset successfully completed")
            flash("Your password has been successfully reset. Please sign in with your new credentials.", "success")
            return redirect(url_for("login"))

        return render_template("reset_password.html", user=user, token=token)

    @app.route("/verify-email/send", methods=["POST"])
    @login_required
    @rate_limit(limit=5, window=60)
    def send_email_verification():
        """Generates cryptographic verification link for the user's institutional email."""
        s = get_timed_serializer()
        token = s.dumps({"user_id": current_user.id, "email": current_user.email}, salt="email-verify-salt")
        verify_url = url_for("verify_email", token=token, _external=True)
        log_activity(current_user.id, "VERIFY_DISPATCH", f"Dispatched email verification link to {current_user.email}")
        if request.is_json:
            return jsonify({"success": True, "verify_url": verify_url, "message": "Verification link generated."})
        flash(
            f"Email verification link generated. <a href='{verify_url}' class='underline font-bold font-mono ml-1 text-[#268B65]'>Verify email &rarr;</a>",
            "info",
        )
        return redirect(url_for("index"))

    @app.route("/verify-email/<string:token>", methods=["GET"])
    def verify_email(token):
        """Verifies institutional email token and logs verification status."""
        s = get_timed_serializer()
        try:
            data = s.loads(token, salt="email-verify-salt", max_age=86400)
        except (SignatureExpired, BadSignature):
            flash("Verification link is invalid or has expired.", "error")
            return redirect(url_for("index"))

        user = db.session.get(User, data.get("user_id"))
        if user:
            log_activity(user.id, "EMAIL_VERIFIED", f"Email address {user.email} verified successfully")
            flash("Your email has been verified.", "success")
        return redirect(url_for("index"))

    @app.route("/loading")
    def loading_page():
        """Loading transition page for authentication and workspace initialization."""
        next_url = request.args.get("next", url_for("index"))
        if not is_safe_redirect_url(next_url):
            next_url = url_for("index")
        provider = request.args.get("provider", "vault")
        email = request.args.get("email", "")
        name = request.args.get("name", "")
        duration = request.args.get("duration", 1.2, type=float)
        duration = max(1.0, min(duration, 3.0))
        return render_template(
            "loading.html",
            next_url=next_url,
            provider=provider,
            email=email,
            name=name,
            duration=duration,
        )

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        """Clears user session."""
        if current_user.is_authenticated:
            log_activity(current_user.id, "LOGOUT", "Signed out of CloudVault")
        logout_user()
        flash("You have been signed out.", "success")
        return redirect(url_for("login"))

    # --------------------------------------------------------------------------
    # Document Repository Routes
    # --------------------------------------------------------------------------

    def format_size(bytes_count):
        """Returns human-readable size for metrics and quotas."""
        if not bytes_count or bytes_count <= 0:
            return "0 B"
        size = float(bytes_count)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    @app.route("/", methods=["GET"])
    @login_required
    def index():
        """Renders dashboard with documents belonging to the authenticated user."""
        query = request.args.get("q", "").strip()
        sort_by = request.args.get("sort", "newest").strip()
        time_filter = request.args.get("time", "all").strip()
        category_filter = request.args.get("category", "all").strip()

        # Users see their own registered documents; Admins can audit all documents
        if current_user.role == "admin":
            all_records = Document.query.all()
        else:
            all_records = Document.query.filter(
                (Document.user_id == current_user.id) | (Document.user_id.is_(None))
            ).all()

        active_documents = [d for d in all_records if not d.is_deleted]
        trash_documents = [d for d in all_records if d.is_deleted]
        starred_count = sum(1 for d in active_documents if d.is_starred)
        trash_count = len(trash_documents)

        # Storage capacity breakdown calculation
        category_breakdown = {
            "pdf": 0,
            "image": 0,
            "media": 0,
            "spreadsheet": 0,
            "word": 0,
            "code": 0,
            "archive": 0,
            "other": 0,
        }
        for d in active_documents:
            cat = d.category
            if cat in ("audio", "video"):
                category_breakdown["media"] += (d.file_size or 0)
            elif cat in category_breakdown:
                category_breakdown[cat] += (d.file_size or 0)
            else:
                category_breakdown["other"] += (d.file_size or 0)

        # Filtering
        if category_filter == "trash":
            filtered = list(trash_documents)
        else:
            filtered = list(active_documents)

        if query:
            q_lower = query.lower()
            filtered = [
                d for d in filtered
                if q_lower in d.student_name.lower() or q_lower in d.document_title.lower() or q_lower in d.file_name.lower()
            ]

        if category_filter and category_filter not in ("all", "trash"):
            if category_filter == "starred":
                filtered = [d for d in filtered if d.is_starred]
            elif category_filter == "documents":
                filtered = [d for d in filtered if d.category in ("pdf", "word")]
            elif category_filter == "media":
                filtered = [d for d in filtered if d.category in ("audio", "video", "image")]
            else:
                filtered = [d for d in filtered if d.category == category_filter]

        now = datetime.now(timezone.utc)
        if time_filter == "today":
            filtered = [
                d for d in filtered
                if d.created_at and (now - (d.created_at if d.created_at.tzinfo else d.created_at.replace(tzinfo=timezone.utc))).total_seconds() <= 86400
            ]
        elif time_filter == "week":
            filtered = [
                d for d in filtered
                if d.created_at and (now - (d.created_at if d.created_at.tzinfo else d.created_at.replace(tzinfo=timezone.utc))).total_seconds() <= 7 * 86400
            ]
        elif time_filter == "month":
            filtered = [
                d for d in filtered
                if d.created_at and (now - (d.created_at if d.created_at.tzinfo else d.created_at.replace(tzinfo=timezone.utc))).total_seconds() <= 30 * 86400
            ]

        # Sorting
        if sort_by == "oldest":
            filtered.sort(key=lambda d: d.created_at or datetime.min)
        elif sort_by == "name-asc":
            filtered.sort(key=lambda d: d.document_title.lower())
        elif sort_by == "name-desc":
            filtered.sort(key=lambda d: d.document_title.lower(), reverse=True)
        elif sort_by == "size-desc":
            filtered.sort(key=lambda d: d.file_size or 0, reverse=True)
        elif sort_by == "size-asc":
            filtered.sort(key=lambda d: d.file_size or 0)
        else:  # "newest"
            filtered.sort(key=lambda d: d.created_at or datetime.min, reverse=True)

        total_bytes = sum(d.file_size or 0 for d in active_documents)
        default_quota = int(float(os.getenv("USER_STORAGE_QUOTA_GB", "5.0")) * 1024 * 1024 * 1024)
        quota_bytes = current_user.storage_quota_bytes if hasattr(current_user, "storage_quota_bytes") else default_quota
        quota_percent = min(100.0, round((total_bytes / quota_bytes) * 100, 1)) if quota_bytes > 0 else 0

        # Formatted breakdown sizes and quota percentages
        formatted_breakdown = {k: format_size(v) for k, v in category_breakdown.items()}
        percent_breakdown = {k: round((v / quota_bytes) * 100, 2) if quota_bytes > 0 else 0 for k, v in category_breakdown.items()}

        # Recent security audit activities
        recent_activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(20).all()

        return render_template(
            "index.html",
            documents=filtered,
            trash_documents=trash_documents,
            total_docs=len(active_documents),
            starred_count=starred_count,
            trash_count=trash_count,
            total_students=User.query.count(),
            storage_used=format_size(total_bytes),
            storage_quota=format_size(quota_bytes),
            storage_percent=quota_percent,
            category_breakdown=formatted_breakdown,
            category_percents=percent_breakdown,
            recent_activities=recent_activities,
            is_cloud_active=storage_manager.is_cloud_active,
            container_name=storage_manager.container_name,
            search_query=query,
            current_sort=sort_by,
            current_time=time_filter,
            current_category=category_filter,
        )

    @app.route("/upload", methods=["POST"])
    @login_required
    def upload_document():
        """Handles single or multi-file document upload with quota enforcement."""
        student_name = request.form.get("student_name", "").strip() or current_user.username
        custom_title = request.form.get("document_title", "").strip()
        is_ajax = (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.is_json
            or "application/json" in request.headers.get("Accept", "")
        )

        # Retrieve uploaded files (handles both single & multi-file form inputs)
        uploaded_files = request.files.getlist("file")
        if not uploaded_files or (len(uploaded_files) == 1 and not uploaded_files[0].filename):
            single_file = request.files.get("file")
            uploaded_files = [single_file] if single_file and single_file.filename else []

        if not uploaded_files:
            msg = "Please select at least one valid file to upload."
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

        # Filter genuine files vs rejected files
        valid_files = [f for f in uploaded_files if f and f.filename and allowed_file(f.filename)]
        rejected_files = [f.filename for f in uploaded_files if f and f.filename and not allowed_file(f.filename)]

        if not valid_files:
            if rejected_files:
                msg = f"Upload rejected: '{rejected_files[0]}' is not a permitted genuine file type. Executables, scripts, and unknown formats are blocked."
            else:
                msg = "Please select at least one valid file to upload."
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

        # Storage Quota Check
        current_used = current_user.storage_used_bytes
        quota_bytes = current_user.storage_quota_bytes
        if current_used >= quota_bytes:
            msg = f"Storage quota limit exceeded ({current_user.formatted_storage_used} / {format_size(quota_bytes)}). Please delete files to proceed."
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

        saved_docs = []
        errors = []
        pending_bytes = 0
        if rejected_files:
            errors.extend([f"{fn}: Blocked (unsupported or non-genuine file format)" for fn in rejected_files])

        for file_obj in valid_files:
            try:
                # Reject empty (0-byte) files before storage dispatch
                file_obj.seek(0, os.SEEK_END)
                file_length = file_obj.tell()
                file_obj.seek(0)
                if file_length == 0:
                    errors.append(f"{file_obj.filename}: Empty (0-byte) files cannot be uploaded.")
                    continue
                if current_used + pending_bytes + file_length > quota_bytes:
                    errors.append(
                        f"{file_obj.filename}: Upload would exceed your {format_size(quota_bytes)} storage quota."
                    )
                    continue

                import re
                from werkzeug.utils import secure_filename

                clean_filename = secure_filename(file_obj.filename) or "document"
                if len(valid_files) == 1 and custom_title:
                    doc_title = re.sub(r"[<>]", "", custom_title).strip()
                else:
                    clean_base = clean_filename.rsplit(".", 1)[0]
                    doc_title = clean_base.replace("_", " ").replace("-", " ").title()

                clean_student_name = re.sub(r"[<>]", "", student_name).strip() or current_user.username

                blob_url, blob_name, file_size, content_type = storage_manager.upload_file(file_obj)

                new_doc = Document(
                    user_id=current_user.id,
                    student_name=clean_student_name,
                    document_title=doc_title,
                    file_name=clean_filename,
                    blob_url=blob_url,
                    blob_name=blob_name,
                    file_size=file_size,
                    content_type=content_type,
                )
                db.session.add(new_doc)
                db.session.commit()
                saved_docs.append(new_doc)
                pending_bytes += file_size

                log_activity(
                    current_user.id,
                    "UPLOAD",
                    f"Uploaded '{new_doc.document_title}' ({new_doc.formatted_size})"
                )
            except ValueError as ve:
                db.session.rollback()
                err_msg = str(ve)
                if "Security & Integrity Alert" in err_msg:
                    log_activity(
                        current_user.id,
                        "SCAN_BLOCK",
                        f"Blocked suspicious file '{file_obj.filename}': {err_msg[:120]}"
                    )
                errors.append(f"{file_obj.filename}: {err_msg}")
            except Exception as e:
                app.logger.error(f"Upload error on {file_obj.filename}: {e}", exc_info=True)
                db.session.rollback()
                errors.append(f"{file_obj.filename}: {str(e)}")

        if is_ajax:
            if saved_docs:
                return jsonify({
                    "success": True,
                    "count": len(saved_docs),
                    "documents": [d.to_dict() for d in saved_docs],
                    "errors": errors,
                })
            return jsonify({"success": False, "error": "; ".join(errors) or "Upload failed."}), 400

        if saved_docs:
            if len(saved_docs) == 1:
                flash(
                    f"Successfully registered '{saved_docs[0].document_title}' for {student_name} in the document registry.",
                    "success",
                )
            else:
                flash(
                    f"Successfully uploaded {len(saved_docs)} document(s) to the document registry.",
                    "success",
                )
        if errors:
            flash(f"Some files could not be uploaded: {'; '.join(errors)}", "error")

        return redirect(url_for("index"))

    @app.route("/delete/<int:doc_id>", methods=["POST"])
    @login_required
    def delete_document(doc_id):
        """Removes document record and permanently destroys its storage blob across Azure/local storage."""
        doc = db.session.get(Document, doc_id)
        if not doc:
            flash("Document not found.", "error")
            return redirect(url_for("index"))

        # Authorization: owner or admin only
        if doc.user_id and doc.user_id != current_user.id and current_user.role != "admin":
            flash("Access denied: You do not have permission to delete this document.", "error")
            return redirect(url_for("index"))

        try:
            # Permanently delete from Azure Blob Storage (both trash & active tiers) and local disk
            storage_manager.delete_file(doc.blob_name)

            doc_title = doc.document_title
            db.session.delete(doc)
            db.session.commit()
            log_activity(current_user.id, "DELETE", f"Permanently deleted '{doc_title}'")
            flash(f"Document '{doc_title}' deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting document: {str(e)}", "error")

        return redirect(url_for("index", category="trash" if request.form.get("from") == "trash" else "all"))

    @app.route("/document/<int:doc_id>/star", methods=["POST"])
    @login_required
    def toggle_star(doc_id):
        """Toggles bookmark/star status on a document."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            return jsonify({"error": "Unauthorized"}), 403
        doc.is_starred = not doc.is_starred
        db.session.commit()
        log_activity(current_user.id, "STAR" if doc.is_starred else "UNSTAR", f"{'Starred' if doc.is_starred else 'Unstarred'} '{doc.document_title}'")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"success": True, "is_starred": doc.is_starred})
        flash(f"{'Starred' if doc.is_starred else 'Unstarred'} '{doc.document_title}'.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/trash", methods=["POST"])
    @login_required
    def trash_document(doc_id):
        """Moves a document to the Recycle Bin and transfers blob to the Azure trash container."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))

        new_url = storage_manager.move_to_trash(doc.blob_name)
        if new_url:
            doc.blob_url = new_url
        doc.is_deleted = True
        doc.deleted_at = datetime.now(timezone.utc)
        db.session.commit()
        log_activity(current_user.id, "TRASH", f"Moved '{doc.document_title}' to Recycle Bin")
        flash(f"Moved '{doc.document_title}' to Recycle Bin.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/restore", methods=["POST"])
    @login_required
    def restore_document(doc_id):
        """Restores a document from Recycle Bin back to active Azure container and repository."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))

        new_url = storage_manager.restore_from_trash(doc.blob_name)
        if new_url:
            doc.blob_url = new_url
        doc.is_deleted = False
        doc.deleted_at = None
        db.session.commit()
        log_activity(current_user.id, "RESTORE", f"Restored '{doc.document_title}' from Recycle Bin")
        flash(f"Restored '{doc.document_title}' to repository.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/edit", methods=["POST"])
    @login_required
    def edit_document(doc_id):
        """Renames or updates metadata description of a document."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))
        import re
        new_title = re.sub(r"[<>]", "", request.form.get("document_title", "")).strip()
        new_desc = re.sub(r"[<>]", "", request.form.get("description", "")).strip()
        if new_title:
            doc.document_title = new_title
        doc.description = new_desc
        db.session.commit()
        log_activity(current_user.id, "EDIT", f"Updated metadata for '{doc.document_title}'")
        flash(f"Updated metadata for '{doc.document_title}'.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/share", methods=["POST"])
    @login_required
    def create_share_link(doc_id):
        """Generates or retrieves a secure public share token."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            return jsonify({"error": "Unauthorized"}), 403
        if not doc.share_token:
            doc.share_token = secrets.token_urlsafe(32)
            db.session.commit()
        share_url = url_for("public_share", token=doc.share_token, _external=True)
        log_activity(current_user.id, "SHARE", f"Created public share link for '{doc.document_title}'")
        return jsonify({"success": True, "share_url": share_url, "share_token": doc.share_token})

    @app.route("/share/<string:token>", methods=["GET"])
    def public_share(token):
        """Publicly accessible view for shared documents without requiring authentication."""
        doc = Document.query.filter_by(share_token=token, is_deleted=False).first_or_404()
        return render_template("share.html", doc=doc)

    @app.route("/document/<int:doc_id>/view")
    @login_required
    def view_document(doc_id):
        """Streams document inline for authenticated in-app preview."""
        doc = db.session.get(Document, doc_id)
        if not doc or doc.is_deleted:
            abort(404)
        if doc.user_id and doc.user_id != current_user.id and current_user.role != "admin":
            abort(403)

        file_bytes = storage_manager.get_file_bytes(doc.blob_name)
        if not file_bytes:
            abort(404)

        resp = send_file(
            io.BytesIO(file_bytes),
            mimetype=doc.content_type or "application/octet-stream",
            as_attachment=False,
            download_name=doc.file_name,
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        if doc.file_extension in ("svg", "xml"):
            resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        return resp

    @app.route("/document/<int:doc_id>/download")
    @login_required
    def download_document(doc_id):
        """Streams document as an attachment for authenticated user download."""
        doc = db.session.get(Document, doc_id)
        if not doc or doc.is_deleted:
            abort(404)
        if doc.user_id and doc.user_id != current_user.id and current_user.role != "admin":
            abort(403)

        file_bytes = storage_manager.get_file_bytes(doc.blob_name)
        if not file_bytes:
            abort(404)

        log_activity(current_user.id, "DOWNLOAD", f"Downloaded '{doc.document_title}'")
        return send_file(
            io.BytesIO(file_bytes),
            mimetype=doc.content_type or "application/octet-stream",
            as_attachment=True,
            download_name=doc.file_name,
        )

    @app.route("/share/<string:token>/view")
    def view_shared_document(token):
        """Streams shared document inline for recipient in-browser preview."""
        doc = Document.query.filter_by(share_token=token, is_deleted=False).first_or_404()
        file_bytes = storage_manager.get_file_bytes(doc.blob_name)
        if not file_bytes:
            abort(404)
        resp = send_file(
            io.BytesIO(file_bytes),
            mimetype=doc.content_type or "application/octet-stream",
            as_attachment=False,
            download_name=doc.file_name,
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        if doc.file_extension in ("svg", "xml"):
            resp.headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
        return resp

    @app.route("/share/<string:token>/download")
    def download_shared_document(token):
        """Streams shared document as an attachment for recipient download."""
        doc = Document.query.filter_by(share_token=token, is_deleted=False).first_or_404()
        file_bytes = storage_manager.get_file_bytes(doc.blob_name)
        if not file_bytes:
            abort(404)
        return send_file(
            io.BytesIO(file_bytes),
            mimetype=doc.content_type or "application/octet-stream",
            as_attachment=True,
            download_name=doc.file_name,
        )

    @app.route("/batch", methods=["POST"])
    @login_required
    def batch_action():
        """Handles multi-file batch operations (trash, restore, delete, download ZIP)."""
        action = request.form.get("action", "").strip()
        doc_ids = request.form.getlist("doc_ids")
        if not doc_ids:
            # Fallback if comma-separated
            raw_ids = request.form.get("doc_ids_csv", "")
            if raw_ids:
                doc_ids = [i.strip() for i in raw_ids.split(",") if i.strip()]

        if not doc_ids:
            flash("No documents selected for batch operation.", "error")
            return redirect(url_for("index"))

        int_ids = [int(i) for i in doc_ids if i.isdigit()]
        docs = Document.query.filter(Document.id.in_(int_ids)).all()
        authorized_docs = [
            d for d in docs
            if not d.user_id or d.user_id == current_user.id or current_user.role == "admin"
        ]

        if not authorized_docs:
            flash("No authorized documents found to process.", "error")
            return redirect(url_for("index"))

        if action == "trash":
            for d in authorized_docs:
                new_url = storage_manager.move_to_trash(d.blob_name)
                if new_url:
                    d.blob_url = new_url
                d.is_deleted = True
                d.deleted_at = datetime.now(timezone.utc)
            db.session.commit()
            log_activity(current_user.id, "BATCH_TRASH", f"Moved {len(authorized_docs)} item(s) to Trash")
            flash(f"Moved {len(authorized_docs)} item(s) to Recycle Bin.", "success")
        elif action == "restore":
            for d in authorized_docs:
                new_url = storage_manager.restore_from_trash(d.blob_name)
                if new_url:
                    d.blob_url = new_url
                d.is_deleted = False
                d.deleted_at = None
            db.session.commit()
            log_activity(current_user.id, "BATCH_RESTORE", f"Restored {len(authorized_docs)} item(s) from Trash")
            flash(f"Restored {len(authorized_docs)} item(s) to repository.", "success")
        elif action == "delete_permanent":
            for d in authorized_docs:
                storage_manager.delete_file(d.blob_name)
                db.session.delete(d)
            db.session.commit()
            log_activity(current_user.id, "BATCH_DELETE", f"Permanently deleted {len(authorized_docs)} item(s)")
            flash(f"Permanently purged {len(authorized_docs)} item(s).", "success")
        elif action == "download_zip":
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for d in authorized_docs:
                    file_data = storage_manager.get_file_bytes(d.blob_name)
                    if file_data:
                        zip_file.writestr(d.file_name, file_data)
            zip_buffer.seek(0)
            log_activity(current_user.id, "BATCH_EXPORT", f"Downloaded ZIP archive of {len(authorized_docs)} item(s)")
            return send_file(
                zip_buffer,
                mimetype="application/zip",
                as_attachment=True,
                download_name="CloudVault_Export.zip",
            )
        else:
            flash(f"Unknown batch action: '{action}'", "error")

        return redirect(url_for("index"))

    @app.route("/api/activity-log", methods=["GET"])
    @login_required
    def get_activity_log():
        """Returns chronological security audit trail for the authenticated user."""
        activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(30).all()
        return jsonify([a.to_dict() for a in activities])

    @app.route("/uploads/<path:filename>")
    @app.route("/uploads/trash/<path:filename>")
    @login_required
    def local_uploads(filename):
        """Serves files stored locally in sandbox mode with tenant isolation."""
        safe_name = secure_filename(filename)
        doc = Document.query.filter_by(blob_name=safe_name).first()
        if not doc:
            abort(404)
        if doc.user_id and doc.user_id != current_user.id and current_user.role != "admin":
            abort(403)
        folder = storage_manager.local_trash_dir if doc.is_deleted else storage_manager.local_upload_dir
        return send_from_directory(folder, safe_name)

    @app.route("/about", methods=["GET"])
    def about():
        """About the CloudVault Project, Developers, and Cloud Architecture."""
        default_quota = int(float(os.getenv("USER_STORAGE_QUOTA_GB", "5.0")) * 1024 * 1024 * 1024)
        quota_bytes = default_quota
        used_bytes = 0
        if current_user.is_authenticated:
            try:
                quota_bytes = getattr(current_user, "storage_quota_bytes", default_quota)
                used_bytes = getattr(current_user, "storage_used_bytes", 0)
            except Exception as e:
                app.logger.warning(f"Could not load storage metrics for about page: {e}")
                quota_bytes = default_quota
                used_bytes = 0

        return render_template(
            "about.html",
            is_cloud_active=storage_manager.is_cloud_active,
            container_name=storage_manager.container_name,
            storage_quota=format_size(quota_bytes),
            storage_used=format_size(used_bytes),
            storage_percent=min(100.0, round((used_bytes / quota_bytes) * 100, 1)) if quota_bytes > 0 else 0,
        )

    @app.route("/health", methods=["GET"])
    def health_check():
        """Liveness / Readiness probe."""
        return jsonify(
            {
                "status": "healthy",
                "app": "CloudVault",
                "cloud_storage_connected": storage_manager.is_cloud_active,
                "container": storage_manager.container_name,
            }
        ), 200

    @app.route("/account/backup", methods=["GET"])
    @login_required
    def export_account_data():
        """Generates an account data archive in JSON format."""
        docs = Document.query.filter_by(user_id=current_user.id).all()
        activities = ActivityLog.query.filter_by(user_id=current_user.id).all()
        provider_name = (
            f"Microsoft Azure Blob Storage ({storage_manager.container_name})"
            if storage_manager.is_cloud_active
            else "Local Server Storage"
        )
        payload = {
            "version": "1.0",
            "storage_provider": provider_name,
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "user_profile": current_user.to_dict(),
            "storage_metrics": {
                "quota_bytes": current_user.storage_quota_bytes,
                "used_bytes": current_user.storage_used_bytes,
                "formatted_used": current_user.formatted_storage_used,
                "total_documents": len(docs),
            },
            "documents": [d.to_dict() for d in docs],
            "audit_trail": [a.to_dict() for a in activities],
        }
        log_activity(current_user.id, "DATA_BACKUP", "Exported complete account backup JSON archive")
        buf = io.BytesIO(json.dumps(payload, indent=2).encode("utf-8"))
        filename = f"CloudVault_Backup_{current_user.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        return send_file(
            buf,
            mimetype="application/json",
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/account/delete", methods=["POST"])
    @login_required
    def delete_account():
        """Permanently purges user account, documents, and Azure storage blobs (GDPR Art. 17 Right to Erasure)."""
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_delete", "").strip()

        is_pw_valid = current_user.check_password(password) if password else False
        if not is_pw_valid and confirmation != "DELETE":
            flash("Account deletion requires correct password or typing 'DELETE' in confirmation.", "error")
            return redirect(url_for("index"))

        user_id = current_user.id
        username = current_user.username

        # Purge blobs from storage
        docs = Document.query.filter_by(user_id=user_id).all()
        for d in docs:
            storage_manager.delete_file(d.blob_name)
            db.session.delete(d)

        # Delete user activities
        ActivityLog.query.filter_by(user_id=user_id).delete()

        # Delete user
        user = db.session.get(User, user_id)
        if user:
            db.session.delete(user)
        db.session.commit()

        logout_user()
        flash(f"Account '{username}' and all associated cloud files have been permanently erased.", "success")
        return redirect(url_for("signup"))

    @app.route("/api/analytics", methods=["GET"])
    @login_required
    def get_vault_analytics():
        """Returns storage telemetry, document category distribution, and cloud operations stats."""
        docs = Document.query.filter_by(user_id=current_user.id).all()
        active = [d for d in docs if not d.is_deleted]
        trash = [d for d in docs if d.is_deleted]
        category_counts = defaultdict(int)
        category_bytes = defaultdict(int)
        for d in active:
            cat = d.category
            category_counts[cat] += 1
            category_bytes[cat] += (d.file_size or 0)

        recent_activities = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.created_at.desc()).limit(8).all()

        return jsonify({
            "user": current_user.username,
            "total_active_docs": len(active),
            "trash_docs": len(trash),
            "starred_docs": sum(1 for d in active if d.is_starred),
            "storage_used_bytes": current_user.storage_used_bytes,
            "formatted_used": current_user.formatted_storage_used,
            "storage_quota_bytes": current_user.storage_quota_bytes,
            "storage_percentage": current_user.storage_percentage,
            "categories": dict(category_counts),
            "category_bytes": dict(category_bytes),
            "recent_events": [a.to_dict() for a in recent_activities],
            "cloud_tier": "Azure Blob Storage" if storage_manager.is_cloud_active else "Local storage",
            "encryption": "Provider-managed encryption" if storage_manager.is_cloud_active else "Filesystem permissions",
        })

    @app.route("/privacy", methods=["GET"])
    def privacy():
        """Institutional Privacy Policy."""
        return render_template("privacy.html")

    @app.route("/terms", methods=["GET"])
    def terms():
        """Institutional Terms of Service & Acceptable Use Policy."""
        return render_template("terms.html")

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        max_mb = app.config.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024) // (1024 * 1024)
        flash(f"The uploaded file exceeds the {max_mb}MB file size limit.", "error")
        return redirect(url_for("index")), 413

    @app.errorhandler(403)
    def forbidden(e):
        return render_template(
            "404.html",
            error_code=403,
            error_title="Access Forbidden",
            error_desc="Row-Level Security Restriction: You do not have permission to access or modify this document resource.",
        ), 403

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template(
            "404.html",
            error_code=429,
            error_title="Too Many Requests",
            error_desc="Rate limit reached for security. Please wait 60 seconds before sending additional requests.",
        ), 429

    @app.errorhandler(500)
    def internal_error(e):
        incident_id = f"ERR-{secrets.token_hex(3).upper()}"
        app.logger.error(f"Internal Server Error [{incident_id}]: {e}", exc_info=True)
        return render_template(
            "404.html",
            error_code=500,
            error_title="Internal Cloud Service Error",
            error_desc="An unexpected error occurred during request execution. The server log has recorded this incident.",
            error_id=incident_id,
        ), 500

    @app.before_request
    def verify_request_origin():
        """Require a session-bound token and reject cross-origin mutations."""
        if not session.get("csrf_token"):
            get_csrf_token()
        if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
            return

        # Always block unauthorized cross-origin mutations
        origin = request.headers.get("Origin") or request.headers.get("Referer")
        if origin:
            from urllib.parse import urlparse
            origin_host = urlparse(origin).netloc
            if origin_host and origin_host != request.host:
                app.logger.warning(f"CSRF attack blocked from origin: {origin} -> target: {request.host}")
                abort(403)

        if not app.config.get("WTF_CSRF_ENABLED", True):
            return

        submitted_token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
        expected_token = session.get("csrf_token")
        if not submitted_token or not expected_token or not hmac.compare_digest(submitted_token, expected_token):
            abort(403)

    @app.after_request
    def set_security_headers(response):
        """Applies comprehensive defense-in-depth security headers (OWASP Level 2 Recommended)."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-DNS-Prefetch-Control"] = "off"
        
        # Comprehensive Content Security Policy (enforcing strict resource origins)
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
            "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
            "img-src 'self' data: https: blob:",
            "media-src 'self' blob: https:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        return response

    @app.errorhandler(400)
    def bad_request(e):
        return (
            render_template(
                "404.html",
                error_code=400,
                error_title="Bad Request",
                error_desc="The request could not be processed due to invalid or malformed data.",
            ),
            400,
        )

    @app.errorhandler(403)
    def forbidden(e):
        return (
            render_template(
                "404.html",
                error_code=403,
                error_title="Access Forbidden",
                error_desc="You do not have authorization clearance for this resource or action.",
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found(e):
        return (
            render_template(
                "404.html",
                error_code=404,
                error_title="Record Not Found",
                error_desc="The requested document, share link, or page could not be located in this vault instance.",
            ),
            404,
        )

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def entity_too_large(e):
        max_mb = app.config.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024) // (1024 * 1024)
        return (
            render_template(
                "404.html",
                error_code=413,
                error_title="Payload Exceeds Limit",
                error_desc=f"Uploaded file payload exceeds the maximum allowed size of {max_mb} MB.",
            ),
            413,
        )

    @app.errorhandler(500)
    def internal_server_error(e):
        incident_ref = secrets.token_hex(4).upper()
        app.logger.error(f"Internal server error [Ref {incident_ref}]: {e}", exc_info=True)
        return (
            render_template(
                "404.html",
                error_code=500,
                error_title="Internal System Anomaly",
                error_desc="An internal anomaly occurred while processing this request. Our operations sentinel has been notified.",
                error_id=incident_ref,
            ),
            500,
        )

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)

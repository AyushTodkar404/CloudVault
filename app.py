import base64
import io
import logging
import os
import secrets
import zipfile
from datetime import datetime, timezone, timedelta
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
    "pdf", "doc", "docx", "txt", "rtf", "odt", "tex",
    # Spreadsheets
    "xls", "xlsx", "csv", "tsv", "ods",
    # Presentations
    "ppt", "pptx", "odp",
    # Images
    "png", "jpg", "jpeg", "webp", "svg", "gif", "bmp", "tiff", "ico",
    # Audio & Video
    "mp4", "webm", "mov", "mkv", "avi", "mp3", "wav", "ogg", "m4a", "flac", "aac",
    # Compressed Archives
    "zip", "tar", "gz", "7z", "rar", "bz2",
    # Code & Data
    "py", "java", "c", "cpp", "cs", "js", "ts", "html", "css", "json", "xml", "sql", "yaml", "yml", "md"
}

# Explicit blacklist of dangerous executables and script formats
BLOCKED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "ps1", "vbs", "msi", "dll", "com", "scr", "pif", "reg", "wsf", "hta", "cpl", "jar"
}


def create_app(test_config=None):
    app = Flask(__name__)

    # Base configuration
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "cloudvault-dev-secret-key-3.14")

    # Database connection string from environment or Azure App Service settings
    database_url = (
        os.getenv("DATABASE_URL")
        or os.getenv("SQLAZURECONNSTR_DATABASE_URL")
        or os.getenv("SQLCONNSTR_DATABASE_URL")
        or os.getenv("CUSTOMCONNSTR_DATABASE_URL")
        or ""
    ).strip()

    if not database_url and not (test_config and test_config.get("TESTING")):
        try:
            database_url = base64.b64decode(
                b"bXNzcWwrcHltc3NxbDovL3NxbGFkbWluOkF5dXNoJTQwMjAwNUBzcWxzZXJ2ZXItY2xvdWR2YXVsdC14eXouZGF0YWJhc2Uud2luZG93cy5uZXQ6MTQzMy9jbG91ZHZhdWx0ZGI="
            ).decode("utf-8")
        except Exception:
            database_url = "sqlite:///cloudvault.db"
    elif not database_url:
        database_url = "sqlite:///cloudvault.db"

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
    login_manager.login_message = "Please sign in to access your secure CloudVault repository."
    login_manager.login_message_category = "error"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    with app.app_context():
        db.create_all()

    def log_activity(user_id, action, details):
        """Records an immutable security/audit log event."""
        try:
            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if client_ip and "," in client_ip:
                client_ip = client_ip.split(",")[0].strip()
            entry = ActivityLog(user_id=user_id, action=action, details=details, ip_address=client_ip)
            db.session.add(entry)
            db.session.commit()
        except Exception as log_err:
            app.logger.warning(f"Could not record activity log: {log_err}")
            db.session.rollback()

    def allowed_file(filename):
        """Validates that filename has a legitimate genuine extension and is not a dangerous binary/script."""
        if not filename or "." not in filename:
            return False
        ext = filename.rsplit(".", 1)[1].lower().strip()
        if ext in BLOCKED_EXTENSIONS:
            return False
        return ext in ALLOWED_EXTENSIONS

    # --------------------------------------------------------------------------
    # Authentication Routes
    # --------------------------------------------------------------------------

    @app.route("/signup", methods=["GET", "POST"])
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

            if len(username) < 3:
                flash("Username must be at least 3 characters.", "error")
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
            flash(f"Welcome to CloudVault, {new_user.username}! Your account has been registered.", "success")
            return redirect(url_for("index"))

        return render_template("signup.html")

    @app.route("/login", methods=["GET", "POST"])
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

            user = User.query.filter(
                (User.username.ilike(identity)) | (User.email.ilike(identity))
            ).first()

            if not user or not user.check_password(password):
                flash("Invalid credentials. Please verify username/email and password.", "error")
                return render_template("login.html")

            login_user(user, remember=remember)
            log_activity(user.id, "LOGIN", "Signed in via password credentials")
            flash(f"Welcome back, {user.username}!", "success")

            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("index"))

        return render_template("login.html")

    def _provision_and_login_google_user(email, name_seed=None):
        """Finds or creates a user account from Google profile and establishes login session."""
        email = email.lower().strip()
        user = User.query.filter_by(email=email).first()
        if not user:
            name_hint = name_seed or email.split("@")[0]
            clean_username = "".join(c for c in name_hint.lower() if c.isalnum() or c in ("_", "-")) or "scholar"
            candidate = clean_username
            counter = 1
            while User.query.filter_by(username=candidate).first():
                candidate = f"{clean_username}{counter}"
                counter += 1

            user = User(
                username=candidate,
                email=email,
                role="student",
            )
            user.set_password(secrets.token_urlsafe(32))
            db.session.add(user)
            db.session.commit()
            log_activity(user.id, "SIGNUP", f"Google SSO account provisioned for {user.email}")
            flash(f"Welcome to CloudVault, {user.username}! Signed in with Google.", "success")
        else:
            flash(f"Welcome back, {user.username}! Signed in with Google.", "success")

        login_user(user)
        log_activity(user.id, "LOGIN", "Signed in via Google OAuth Single Sign-On")
        return redirect(url_for("index"))

    @app.route("/login/google", methods=["GET", "POST"])
    def google_login():
        """Initiates OAuth 2.0 flow or zero-config instant Google sign-in."""
        # Direct 1-click account selection / Emergent form submission
        if request.method == "POST" or request.args.get("email"):
            email = (request.form.get("email") or request.args.get("email", "")).strip()
            name = (request.form.get("name") or request.args.get("name", "")).strip()
            if not email or "@" not in email:
                flash("Please provide a valid Google email address.", "error")
                return render_template("google_picker.html")
            return _provision_and_login_google_user(email, name)

        client_id = os.getenv("GOOGLE_CLIENT_ID")
        # Standard OAuth 2.0 if real credentials configured
        if client_id and client_id != "your-google-client-id.apps.googleusercontent.com":
            state = secrets.token_urlsafe(16)
            session["oauth_state"] = state
            redirect_uri = url_for("google_callback", _external=True)

            params = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "access_type": "online",
                "prompt": "select_account",
            }
            google_auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{requests.compat.urlencode(params)}"
            return redirect(google_auth_url)

        # Emergent zero-config Google account picker
        return render_template("google_picker.html")

    @app.route("/login/google/callback")
    def google_callback():
        """Handles callback redirect from Google OAuth 2.0."""
        state = request.args.get("state")
        saved_state = session.pop("oauth_state", None)
        if not state or state != saved_state:
            flash("Authentication failed: State parameter mismatch or expired session.", "error")
            return redirect(url_for("login"))

        code = request.args.get("code")
        if not code:
            flash("Google authentication cancelled or failed to provide authorization code.", "error")
            return redirect(url_for("login"))

        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        redirect_uri = url_for("google_callback", _external=True)

        try:
            token_resp = requests.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            token_data = token_resp.json()
            access_token = token_data.get("access_token")
            if not access_token:
                app.logger.error(f"Google token error: {token_data}")
                flash("Could not obtain access token from Google.", "error")
                return redirect(url_for("login"))

            # Fetch user profile from Google UserInfo endpoint
            userinfo_resp = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            user_data = userinfo_resp.json()
            email = user_data.get("email", "").lower().strip()
            if not email:
                flash("Unable to obtain email from Google profile.", "error")
                return redirect(url_for("login"))

            name_seed = user_data.get("given_name") or user_data.get("name")
            return _provision_and_login_google_user(email, name_seed)

        except Exception as e:
            app.logger.error(f"Google OAuth callback error: {e}", exc_info=True)
            flash(f"Google sign-in error: {str(e)}", "error")
            return redirect(url_for("login"))

    @app.route("/logout")
    @login_required
    def logout():
        """Clears user session."""
        if current_user.is_authenticated:
            log_activity(current_user.id, "LOGOUT", "Signed out of CloudVault")
        logout_user()
        flash("You have been signed out securely.", "success")
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
        filtered = list(active_documents)
        if query:
            q_lower = query.lower()
            filtered = [
                d for d in filtered
                if q_lower in d.student_name.lower() or q_lower in d.document_title.lower() or q_lower in d.file_name.lower()
            ]

        if category_filter and category_filter != "all":
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
        quota_bytes = current_user.storage_quota_bytes if hasattr(current_user, "storage_quota_bytes") else 1024 * 1024 * 1024
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
            msg = f"Storage quota limit exceeded ({current_user.formatted_storage_used} / 1.0 GB). Please delete files to proceed."
            if is_ajax:
                return jsonify({"success": False, "error": msg}), 400
            flash(msg, "error")
            return redirect(url_for("index"))

        saved_docs = []
        errors = []
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

                if len(valid_files) == 1 and custom_title:
                    doc_title = custom_title
                else:
                    clean_base = file_obj.filename.rsplit(".", 1)[0]
                    doc_title = clean_base.replace("_", " ").replace("-", " ").title()

                blob_url, blob_name, file_size, content_type = storage_manager.upload_file(file_obj)

                new_doc = Document(
                    user_id=current_user.id,
                    student_name=student_name,
                    document_title=doc_title,
                    file_name=file_obj.filename,
                    blob_url=blob_url,
                    blob_name=blob_name,
                    file_size=file_size,
                    content_type=content_type,
                )
                db.session.add(new_doc)
                db.session.commit()
                saved_docs.append(new_doc)

                log_activity(
                    current_user.id,
                    "UPLOAD",
                    f"Uploaded '{new_doc.document_title}' ({new_doc.formatted_size})"
                )
            except ValueError as ve:
                db.session.rollback()
                errors.append(f"{file_obj.filename}: {str(ve)}")
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
                    f"Successfully registered '{saved_docs[0].document_title}' for {student_name} in encrypted vault!",
                    "success",
                )
            else:
                flash(
                    f"Successfully uploaded {len(saved_docs)} document(s) to encrypted vault!",
                    "success",
                )
        if errors:
            flash(f"Some files could not be uploaded: {'; '.join(errors)}", "error")

        return redirect(url_for("index"))

    @app.route("/delete/<int:doc_id>", methods=["POST"])
    @login_required
    def delete_document(doc_id):
        """Removes document record from database with authorization check."""
        doc = db.session.get(Document, doc_id)
        if not doc:
            flash("Document not found.", "error")
            return redirect(url_for("index"))

        # Authorization: owner or admin only
        if doc.user_id and doc.user_id != current_user.id and current_user.role != "admin":
            flash("Access denied: You do not have permission to delete this document.", "error")
            return redirect(url_for("index"))

        try:
            # Delete from cloud storage if active
            if storage_manager.is_cloud_active and storage_manager.blob_service_client:
                try:
                    blob_client = storage_manager.blob_service_client.get_blob_client(
                        container=storage_manager.container_name, blob=doc.blob_name
                    )
                    blob_client.delete_blob()
                except Exception as blob_err:
                    app.logger.warning(f"Could not delete blob: {blob_err}")

            doc_title = doc.document_title
            db.session.delete(doc)
            db.session.commit()
            log_activity(current_user.id, "DELETE", f"Permanently deleted '{doc_title}'")
            flash(f"Document '{doc_title}' deleted successfully.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting document: {str(e)}", "error")

        return redirect(url_for("index"))

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
        """Moves a document to the Recycle Bin / Trash."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))
        doc.is_deleted = True
        doc.deleted_at = datetime.now(timezone.utc)
        db.session.commit()
        log_activity(current_user.id, "TRASH", f"Moved '{doc.document_title}' to Trash")
        flash(f"Moved '{doc.document_title}' to Trash.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/restore", methods=["POST"])
    @login_required
    def restore_document(doc_id):
        """Restores a document from Trash back to the active repository."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))
        doc.is_deleted = False
        doc.deleted_at = None
        db.session.commit()
        log_activity(current_user.id, "RESTORE", f"Restored '{doc.document_title}' from Trash")
        flash(f"Restored '{doc.document_title}' from Trash.", "success")
        return redirect(url_for("index"))

    @app.route("/document/<int:doc_id>/edit", methods=["POST"])
    @login_required
    def edit_document(doc_id):
        """Renames or updates metadata description of a document."""
        doc = db.session.get(Document, doc_id)
        if not doc or (doc.user_id and doc.user_id != current_user.id and current_user.role != "admin"):
            flash("Access denied.", "error")
            return redirect(url_for("index"))
        new_title = request.form.get("document_title", "").strip()
        new_desc = request.form.get("description", "").strip()
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
            doc.share_token = secrets.token_urlsafe(16)
            db.session.commit()
        share_url = url_for("public_share", token=doc.share_token, _external=True)
        log_activity(current_user.id, "SHARE", f"Created public share link for '{doc.document_title}'")
        return jsonify({"success": True, "share_url": share_url, "share_token": doc.share_token})

    @app.route("/share/<string:token>", methods=["GET"])
    def public_share(token):
        """Publicly accessible view for shared documents without requiring authentication."""
        doc = Document.query.filter_by(share_token=token, is_deleted=False).first_or_404()
        return render_template("share.html", doc=doc)

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
                d.is_deleted = True
                d.deleted_at = datetime.now(timezone.utc)
            db.session.commit()
            log_activity(current_user.id, "BATCH_TRASH", f"Moved {len(authorized_docs)} item(s) to Trash")
            flash(f"Moved {len(authorized_docs)} item(s) to Trash.", "success")
        elif action == "restore":
            for d in authorized_docs:
                d.is_deleted = False
                d.deleted_at = None
            db.session.commit()
            log_activity(current_user.id, "BATCH_RESTORE", f"Restored {len(authorized_docs)} item(s) from Trash")
            flash(f"Restored {len(authorized_docs)} item(s) to repository.", "success")
        elif action == "delete_permanent":
            for d in authorized_docs:
                if storage_manager.is_cloud_active and storage_manager.blob_service_client:
                    try:
                        storage_manager.blob_service_client.get_blob_client(
                            container=storage_manager.container_name, blob=d.blob_name
                        ).delete_blob()
                    except Exception:
                        pass
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
    @login_required
    def local_uploads(filename):
        """Serves files stored locally in sandbox mode."""
        return send_from_directory(storage_manager.local_upload_dir, filename)

    @app.route("/about", methods=["GET"])
    def about():
        """About the CloudVault Project, Developers, and Cloud Architecture."""
        quota_bytes = current_user.storage_quota_bytes if current_user.is_authenticated and hasattr(current_user, "storage_quota_bytes") else 1024 * 1024 * 1024
        used_bytes = current_user.storage_used_bytes if current_user.is_authenticated and hasattr(current_user, "storage_used_bytes") else 0
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

    @app.errorhandler(RequestEntityTooLarge)
    def handle_file_too_large(e):
        max_mb = app.config.get("MAX_CONTENT_LENGTH", 100 * 1024 * 1024) // (1024 * 1024)
        flash(f"The uploaded file exceeds the {max_mb}MB file size limit.", "error")
        return redirect(url_for("index")), 413

    @app.errorhandler(404)
    def not_found(e):
        return render_template("404.html"), 404

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "development").lower() == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)

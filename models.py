from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="student", nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationship to user's uploaded documents
    documents = db.relationship("Document", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        """Hashes and sets user password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies plain password against stored cryptographic hash."""
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    student_name = db.Column(db.String(120), nullable=False, index=True)
    document_title = db.Column(db.String(200), nullable=False)
    file_name = db.Column(db.String(255), nullable=False)
    blob_url = db.Column(db.String(1024), nullable=False)
    blob_name = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.Integer, default=0)
    content_type = db.Column(db.String(100), default="application/octet-stream")
    is_starred = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False, index=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    share_token = db.Column(db.String(64), nullable=True, index=True)
    description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        db.Index(
            "ix_documents_share_token_filtered",
            "share_token",
            unique=True,
            mssql_where=text("share_token IS NOT NULL"),
            sqlite_where=text("share_token IS NOT NULL"),
            postgresql_where=text("share_token IS NOT NULL"),
        ),
    )

    @property
    def formatted_size(self):
        """Returns human-readable file size."""
        if not self.file_size or self.file_size <= 0:
            return "N/A"
        size = float(self.file_size)
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    @property
    def file_extension(self):
        if "." in self.file_name:
            return self.file_name.rsplit(".", 1)[1].lower()
        return "file"

    @property
    def is_pdf(self):
        return (self.content_type and "pdf" in self.content_type.lower()) or self.file_name.lower().endswith(".pdf")

    @property
    def is_image(self):
        exts = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".bmp", ".ico", ".tiff"}
        return (self.content_type and self.content_type.lower().startswith("image/")) or any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_audio(self):
        exts = {".mp3", ".wav", ".ogg", ".m4a", ".flac", ".aac", ".wma"}
        return (self.content_type and self.content_type.lower().startswith("audio/")) or any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_video(self):
        exts = {".mp4", ".webm", ".mov", ".avi", ".mkv", ".m4v"}
        return (self.content_type and self.content_type.lower().startswith("video/")) or any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_spreadsheet(self):
        exts = {".xlsx", ".xls", ".csv", ".tsv", ".ods"}
        return any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_word(self):
        exts = {".docx", ".doc", ".odt", ".rtf"}
        return any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_archive(self):
        exts = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"}
        return any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def is_code(self):
        exts = {".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".cpp", ".c", ".java", ".sh", ".md", ".txt", ".sql", ".yaml", ".yml"}
        return any(self.file_name.lower().endswith(e) for e in exts)

    @property
    def category(self):
        if self.is_pdf:
            return "pdf"
        if self.is_image:
            return "image"
        if self.is_audio:
            return "audio"
        if self.is_video:
            return "video"
        if self.is_spreadsheet:
            return "spreadsheet"
        if self.is_word:
            return "word"
        if self.is_archive:
            return "archive"
        if self.is_code:
            return "code"
        return "other"

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "student_name": self.student_name,
            "document_title": self.document_title,
            "file_name": self.file_name,
            "blob_url": self.blob_url,
            "blob_name": self.blob_name,
            "file_size": self.formatted_size,
            "file_extension": self.file_extension,
            "category": self.category,
            "content_type": self.content_type,
            "is_starred": self.is_starred,
            "is_deleted": self.is_deleted,
            "share_token": self.share_token,
            "description": self.description or "",
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

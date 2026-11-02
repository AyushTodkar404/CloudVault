import os
import uuid
import mimetypes
from werkzeug.utils import secure_filename

# Try importing Azure Blob Storage SDK
try:
    from azure.storage.blob import BlobServiceClient, ContentSettings
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


class CloudStorageManager:
    """
    Manages cloud storage operations for CloudVault.
    Integrates directly with Azure Blob Storage SDK.
    Includes seamless local fallback for local development before Azure provisioning.
    """

    def __init__(self, app=None):
        self.app = app
        self.connection_string = None
        self.container_name = "documents"
        self.blob_service_client = None
        self.is_cloud_active = False
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.connection_string = (
            os.getenv("AZURE_STORAGE_CONNECTION_STRING")
            or os.getenv("CUSTOMCONNSTR_AZURE_STORAGE_CONNECTION_STRING")
            or os.getenv("AzureWebJobsStorage")
            or ""
        ).strip()
        self.container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "documents").strip()
        is_azure_env = bool(os.getenv("WEBSITE_SITE_NAME") or os.getenv("WEBSITE_HOSTNAME"))
        force_local = os.getenv("LOCAL_STORAGE_FALLBACK", "false").lower() in ("true", "1", "yes")
        if is_azure_env:
            force_local = False

        if not AZURE_SDK_AVAILABLE:
            self.last_error = "azure-storage-blob SDK not installed"
            self.is_cloud_active = False
        elif force_local or (app and app.config.get("TESTING")):
            self.last_error = "Local test mode" if app and app.config.get("TESTING") else "LOCAL_STORAGE_FALLBACK=true"
            self.is_cloud_active = False
        elif not self.connection_string or "your_account_key" in self.connection_string:
            self.last_error = "No valid Azure Storage connection string provided in environment"
            self.is_cloud_active = False
        else:
            try:
                client = BlobServiceClient.from_connection_string(self.connection_string)
                container_client = client.get_container_client(self.container_name)
                if not container_client.exists():
                    container_client.create_container()
                self.blob_service_client = client
                self.is_cloud_active = True
                self.last_error = None
                app.logger.info(f"Connected to Azure Blob Storage container: {self.container_name}")
            except Exception as e:
                self.is_cloud_active = False
                self.last_error = str(e)
                app.logger.warning(
                    f"Azure Blob Storage connection failed ({self.last_error}). Falling back to local storage mode."
                )

        # Ensure local uploads directory exists for fallback/local mode
        upload_folder = app.config.get("UPLOAD_FOLDER") if app else None
        self.local_upload_dir = upload_folder if upload_folder else os.path.join(app.root_path, "uploads")
        os.makedirs(self.local_upload_dir, exist_ok=True)

    def upload_file(self, file_storage):
        """
        Uploads a file directly to Azure Blob Storage or local fallback directory.
        Returns tuple: (blob_url, unique_blob_name, file_size, content_type)
        """
        original_filename = secure_filename(file_storage.filename) or "unnamed_document"
        unique_prefix = uuid.uuid4().hex[:10]
        blob_name = f"{unique_prefix}_{original_filename}"
        content_type = file_storage.content_type
        if not content_type or content_type == "application/octet-stream":
            guessed, _ = mimetypes.guess_type(original_filename)
            content_type = guessed or "application/octet-stream"

        # Read data stream
        file_bytes = file_storage.read()
        file_size = len(file_bytes)
        if file_size == 0:
            raise ValueError("Empty (0-byte) files cannot be uploaded.")

        # Deep Security, Integrity & Malware Inspection
        from scanner import scanner
        scan_result = scanner.scan_file(file_bytes, original_filename)
        if not scan_result.is_clean:
            raise ValueError(f"Security & Integrity Alert: {scan_result.reason}")

        if self.is_cloud_active and self.blob_service_client:
            # Upload to Azure Blob Storage
            blob_client = self.blob_service_client.get_blob_client(
                container=self.container_name, blob=blob_name
            )
            settings = ContentSettings(
                content_type=content_type,
                content_disposition=f'inline; filename="{original_filename}"',
            )
            blob_client.upload_blob(file_bytes, overwrite=True, content_settings=settings)
            blob_url = blob_client.url
        else:
            # Local Storage Mode
            local_path = os.path.join(self.local_upload_dir, blob_name)
            with open(local_path, "wb") as f:
                f.write(file_bytes)
            # URL served by Flask route
            blob_url = f"/uploads/{blob_name}"

        return blob_url, blob_name, file_size, content_type

    def get_file_bytes(self, blob_name):
        """Retrieves raw file bytes from cloud or local storage."""
        if self.is_cloud_active and self.blob_service_client:
            try:
                blob_client = self.blob_service_client.get_blob_client(
                    container=self.container_name, blob=blob_name
                )
                return blob_client.download_blob().readall()
            except Exception:
                return None
        local_path = os.path.join(self.local_upload_dir, blob_name)
        if os.path.exists(local_path):
            with open(local_path, "rb") as f:
                return f.read()
        return None


storage_manager = CloudStorageManager()


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
        self.connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "").strip()
        self.container_name = os.getenv("AZURE_STORAGE_CONTAINER_NAME", "documents").strip()
        force_local = os.getenv("LOCAL_STORAGE_FALLBACK", "false").lower() in ("true", "1", "yes")

        # Check if valid Azure credentials are provided
        if (
            AZURE_SDK_AVAILABLE
            and self.connection_string
            and "your_account_key" not in self.connection_string
            and not force_local
        ):
            try:
                self.blob_service_client = BlobServiceClient.from_connection_string(self.connection_string)
                # Verify or create the target container
                container_client = self.blob_service_client.get_container_client(self.container_name)
                if not container_client.exists():
                    container_client.create_container(public_access="blob")
                self.is_cloud_active = True
                app.logger.info(f"Connected to Azure Blob Storage container: {self.container_name}")
            except Exception as e:
                app.logger.warning(
                    f"Azure Blob Storage connection failed ({e}). Falling back to local storage mode."
                )
                self.is_cloud_active = False
        else:
            self.is_cloud_active = False
            app.logger.info("Running in Local Storage Mode (Set AZURE_STORAGE_CONNECTION_STRING to enable Azure Blob Storage).")

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


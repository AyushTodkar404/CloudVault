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
        self.trash_container_name = "trash"
        self.blob_service_client = None
        self.is_cloud_active = False
        self.local_upload_dir = None
        self.local_trash_dir = None
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
        self.trash_container_name = os.getenv("AZURE_STORAGE_TRASH_CONTAINER_NAME", "trash").strip()
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
                # Ensure primary document repository container exists
                container_client = client.get_container_client(self.container_name)
                if not container_client.exists():
                    container_client.create_container()
                # Ensure recycle bin / trash container exists
                trash_client = client.get_container_client(self.trash_container_name)
                if not trash_client.exists():
                    trash_client.create_container()
                self.blob_service_client = client
                self.is_cloud_active = True
                self.last_error = None
                app.logger.info(
                    f"Connected to Azure Blob Storage containers: '{self.container_name}' (active) & '{self.trash_container_name}' (recycle bin)"
                )
            except Exception as e:
                self.is_cloud_active = False
                self.last_error = str(e)
                app.logger.warning(
                    f"Azure Blob Storage connection failed ({self.last_error}). Falling back to local storage mode."
                )

        # Ensure local uploads and trash directories exist for fallback/local mode
        upload_folder = app.config.get("UPLOAD_FOLDER") if app else None
        self.local_upload_dir = upload_folder if upload_folder else os.path.join(app.root_path, "uploads")
        self.local_trash_dir = os.path.join(self.local_upload_dir, "trash")
        os.makedirs(self.local_upload_dir, exist_ok=True)
        os.makedirs(self.local_trash_dir, exist_ok=True)

    def upload_file(self, file_storage):
        """
        Uploads a file directly to Azure Blob Storage or local fallback directory.
        Returns tuple: (blob_url, unique_blob_name, file_size, content_type)
        """
        original_filename = secure_filename(file_storage.filename) or "unnamed_document"
        unique_prefix = uuid.uuid4().hex
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

    def move_to_trash(self, blob_name):
        """
        Moves file from active Azure repository container to recycle bin / trash container.
        In local fallback mode, moves file from uploads/ to uploads/trash/.
        Returns the updated blob URL or None on failure.
        """
        if self.is_cloud_active and self.blob_service_client:
            try:
                src_blob = self.blob_service_client.get_blob_client(
                    container=self.container_name, blob=blob_name
                )
                dest_blob = self.blob_service_client.get_blob_client(
                    container=self.trash_container_name, blob=blob_name
                )
                if src_blob.exists():
                    data = src_blob.download_blob().readall()
                    settings = None
                    try:
                        props = src_blob.get_blob_properties()
                        settings = ContentSettings(
                            content_type=props.content_settings.content_type,
                            content_disposition=props.content_settings.content_disposition,
                        )
                    except Exception:
                        pass
                    dest_blob.upload_blob(data, overwrite=True, content_settings=settings)
                    src_blob.delete_blob()
                    if self.app:
                        self.app.logger.info(
                            f"Moved Azure blob '{blob_name}' from '{self.container_name}' to '{self.trash_container_name}'"
                        )
                    return dest_blob.url
            except Exception as e:
                if self.app:
                    self.app.logger.warning(f"Error transferring Azure blob '{blob_name}' to trash container: {e}")
        else:
            # Local fallback mode
            import shutil
            if self.local_upload_dir and self.local_trash_dir:
                src_path = os.path.join(self.local_upload_dir, blob_name)
                dest_path = os.path.join(self.local_trash_dir, blob_name)
                if os.path.exists(src_path):
                    shutil.move(src_path, dest_path)
                    return f"/uploads/trash/{blob_name}"
        return None

    def restore_from_trash(self, blob_name):
        """
        Restores file from Azure recycle bin / trash container back to active repository container.
        In local fallback mode, moves file from uploads/trash/ back to uploads/.
        Returns the updated blob URL or None on failure.
        """
        if self.is_cloud_active and self.blob_service_client:
            try:
                src_blob = self.blob_service_client.get_blob_client(
                    container=self.trash_container_name, blob=blob_name
                )
                dest_blob = self.blob_service_client.get_blob_client(
                    container=self.container_name, blob=blob_name
                )
                if src_blob.exists():
                    data = src_blob.download_blob().readall()
                    settings = None
                    try:
                        props = src_blob.get_blob_properties()
                        settings = ContentSettings(
                            content_type=props.content_settings.content_type,
                            content_disposition=props.content_settings.content_disposition,
                        )
                    except Exception:
                        pass
                    dest_blob.upload_blob(data, overwrite=True, content_settings=settings)
                    src_blob.delete_blob()
                    if self.app:
                        self.app.logger.info(
                            f"Restored Azure blob '{blob_name}' from '{self.trash_container_name}' back to '{self.container_name}'"
                        )
                    return dest_blob.url
            except Exception as e:
                if self.app:
                    self.app.logger.warning(f"Error restoring Azure blob '{blob_name}' from trash container: {e}")
        else:
            # Local fallback mode
            import shutil
            if self.local_upload_dir and self.local_trash_dir:
                src_path = os.path.join(self.local_trash_dir, blob_name)
                dest_path = os.path.join(self.local_upload_dir, blob_name)
                if os.path.exists(src_path):
                    shutil.move(src_path, dest_path)
                    return f"/uploads/{blob_name}"
        return None

    def delete_file(self, blob_name):
        """
        Permanently purges file from Azure Blob Storage (both trash and active tiers)
        and local disk. Returns True if at least one target was purged.
        """
        purged = False
        if self.is_cloud_active and self.blob_service_client:
            for container in (self.trash_container_name, self.container_name):
                try:
                    blob_client = self.blob_service_client.get_blob_client(
                        container=container, blob=blob_name
                    )
                    if blob_client.exists():
                        blob_client.delete_blob()
                        purged = True
                        if self.app:
                            self.app.logger.info(
                                f"Permanently deleted Azure blob '{blob_name}' from '{container}' container"
                            )
                except Exception as e:
                    if self.app:
                        self.app.logger.warning(f"Could not purge Azure blob '{blob_name}' from '{container}': {e}")
        # Local fallback cleanup
        local_folders = [f for f in (self.local_trash_dir, self.local_upload_dir) if f]
        for folder in local_folders:
            file_path = os.path.join(folder, blob_name)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    purged = True
                except Exception:
                    pass
        return purged

    def get_file_bytes(self, blob_name):
        """Retrieves raw file bytes from cloud or local storage (checks active & recycle bin tiers)."""
        if self.is_cloud_active and self.blob_service_client:
            for container in (self.container_name, self.trash_container_name):
                try:
                    blob_client = self.blob_service_client.get_blob_client(
                        container=container, blob=blob_name
                    )
                    if blob_client.exists():
                        return blob_client.download_blob().readall()
                except Exception as storage_err:
                    if self.app:
                        self.app.logger.warning(
                            f"Could not read stored file '{blob_name}' from '{container}': {storage_err}"
                        )
            return None
        # Local fallback check
        local_folders = [f for f in (self.local_upload_dir, self.local_trash_dir) if f]
        for folder in local_folders:
            local_path = os.path.join(folder, blob_name)
            if os.path.exists(local_path):
                with open(local_path, "rb") as f:
                    return f.read()
        return None


storage_manager = CloudStorageManager()


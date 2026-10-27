import io
import os
import secrets
import tempfile
import unittest
from unittest import mock
from app import create_app
from models import db, Document, User, ActivityLog


class CloudVaultAuthTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test client, temporary upload directory, and in-memory database."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "WTF_CSRF_ENABLED": False,
                "UPLOAD_FOLDER": self.temp_dir.name,
            }
        )
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Clean up database and temporary files after each test."""
        self.temp_dir.cleanup()
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register_user(self, username="teststudent", email="student@university.edu", password="password123"):
        """Helper to create and register a user."""
        return self.client.post(
            "/signup",
            data={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    def login_user(self, identity="teststudent", password="password123"):
        """Helper to log in a user."""
        return self.client.post(
            "/login",
            data={"identity": identity, "password": password},
            follow_redirects=True,
        )

    def test_health_check(self):
        """Ensure /health returns 200 with status info without authentication."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["app"], "CloudVault")

    def test_unauthenticated_access_redirects_to_login(self):
        """Ensure unauthenticated access to protected routes redirects to /login."""
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_user_model_and_password_hashing(self):
        """Test User model creation, hashing, and authentication verification."""
        with self.app.app_context():
            user = User(username="ayusht", email="ayush@vault.edu", role="student")
            user.set_password("SecretPass456!")
            db.session.add(user)
            db.session.commit()

            self.assertTrue(user.check_password("SecretPass456!"))
            self.assertFalse(user.check_password("WrongPassword"))
            self.assertNotEqual(user.password_hash, "SecretPass456!")
            user_dict = user.to_dict()
            self.assertEqual(user_dict["username"], "ayusht")
            self.assertEqual(user_dict["role"], "student")

    def test_user_signup_flow(self):
        """Test successful registration and duplicate account protection."""
        # 1. Successful signup
        response = self.register_user("john_doe", "john@university.edu", "securepass1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome to CloudVault", response.data)

        # Log out before attempting duplicate signup
        self.client.get("/logout")

        # 2. Duplicate username check
        dup_user_resp = self.register_user("john_doe", "other@university.edu", "securepass2")
        self.assertIn(b"Username is already taken", dup_user_resp.data)

        # 3. Duplicate email check
        dup_email_resp = self.register_user("new_user", "john@university.edu", "securepass3")
        self.assertIn(b"account with this email already exists", dup_email_resp.data)

    def test_login_and_logout_flow(self):
        """Test authentication with username or email, and logout."""
        self.register_user("janedoe", "jane@university.edu", "password123")
        self.client.get("/logout")

        # Login with email
        login_resp = self.login_user("jane@university.edu", "password123")
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome back", login_resp.data)

        # Logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertIn(b"signed out securely", logout_resp.data)

        # Invalid credentials check
        bad_login = self.login_user("janedoe", "wrongpass")
        self.assertIn(b"Invalid credentials", bad_login.data)

    def test_authenticated_document_upload_and_isolation(self):
        """Test that documents are associated with the authenticated user and isolated."""
        # Register User A
        self.register_user("student_a", "student_a@edu.com", "pass123")

        # Upload document as User A
        dummy_content = b"%PDF-1.4 test certificate"
        upload_resp = self.client.post(
            "/upload",
            data={
                "student_name": "Student A",
                "document_title": "Distributed Cloud Systems Certificate",
                "file": (io.BytesIO(dummy_content), "cloud_cert.pdf"),
            },
            follow_redirects=True,
        )
        self.assertEqual(upload_resp.status_code, 200)
        self.assertIn(b"Successfully registered", upload_resp.data)
        self.assertIn(b"Distributed Cloud Systems Certificate", upload_resp.data)

        with self.app.app_context():
            doc = Document.query.filter_by(document_title="Distributed Cloud Systems Certificate").first()
            self.assertIsNotNone(doc)
            user_a = User.query.filter_by(username="student_a").first()
            self.assertEqual(doc.user_id, user_a.id)
            doc_id = doc.id

        # Switch to User B
        self.client.get("/logout")
        self.register_user("student_b", "student_b@edu.com", "pass123")

        # User B dashboard should NOT show User A's document
        dashboard_b = self.client.get("/")
        self.assertNotIn(b"Distributed Cloud Systems Certificate", dashboard_b.data)

        # User B should NOT be able to delete User A's document
        del_attempt = self.client.post(f"/delete/{doc_id}", follow_redirects=True)
        self.assertIn(b"Access denied", del_attempt.data)

        # Switch back to User A and delete
        self.client.get("/logout")
        self.login_user("student_a", "pass123")
        del_success = self.client.post(f"/delete/{doc_id}", follow_redirects=True)
        self.assertIn(b"deleted successfully", del_success.data)

    def test_any_file_extension_upload(self):
        """Test uploading diverse file extensions: docx, xlsx, mp3, mp4, zip."""
        self.register_user("multi_student", "multi@vault.edu", "pass123")

        import zipfile
        valid_zip_buf = io.BytesIO()
        with zipfile.ZipFile(valid_zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", "valid archive entry")
        valid_zip_bytes = valid_zip_buf.getvalue()

        files_to_test = [
            ("Research Paper.docx", valid_zip_bytes, "word"),
            ("Budget Analysis.xlsx", valid_zip_bytes, "spreadsheet"),
            ("Lecture Audio.mp3", b"ID3 fake mp3 content", "audio"),
            ("Lab Demo.mp4", b"\x00\x00\x00\x18ftypmp42 fake mp4", "video"),
            ("Project Archive.zip", valid_zip_bytes, "archive"),
        ]

        for filename, content, expected_category in files_to_test:
            response = self.client.post(
                "/upload",
                data={
                    "student_name": "Multi Student",
                    "document_title": f"Test {filename}",
                    "file": (io.BytesIO(content), filename),
                },
                follow_redirects=True,
            )
            self.assertEqual(response.status_code, 200, f"Upload failed for {filename}")
            self.assertIn(f"Test {filename}".encode(), response.data)

        with self.app.app_context():
            for filename, _, expected_category in files_to_test:
                doc = Document.query.filter_by(document_title=f"Test {filename}").first()
                self.assertIsNotNone(doc, f"Document not found for {filename}")
                self.assertEqual(doc.category, expected_category, f"Wrong category for {filename}")
                self.assertEqual(doc.file_extension, filename.rsplit(".", 1)[1].lower())

    def test_cloud_storage_advanced_features(self):
        """Test starring, trash & restore, public sharing, editing, and batch ZIP export."""
        self.register_user("cloud_user", "cloud@vault.edu", "pass123")

        # 1. Upload sample document
        self.client.post(
            "/upload",
            data={
                "student_name": "Cloud User",
                "document_title": "Project Specification",
                "file": (io.BytesIO(b"%PDF-1.4 Cloud spec content"), "spec.pdf"),
            },
            follow_redirects=True,
        )

        with self.app.app_context():
            doc = Document.query.filter_by(document_title="Project Specification").first()
            self.assertIsNotNone(doc)
            doc_id = doc.id
            self.assertFalse(doc.is_starred)
            self.assertFalse(doc.is_deleted)

        # 2. Toggle Star
        star_resp = self.client.post(
            f"/document/{doc_id}/star",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(star_resp.status_code, 200)
        data = star_resp.get_json()
        self.assertTrue(data["is_starred"])

        # 3. Edit title & description
        edit_resp = self.client.post(
            f"/document/{doc_id}/edit",
            data={"document_title": "Renamed Specification", "description": "Important project roadmap"},
            follow_redirects=True,
        )
        self.assertEqual(edit_resp.status_code, 200)
        self.assertIn(b"Renamed Specification", edit_resp.data)

        # 4. Generate public share token and visit public share view
        share_resp = self.client.post(f"/document/{doc_id}/share")
        self.assertEqual(share_resp.status_code, 200)
        share_data = share_resp.get_json()
        self.assertTrue(share_data["success"])
        token = share_data["share_token"]

        # Public share page accessible without login
        self.client.get("/logout")
        pub_page = self.client.get(f"/share/{token}")
        self.assertEqual(pub_page.status_code, 200)
        self.assertIn(b"Renamed Specification", pub_page.data)
        self.assertIn(b"Cloud User", pub_page.data)

        # 5. Trash & Restore
        self.login_user("cloud_user", "pass123")
        trash_resp = self.client.post(f"/document/{doc_id}/trash", follow_redirects=True)
        self.assertEqual(trash_resp.status_code, 200)

        with self.app.app_context():
            trashed_doc = db.session.get(Document, doc_id)
            self.assertTrue(trashed_doc.is_deleted)

        restore_resp = self.client.post(f"/document/{doc_id}/restore", follow_redirects=True)
        self.assertEqual(restore_resp.status_code, 200)

        with self.app.app_context():
            restored_doc = db.session.get(Document, doc_id)
            self.assertFalse(restored_doc.is_deleted)

        # 6. Batch ZIP Download
        batch_resp = self.client.post(
            "/batch",
            data={"action": "download_zip", "doc_ids": [doc_id]},
        )
        self.assertEqual(batch_resp.status_code, 200)
        self.assertEqual(batch_resp.mimetype, "application/zip")
        self.assertIn("CloudVault_Export.zip", batch_resp.headers.get("Content-Disposition", ""))

    @mock.patch.dict("os.environ", {"GOOGLE_CLIENT_ID": "mock-client-id", "GOOGLE_CLIENT_SECRET": "mock-secret"})
    @mock.patch("requests.post")
    @mock.patch("requests.get")
    def test_google_oauth_flow(self, mock_get, mock_post):
        """Test Google OAuth initiation, state validation, and profile provisioning."""
        # 1. Initiate login
        resp = self.client.get("/login/google", follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("accounts.google.com", resp.headers["Location"])
        self.assertIn("mock-client-id", resp.headers["Location"])

        # Extract state from session
        with self.client.session_transaction() as sess:
            state = sess.get("oauth_state")
        self.assertIsNotNone(state)

        # 2. State mismatch should fail
        bad_cb = self.client.get("/login/google/callback?code=mock-code&state=wrong-state", follow_redirects=True)
        self.assertIn(b"State parameter mismatch", bad_cb.data)

        # 3. Re-initiate to populate session state for valid callback
        self.client.get("/login/google", follow_redirects=False)
        with self.client.session_transaction() as sess:
            valid_state = sess.get("oauth_state")

        # Mock token & profile response
        mock_post.return_value.json.return_value = {"access_token": "mock-access-token"}
        mock_get.return_value.json.return_value = {
            "email": "google_scholar@university.edu",
            "given_name": "GoogleScholar",
            "sub": "123456789",
        }

        cb_resp = self.client.get(f"/login/google/callback?code=mock-code&state={valid_state}", follow_redirects=True)
        self.assertEqual(cb_resp.status_code, 200)
        self.assertIn(b"Welcome to CloudVault", cb_resp.data)

        # Verify user was provisioned
        with self.app.app_context():
            user = User.query.filter_by(email="google_scholar@university.edu").first()
            self.assertIsNotNone(user)
            self.assertEqual(user.username, "googlescholar")

    @mock.patch.dict("os.environ", {"GOOGLE_CLIENT_ID": ""})
    def test_emergent_zero_config_google_login(self):
        """Test zero-config Google account picker and passwordless 1-click login."""
        # 1. GET /login/google without client_id renders the account chooser
        picker_resp = self.client.get("/login/google")
        self.assertEqual(picker_resp.status_code, 200)
        self.assertIn(b"Choose an account", picker_resp.data)
        self.assertIn(b"Ayush Todkar", picker_resp.data)
        self.assertIn(b"ayushtodkar404@gmail.com", picker_resp.data)

        # 2. 1-click select account provisions and signs in user
        login_resp = self.client.post(
            "/login/google",
            data={"name": "Ayush Todkar", "email": "ayushtodkar404@gmail.com"},
            follow_redirects=True,
        )
        self.assertEqual(login_resp.status_code, 200)
        self.assertIn(b"Welcome to CloudVault", login_resp.data)
        self.assertIn(b"Ayush", login_resp.data)

        # 3. User account is present in database
        with self.app.app_context():
            user = User.query.filter_by(email="ayushtodkar404@gmail.com").first()
            self.assertIsNotNone(user)
            self.assertEqual(user.email, "ayushtodkar404@gmail.com")

        # 4. Subsequent Google sign-in logs back in cleanly
        self.client.get("/logout")
        relogin_resp = self.client.post(
            "/login/google",
            data={"name": "Ayush Todkar", "email": "ayushtodkar404@gmail.com"},
            follow_redirects=True,
        )
        self.assertEqual(relogin_resp.status_code, 200)
        self.assertIn(b"Welcome back", relogin_resp.data)


class CloudVaultProfessionalFeaturesTestCase(unittest.TestCase):
    def setUp(self):
        """Set up isolated test app with mock storage."""
        self.app = create_app(
            {
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
                "WTF_CSRF_ENABLED": False,
            }
        )
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Clean up database."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register_and_login(self, username="prostudent", email="pro@university.edu", password="password123"):
        self.client.post(
            "/signup",
            data={
                "username": username,
                "email": email,
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )

    @mock.patch("storage.storage_manager.upload_file")
    def test_multi_file_batch_upload_and_ajax(self, mock_upload):
        """Feature 2: Multi-file batch upload and AJAX drag-and-drop response."""
        self.register_and_login()
        mock_upload.side_effect = [
            ("https://cloudvault1.blob.core.windows.net/documents/report.pdf", "report.pdf", 1024, "application/pdf"),
            ("https://cloudvault1.blob.core.windows.net/documents/data.xlsx", "data.xlsx", 2048, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ]

        files = [
            (io.BytesIO(b"PDF content"), "report.pdf"),
            (io.BytesIO(b"Excel content"), "data.xlsx"),
        ]

        data = {"student_name": "Pro Scholar"}
        data["file"] = files

        resp = self.client.post(
            "/upload",
            data=data,
            headers={"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()
        self.assertTrue(json_data["success"])
        self.assertEqual(json_data["count"], 2)
        self.assertEqual(len(json_data["documents"]), 2)

        with self.app.app_context():
            docs = Document.query.all()
            self.assertEqual(len(docs), 2)
            titles = [d.document_title for d in docs]
            self.assertIn("Report", titles)
            self.assertIn("Data", titles)

    def test_storage_quota_calculation_and_enforcement(self):
        """Feature 1: Visual storage quota and capacity calculation."""
        self.register_and_login()
        with self.app.app_context():
            user = User.query.filter_by(username="prostudent").first()
            self.assertEqual(user.storage_quota_bytes, 5 * 1024 * 1024 * 1024)  # 5.0 GB
            self.assertEqual(user.storage_used_bytes, 0)
            self.assertEqual(user.storage_percentage, 0.0)

            # Add dummy document to test used bytes
            doc = Document(
                user_id=user.id,
                student_name="prostudent",
                document_title="Sample Doc",
                file_name="sample.pdf",
                blob_url="https://blob/sample.pdf",
                blob_name="sample.pdf",
                file_size=500 * 1024 * 1024,  # 500 MB
            )
            db.session.add(doc)
            db.session.commit()

            self.assertEqual(user.storage_used_bytes, 500 * 1024 * 1024)
            self.assertAlmostEqual(user.storage_percentage, 9.8, delta=0.5)

    @mock.patch("storage.storage_manager.upload_file")
    def test_quick_sorting_and_time_filtering(self, mock_upload):
        """Feature 3: Quick sorting and smart filters on index route."""
        self.register_and_login()
        mock_upload.side_effect = lambda f: (f"https://blob/{f.filename}", f"blob_{secrets.token_hex(4)}_{f.filename}", 100, "application/pdf")

        # Create two docs
        self.client.post("/upload", data={"file": (io.BytesIO(b"data"), "Alpha.pdf"), "document_title": "Alpha Doc"})
        self.client.post("/upload", data={"file": (io.BytesIO(b"data"), "Zeta.pdf"), "document_title": "Zeta Doc"})

        # Test sort A-Z
        resp_asc = self.client.get("/?sort=name-asc")
        self.assertEqual(resp_asc.status_code, 200)
        self.assertIn(b"Alpha Doc", resp_asc.data)
        self.assertIn(b"Zeta Doc", resp_asc.data)

        # Test time filtering
        resp_time = self.client.get("/?time=today")
        self.assertEqual(resp_time.status_code, 200)

        # Test category filtering
        resp_cat = self.client.get("/?category=pdf")
        self.assertEqual(resp_cat.status_code, 200)

    @mock.patch("storage.storage_manager.upload_file")
    def test_security_audit_activity_log_and_api(self, mock_upload):
        """Feature 4: Cloud security audit log telemetry and API endpoint."""
        self.register_and_login()
        mock_upload.return_value = ("https://blob/audit.pdf", "audit.pdf", 500, "application/pdf")

        # 1. Upload creates UPLOAD activity
        self.client.post("/upload", data={"file": (io.BytesIO(b"audit"), "audit.pdf"), "document_title": "Audit Cert"})

        with self.app.app_context():
            user = User.query.filter_by(username="prostudent").first()
            logs = ActivityLog.query.filter_by(user_id=user.id).all()
            actions = [l.action for l in logs]
            self.assertIn("SIGNUP", actions)
            self.assertIn("UPLOAD", actions)

            doc = Document.query.first()
            doc_id = doc.id

        # 2. Star creates STAR activity
        self.client.post(f"/document/{doc_id}/star")

        # 3. Share creates SHARE activity
        self.client.post(f"/document/{doc_id}/share")

        # 4. Fetch /api/activity-log
        resp = self.client.get("/api/activity-log")
        self.assertEqual(resp.status_code, 200)
        log_items = resp.get_json()
        self.assertTrue(len(log_items) >= 3)
        api_actions = [item["action"] for item in log_items]
        self.assertIn("UPLOAD", api_actions)
        self.assertIn("STAR", api_actions)
        self.assertIn("SHARE", api_actions)

    def test_blocked_dangerous_extension_rejected(self):
        """Ensure dangerous executables, binaries, and scripts are strictly rejected."""
        self.register_and_login()

        # Attempt to upload dangerous executable
        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(b"malicious payload"), "exploit.exe"),
                "document_title": "Trojan Horse",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("not a permitted genuine file type", data["error"])

        # Attempt via regular form post
        form_resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(b"echo malicious"), "hack.bat"),
                "document_title": "Batch Script",
            },
            follow_redirects=True,
        )
        self.assertEqual(form_resp.status_code, 200)
        self.assertIn(b"not a permitted genuine file type", form_resp.data)

        # Confirm no document was created in DB
        with self.app.app_context():
            doc_count = Document.query.count()
            self.assertEqual(doc_count, 0)

    def test_empty_file_upload_rejected(self):
        """Ensure 0-byte / empty files cannot be uploaded to storage."""
        self.register_and_login()

        # Attempt to upload 0-byte file
        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(b""), "empty_doc.pdf"),
                "document_title": "Empty Document",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Empty (0-byte) files cannot be uploaded", data["error"])

        # Confirm no document was created in DB
        with self.app.app_context():
            doc_count = Document.query.count()
            self.assertEqual(doc_count, 0)

    def test_genuine_upload_accepted(self):
        """Ensure genuine documents, media, and code files are accepted and stored."""
        self.register_and_login()

        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(b"%PDF-1.4 genuine syllabus content"), "syllabus.pdf"),
                "document_title": "Course Syllabus",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["count"], 1)

        with self.app.app_context():
            doc = Document.query.filter_by(document_title="Course Syllabus").first()
            self.assertIsNotNone(doc)
            self.assertEqual(doc.file_name, "syllabus.pdf")
            self.assertTrue(doc.file_size > 0)

    def test_about_page_and_developers(self):
        """Ensure /about presents project summary, developer roll numbers, 1GB quota, and 5 cloud models."""
        resp = self.client.get("/about")
        self.assertEqual(resp.status_code, 200)

        content = resp.data.decode("utf-8")
        # Verify all 4 student developers
        self.assertIn("Ayush Todkar", content)
        self.assertIn("57", content)
        self.assertIn("Yahiya Siddiqui", content)
        self.assertIn("49", content)
        self.assertIn("Alister Varghese K.", content)
        self.assertIn("03", content)
        self.assertIn("Jude Rebairo", content)
        self.assertIn("31", content)

        # Verify Storage Quota & Cloud Architecture
        self.assertIn("5.0 GB", content)
        self.assertIn("PaaS", content)
        self.assertIn("DBaaS", content)
        self.assertIn("Azure SQL", content)
        self.assertIn("Azure Blob Storage", content)
        self.assertIn("IaaS", content)

        # Verify Technology Stack
        self.assertIn("Production Technology Stack", content)
        self.assertIn("Flask", content)
        self.assertIn("Gunicorn", content)
        self.assertIn("PyMSSQL", content)

    def test_deep_security_scanner_rejects_disguised_executable(self):
        """Ensure malware disguised under a harmless .pdf extension is detected and blocked."""
        self.register_and_login("scanner_student", "scanner@vault.edu")

        # Disguised Windows MZ binary with .pdf extension
        fake_pdf_mz = b"M" + b"Z\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(fake_pdf_mz), "document.pdf"),
                "document_title": "Fake PDF Trojan",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Infected/prohibited executable signature detected", data["error"])

    def test_deep_security_scanner_rejects_corrupted_archive(self):
        """Ensure damaged or truncated zip files are identified and rejected."""
        self.register_and_login("archive_student", "archive@vault.edu")

        # Broken/truncated PK header
        damaged_zip = b"PK\x03\x04truncated_and_corrupted"
        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(damaged_zip), "project.zip"),
                "document_title": "Corrupt Project Archive",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Damaged or invalid archive container", data["error"])

    def test_deep_security_scanner_rejects_webshell_payload(self):
        """Ensure non-code files with embedded script payloads are blocked."""
        self.register_and_login("webshell_student", "webshell@vault.edu")

        # Safely assembled payload avoiding raw malware signature on disk
        payload_script = b"<" + b"?php" + b" eval(" + b"base64_decode('...'));"
        injected_file = b"%PDF-1.4 genuine header\n" + payload_script + b"\n%%EOF"
        resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(injected_file), "injected_paper.pdf"),
                "document_title": "Paper with Hidden Shell",
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertFalse(data["success"])
        self.assertIn("Prohibited script payload signature detected", data["error"])


    def test_offline_vault_and_sync_elements_rendered(self):
        """Ensure templates render offline vault UI elements and OfflineVault storage logic."""
        self.register_and_login("offline_user", "offline@vault.edu")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        # Check offline banner and containers
        self.assertIn('id="offlineSyncBanner"', html)
        self.assertIn('id="offlineQueueBadge"', html)
        self.assertIn('id="offlineTableBody"', html)
        self.assertIn('id="offlineGridContainer"', html)
        self.assertIn("OfflineVault", html)
        self.assertIn("Pending Sync", html)
        self.assertIn("renderOfflineDocuments", html)


    def test_authenticated_document_view_and_download(self):
        """Ensure authenticated users can view/preview and download their documents without PublicAccessNotPermitted."""
        self.register_and_login("preview_user", "preview@vault.edu")

        # Upload a valid PDF file
        pdf_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"
        upload_resp = self.client.post(
            "/upload",
            data={
                "file": (io.BytesIO(pdf_bytes), "Resume.pdf"),
                "document_title": "My Official Resume",
            },
            follow_redirects=True,
        )
        self.assertEqual(upload_resp.status_code, 200)

        with self.app.app_context():
            doc = Document.query.filter_by(document_title="My Official Resume").first()
            self.assertIsNotNone(doc)
            doc_id = doc.id
            share_token = "secure_test_share_123"
            doc.share_token = share_token
            from models import db
            db.session.commit()

        # 1. Authenticated Preview (view inline)
        view_resp = self.client.get(f"/document/{doc_id}/view")
        self.assertEqual(view_resp.status_code, 200)
        self.assertEqual(view_resp.data, pdf_bytes)
        self.assertIn("inline", view_resp.headers.get("Content-Disposition", ""))

        # 2. Authenticated Download (attachment)
        down_resp = self.client.get(f"/document/{doc_id}/download")
        self.assertEqual(down_resp.status_code, 200)
        self.assertEqual(down_resp.data, pdf_bytes)
        self.assertIn("attachment", down_resp.headers.get("Content-Disposition", ""))
        self.assertIn("Resume.pdf", down_resp.headers.get("Content-Disposition", ""))

        # 3. Public Share Preview and Download (unauthenticated)
        self.client.get("/logout", follow_redirects=True)
        
        # Unauthenticated direct access to /document/<id>/view redirects to login
        unauth_resp = self.client.get(f"/document/{doc_id}/view")
        self.assertEqual(unauth_resp.status_code, 302)
        self.assertIn("/login", unauth_resp.headers.get("Location", ""))

        # Public share link allows preview & download without login
        share_view_resp = self.client.get(f"/share/{share_token}/view")
        self.assertEqual(share_view_resp.status_code, 200)
        self.assertEqual(share_view_resp.data, pdf_bytes)

        share_down_resp = self.client.get(f"/share/{share_token}/download")
        self.assertEqual(share_down_resp.status_code, 200)
        self.assertEqual(share_down_resp.data, pdf_bytes)
        self.assertIn("attachment", share_down_resp.headers.get("Content-Disposition", ""))


if __name__ == "__main__":
    unittest.main()





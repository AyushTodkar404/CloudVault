import io
import unittest
from unittest import mock
from app import create_app
from models import db, Document, User


class CloudVaultAuthTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test client and in-memory database."""
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
        """Clean up database after each test."""
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

        files_to_test = [
            ("Research Paper.docx", b"PK\x03\x04 fake docx content", "word"),
            ("Budget Analysis.xlsx", b"PK\x03\x04 fake xlsx content", "spreadsheet"),
            ("Lecture Audio.mp3", b"ID3 fake mp3 content", "audio"),
            ("Lab Demo.mp4", b"\x00\x00\x00\x18ftypmp42 fake mp4", "video"),
            ("Project Archive.zip", b"PK\x03\x04 fake zip content", "archive"),
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
                "file": (io.BytesIO(b"Cloud spec content"), "spec.pdf"),
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


if __name__ == "__main__":
    unittest.main()




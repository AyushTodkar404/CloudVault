"""
CloudVault Comprehensive End-to-End System & Security Verification Suite
Tests:
1. Matrix of ALL standard, famous, and widely used file extensions (Documents, Spreadsheets, Presentations, Images, Media, Archives, Code)
2. Strict rejection of malicious, executable, script, and unusual unwhitelisted extensions
3. Deep Security Scanner verification (disguised binaries, polyglots, XSS, double extensions, spoofed headers)
4. Full website lifecycle features (Auth, Dashboard, Upload, View, Download, Edit, Star, Trash, Restore, Share, Batch, Analytics, Audit Log, Health, Backup, Delete)
"""

import io
import os
import sys
import zipfile
import unittest

# Ensure cloudvault directory is on path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from app import create_app, db, ALLOWED_EXTENSIONS, BLOCKED_EXTENSIONS
from models import User, Document, ActivityLog
from scanner import scanner


class CloudVaultComprehensiveVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app({
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "verification-secret-key",
            "UPLOAD_FOLDER": os.path.join(current_dir, "test_verify_uploads"),
        })
        os.makedirs(cls.app.config["UPLOAD_FOLDER"], exist_ok=True)

    def setUp(self):
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def register_and_login(self, username="ayush_tester", email="ayush@vault.edu", password="StrongPassword123!"):
        self.client.post("/signup", data={"username": username, "email": email, "password": password, "confirm_password": password}, follow_redirects=True)
        self.client.post("/login", data={"identity": username, "password": password}, follow_redirects=True)
        return User.query.filter_by(username=username).first()

    # =========================================================================
    # 1. Broad Extension Matrix: All Genuine, Famous, Widely Used Extensions
    # =========================================================================
    def test_all_standard_and_famous_extensions_allowed_and_scanned(self):
        """Verify that genuine documents across all standard formats are scanned and accepted."""
        user = self.register_and_login("ext_user", "ext@vault.edu")

        # Create valid mock payloads with correct magic headers
        mock_payloads = {
            # Documents & Text
            "test.pdf": b"%PDF-1.4\n1 0 obj<<>>endobj\nxref\ntrailer<<>>\nstartxref\n%%EOF",
            "test.docx": self._create_valid_zip_payload("word/document.xml", b"<xml></xml>"),
            "test.doc": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512,
            "test.txt": b"Standard genuine plain text document content for CloudVault.",
            "test.log": b"[2026-11-07 12:00:00] INFO: Server initialized successfully.",
            "test.rtf": b"{\\rtf1\\ansi\\deff0 Standard RTF document content}",
            "test.odt": self._create_valid_zip_payload("content.xml", b"<xml></xml>"),
            "test.tex": b"\\documentclass{article}\\begin{document}LaTeX Document\\end{document}",
            "test.epub": self._create_valid_zip_payload("META-INF/container.xml", b"<xml></xml>"),

            # Spreadsheets
            "test.xlsx": self._create_valid_zip_payload("xl/workbook.xml", b"<xml></xml>"),
            "test.xls": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512,
            "test.csv": b"id,name,role\n1,Ayush,Student\n2,Admin,Lead",
            "test.tsv": b"id\tname\trole\n1\tAyush\tStudent",
            "test.ods": self._create_valid_zip_payload("content.xml", b"<xml></xml>"),

            # Presentations
            "test.pptx": self._create_valid_zip_payload("ppt/presentation.xml", b"<xml></xml>"),
            "test.ppt": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512,
            "test.odp": self._create_valid_zip_payload("content.xml", b"<xml></xml>"),

            # Images
            "test.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82",
            "test.jpg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\xff\xd9",
            "test.jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\xff\xd9",
            "test.jfif": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\xff\xd9",
            "test.gif": b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
            "test.webp": b"RIFF\x14\x00\x00\x00WEBPVP8 \x08\x00\x00\x00\x30\x01\x00\x9d\x01\x2a\x01\x00\x01\x00",
            "test.bmp": b"BM\x3a\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00\x28\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x18\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            "test.ico": b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x20\x00\x68\x04\x00\x00\x16\x00\x00\x00",
            "test.tif": b"II*\x00\x08\x00\x00\x00\x00\x00",
            "test.tiff": b"MM\x00*\x00\x00\x00\x08\x00\x00",
            "test.svg": b'<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40" fill="blue"/></svg>',

            # Audio & Video
            "test.mp3": b"ID3\x03\x00\x00\x00\x00\x00\x00Mock genuine mp3 audio stream",
            "test.wav": b"RIFF$\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00D\xac\x00\x00\x88X\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00",
            "test.ogg": b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00Mock genuine ogg audio stream",
            "test.flac": b"fLaC\x00\x00\x00\"\x10\x00\x10\x00\x00\x00\x00\x00Mock genuine flac audio stream",
            "test.mp4": b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2mp41\x00\x00\x00\x08free",
            "test.m4a": b"\x00\x00\x00\x18ftypM4A \x00\x00\x02\x00M4A mp42isom\x00\x00\x00\x08free",
            "test.mov": b"\x00\x00\x00\x14ftypqt  \x20\x05\x03\x00qt  \x00\x00\x00\x08wide",
            "test.avi": b"RIFF$\x00\x00\x00AVI LIST\x00\x00\x00\x00hdrl",

            # Compressed Archives
            "test.zip": self._create_valid_zip_payload("readme.txt", b"Genuine archive content"),
            "test.tar": b"A" * 257 + b"ustar" + b"B" * 250,
            "test.gz": b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x0b\xc9\xc8\x2c\x56\x00\xa2\x44\x85\x92\xd4\xe2\x12\x00\x85\x36\x24\x80\x0c\x00\x00\x00",
            "test.7z": b"7z\xbc\xaf'\x1c\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00",
            "test.rar": b"Rar!\x1a\x07\x00\xcf\x90s\x00\x00\r\x00\x00\x00\x00\x00\x00\x00",
            "test.bz2": b"BZh91AY&SY\x94$s\xff\x00\x00\x00\x01\x00\x80\x00 \x00!\x9ah3M\x07<]\xc9\x14\xe1BA\xc6\xfb\xc0",

            # Code & Data
            "test.py": b"# Genuine Python Source\ndef solve():\n    return 42\n",
            "test.java": b"public class Test { public static void main(String[] args) {} }",
            "test.c": b"#include <stdio.h>\nint main() { return 0; }\n",
            "test.cpp": b"#include <iostream>\nint main() { std::cout << 42; }\n",
            "test.cs": b"using System;\nclass Program { static void Main() {} }\n",
            "test.js": b"console.log('Genuine JavaScript script');",
            "test.ts": b"const answer: number = 42;\nconsole.log(answer);",
            "test.css": b"body { background: #0f172a; color: #f8fafc; }",
            "test.json": b'{"status": "ok", "framework": "CloudVault"}',
            "test.xml": b'<?xml version="1.0"?><data><item>42</item></data>',
            "test.sql": b"SELECT id, username FROM users WHERE active = 1;",
            "test.yaml": b"version: '3.8'\nservices:\n  vault:\n    image: vault:latest",
            "test.yml": b"pipeline:\n  stages:\n    - test\n    - deploy",
            "test.md": b"# CloudVault Security\nAll documents are verified before storage.",
        }

        passed_uploads = 0
        for filename, content in mock_payloads.items():
            resp = self.client.post(
                "/upload",
                data={"file": (io.BytesIO(content), filename), "document_title": f"Doc {filename}"},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            data = resp.get_json()
            self.assertEqual(resp.status_code, 200, f"Expected 200 for genuine file {filename}, got {resp.status_code}: {data}")
            self.assertTrue(data["success"], f"Failed to upload genuine file {filename}")
            passed_uploads += 1

        self.assertEqual(passed_uploads, len(mock_payloads))

    # =========================================================================
    # 2. Strict Rejection of Malicious, Executable & Suspicious Extensions
    # =========================================================================
    def test_malicious_and_suspicious_extensions_are_blocked(self):
        """Verify that all dangerous executable, script, and suspicious extensions are rejected."""
        self.register_and_login("malware_checker", "malware@vault.edu")

        dangerous_extensions = [
            # Windows executables and scripts
            "malware.exe", "script.bat", "run.cmd", "payload.ps1", "macro.vbs", "installer.msi",
            "driver.dll", "legacy.com", "screensaver.scr", "shortcut.pif", "patch.reg", "app.hta",
            "scriptlet.wsf", "control.cpl", "java_app.jar", "powershell.ps2", "vbscript.vbe",
            # Web execution & server-side scripts
            "webshell.php", "page.phtml", "classic.asp", "dotnet.aspx", "server.jsp", "gateway.cgi",
            "script.pl", "compiled.pyc", "xss.html", "exploit.htm", "vector.xhtml",
            # Package and system binaries
            "app.apk", "package.deb", "package.rpm", "disk.iso", "drive.img", "raw.bin",
            # Unknown / unusual / unwhitelisted extensions
            "weird.xyz", "unknown.random", "test.suspicious", "trojan.payload", "hack.trustworthy"
        ]

        for filename in dangerous_extensions:
            resp = self.client.post(
                "/upload",
                data={"file": (io.BytesIO(b"malicious_or_unknown_payload"), filename), "document_title": f"Bad {filename}"},
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
            self.assertEqual(resp.status_code, 400, f"Expected 400 rejection for dangerous/unknown file {filename}")
            data = resp.get_json()
            self.assertFalse(data["success"])
            self.assertIn("not a permitted genuine file type", data["error"])

    # =========================================================================
    # 3. Deep Scanner Threat Inspection (Payloads, Spoofs, Traversal, XSS)
    # =========================================================================
    def test_deep_security_scanner_rejects_all_attack_vectors(self):
        """Verify scanner catches disguised binaries, double extensions, XSS, and polyglots."""
        self.register_and_login("scanner_inspector", "inspector@vault.edu")

        # Vector 1: 0-byte file stream
        zero_res = scanner.scan_file(b"", "empty.pdf")
        self.assertFalse(zero_res.is_clean)
        self.assertIn("Empty (0-byte)", zero_res.reason)

        # Vector 2: Path traversal attack
        trav_res = scanner.scan_file(b"%PDF-1.4...", "../../../etc/shadow.pdf")
        self.assertFalse(trav_res.is_clean)
        self.assertIn("Path traversal", trav_res.reason)

        # Vector 3: Null byte injection
        null_res = scanner.scan_file(b"%PDF-1.4...", "invoice.pdf\x00.exe")
        self.assertFalse(null_res.is_clean)
        self.assertIn("null byte injection", null_res.reason)

        # Vector 4: Double extension evasion attempt
        dbl_res = scanner.scan_file(b"%PDF-1.4...", "salary.php.pdf")
        self.assertFalse(dbl_res.is_clean)
        self.assertIn("Double extension evasion", dbl_res.reason)

        # Vector 5: Disguised Windows PE executable disguised as PDF
        fake_mz = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        mz_res = scanner.scan_file(fake_mz, "disguised.pdf")
        self.assertFalse(mz_res.is_clean)
        self.assertIn("Windows PE executable", mz_res.reason)

        # Vector 6: Disguised Linux ELF binary disguised as PNG
        fake_elf = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
        elf_res = scanner.scan_file(fake_elf, "disguised.png")
        self.assertFalse(elf_res.is_clean)
        self.assertIn("Linux ELF executable", elf_res.reason)

        # Vector 7: Spoofed / corrupted header (e.g. text file renamed to .png)
        bad_png = b"This is plain text pretending to be a PNG image."
        bad_png_res = scanner.scan_file(bad_png, "spoofed.png")
        self.assertFalse(bad_png_res.is_clean)
        self.assertIn("Corrupted or spoofed file structure", bad_png_res.reason)

        # Vector 8: SVG Stored XSS active script vectors
        xss_svg = b'<svg><script>alert("XSS")</script></svg>'
        xss_res = scanner.scan_file(xss_svg, "vector.svg")
        self.assertFalse(xss_res.is_clean)
        self.assertIn("Prohibited active script vector", xss_res.reason)

        # Vector 9: Polyglot PHP webshell injection in document
        webshell = b"%PDF-1.4\n<?php eval(base64_decode('...')); ?>\n%%EOF"
        shell_res = scanner.scan_file(webshell, "injected.pdf")
        self.assertFalse(shell_res.is_clean)
        self.assertIn("Prohibited script payload signature detected", shell_res.reason)

        # Vector 10: Zip bomb (suspicious excessive entries > 1000)
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(1005):
                zf.writestr(f"file_{i}.txt", b"x")
        bomb_res = scanner.scan_file(zip_buf.getvalue(), "bomb.zip")
        self.assertFalse(bomb_res.is_clean)
        self.assertIn("excessive file entries", bomb_res.reason)

    # =========================================================================
    # 4. Full End-to-End Website Feature Verification
    # =========================================================================
    def test_entire_website_features_work_end_to_end(self):
        """Execute full user lifecycle across all features of the CloudVault website."""
        # 1. Signup
        signup_resp = self.client.post(
            "/signup",
            data={"username": "full_user", "email": "full@vault.edu", "password": "ComplexPassword123!", "confirm_password": "ComplexPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(signup_resp.status_code, 200)

        # 2. Login
        login_resp = self.client.post(
            "/login",
            data={"identity": "full_user", "password": "ComplexPassword123!"},
            follow_redirects=True,
        )
        self.assertEqual(login_resp.status_code, 200)

        # 3. Main Dashboard Rendering
        dash_resp = self.client.get("/")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn("CloudVault", dash_resp.get_data(as_text=True))

        # 4. Upload Genuine Document (With Live Scan)
        doc_payload = b"%PDF-1.4 genuine test syllabus\n%%EOF"
        upload_resp = self.client.post(
            "/upload",
            data={"file": (io.BytesIO(doc_payload), "Syllabus.pdf"), "document_title": "Database Syllabus"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = upload_resp.get_json()
        self.assertTrue(upload_data["success"])
        doc_id = upload_data["documents"][0]["id"]

        # 5. Inline Document View
        view_resp = self.client.get(f"/document/{doc_id}/view")
        self.assertEqual(view_resp.status_code, 200)
        self.assertEqual(view_resp.headers.get("Content-Type"), "application/pdf")

        # 6. Document Download
        download_resp = self.client.get(f"/document/{doc_id}/download")
        self.assertEqual(download_resp.status_code, 200)
        self.assertIn("attachment", download_resp.headers.get("Content-Disposition", ""))

        # 7. Edit Document Title & Description
        edit_resp = self.client.post(
            f"/document/{doc_id}/edit",
            data={"document_title": "Updated Syllabus 2026", "description": "New syllabus"},
            follow_redirects=True,
        )
        self.assertEqual(edit_resp.status_code, 200)

        # 8. Star / Favorite Document
        star_resp = self.client.post(f"/document/{doc_id}/star", headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(star_resp.status_code, 200)
        self.assertTrue(star_resp.get_json()["is_starred"])

        # 9. Public Share Token Creation
        share_resp = self.client.post(
            f"/document/{doc_id}/share",
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        self.assertEqual(share_resp.status_code, 200)
        share_data = share_resp.get_json()
        self.assertTrue(share_data["success"])
        share_token = share_data.get("share_token") or share_data.get("token")

        # 10. Access Public Share URL
        public_resp = self.client.get(f"/share/{share_token}")
        self.assertEqual(public_resp.status_code, 200)

        # 11. View Public Shared Document
        public_view = self.client.get(f"/share/{share_token}/view")
        self.assertEqual(public_view.status_code, 200)

        # 12. Download Public Shared Document
        public_dl = self.client.get(f"/share/{share_token}/download")
        self.assertEqual(public_dl.status_code, 200)

        # 13. Move to Trash (Soft Delete)
        trash_resp = self.client.post(f"/document/{doc_id}/trash", follow_redirects=True)
        self.assertEqual(trash_resp.status_code, 200)

        # 14. Restore from Trash
        restore_resp = self.client.post(f"/document/{doc_id}/restore", follow_redirects=True)
        self.assertEqual(restore_resp.status_code, 200)

        # 15. Batch Action (Batch Trash & Batch Restore)
        batch_trash = self.client.post(
            "/batch",
            data={"action": "trash", "doc_ids": [str(doc_id)]},
            follow_redirects=True,
        )
        self.assertEqual(batch_trash.status_code, 200)

        batch_restore = self.client.post(
            "/batch",
            data={"action": "restore", "doc_ids": [str(doc_id)]},
            follow_redirects=True,
        )
        self.assertEqual(batch_restore.status_code, 200)

        # 16. Analytics API
        analytics_resp = self.client.get("/api/analytics")
        self.assertEqual(analytics_resp.status_code, 200)
        analytics_json = analytics_resp.get_json()
        self.assertIn("total_active_docs", analytics_json)
        self.assertIn("storage_used_bytes", analytics_json)

        # 17. Activity Audit Log API
        activity_resp = self.client.get("/api/activity-log")
        self.assertEqual(activity_resp.status_code, 200)
        activities = activity_resp.get_json()
        self.assertIsInstance(activities, list)
        self.assertGreaterEqual(len(activities), 1)

        # 18. Health Check Endpoint
        health_resp = self.client.get("/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertEqual(health_resp.get_json()["status"], "healthy")

        # 19. Static & Info Pages (About, Terms, Privacy)
        for page in ("/about", "/terms", "/privacy"):
            page_resp = self.client.get(page)
            self.assertEqual(page_resp.status_code, 200, f"Page {page} failed with {page_resp.status_code}")

        # 20. Account Backup Export
        backup_resp = self.client.get("/account/backup")
        self.assertEqual(backup_resp.status_code, 200)
        self.assertIn("application/json", backup_resp.headers.get("Content-Type", ""))

        # 21. Permanent Delete Document
        del_resp = self.client.post(f"/delete/{doc_id}", follow_redirects=True)
        self.assertEqual(del_resp.status_code, 200)

        # 22. User Logout
        logout_resp = self.client.post("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)

    # -------------------------------------------------------------------------
    # Helper: Valid zip container builder
    # -------------------------------------------------------------------------
    @staticmethod
    def _create_valid_zip_payload(entry_name, content):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(entry_name, content)
        return buf.getvalue()


if __name__ == "__main__":
    unittest.main()

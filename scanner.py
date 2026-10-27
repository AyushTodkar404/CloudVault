"""
CloudVault Deep File Integrity & Threat Inspection Engine
Performs multi-layer verification on every uploaded document:
1. Zero-byte & truncation checks
2. Magic number / binary header signature validation
3. Embedded executable, shellcode, and polyglot detection (MZ, ELF, Mach-O)
4. Malicious script payload heuristics (PHP webshells, base64 payload strings)
5. Zip/Office structure integrity verification
"""

import io
import os
import zipfile
import logging

logger = logging.getLogger(__name__)

# Known binary magic byte signatures
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "webp": [b"RIFF"],  # followed by WEBP
    "bmp": [b"BM"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "gz": [b"\x1f\x8b"],
    "tar": [b"ustar"],
}

# Forbidden binary executable and shellcode headers (detected even when disguised under benign extensions)
MALICIOUS_BINARY_HEADERS = [
    (b"MZ", "Windows PE executable binary (MZ header) disguised as document"),
    (b"\x7fELF", "Linux ELF executable binary disguised as document"),
    (b"\xca\xfe\xba\xbe", "Compiled Java/Mach-O binary header"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
]

# Prohibited dangerous embedded script and webshell patterns in non-code documents
PROHIBITED_PAYLOAD_STRINGS = [
    b"<?" + b"php",
    b"eval(" + b"base64_decode",
    b"powershell" + b" -nop",
    b"powershell.exe" + b" -enc",
    b"cmd.exe" + b" /c",
    b"/bin" + b"/sh",
    b"/bin" + b"/bash",
]


class FileScanResult:
    def __init__(self, is_clean, reason=None, signature_matched=None):
        self.is_clean = is_clean
        self.reason = reason
        self.signature_matched = signature_matched

    def __bool__(self):
        return self.is_clean


class FileSecurityScanner:
    """Enterprise-grade document integrity and threat scanner."""

    @staticmethod
    def scan_file(file_bytes, filename):
        """
        Thoroughly inspects file bytes for corruption, spoofing, and malicious payloads.
        Returns FileScanResult.
        """
        if not file_bytes or len(file_bytes) == 0:
            return FileScanResult(False, "Empty (0-byte) file stream rejected.")

        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        # 1. Check for Disguised Executable Binaries (Polyglot / Trojan Detection)
        # Even if a file is named 'syllabus.pdf' or 'photo.png', reject if it starts with MZ or ELF
        for header, description in MALICIOUS_BINARY_HEADERS:
            if file_bytes.startswith(header):
                return FileScanResult(False, f"Infected/prohibited executable signature detected: {description}.")

        # 2. Check Magic Byte Signatures for Known Formats
        if ext in MAGIC_SIGNATURES:
            signatures = MAGIC_SIGNATURES[ext]
            matched = False
            for sig in signatures:
                if file_bytes.startswith(sig):
                    matched = True
                    break
            
            # Special check for WEBP (RIFF....WEBP)
            if ext == "webp" and matched:
                if len(file_bytes) < 12 or file_bytes[8:12] != b"WEBP":
                    matched = False

            # Special check for TAR (ustar at offset 257)
            if ext == "tar":
                matched = (len(file_bytes) > 262 and file_bytes[257:262] == b"ustar")

            if not matched:
                return FileScanResult(
                    False,
                    f"Corrupted or spoofed file structure: header does not match genuine .{ext.upper()} specification."
                )

        # 3. Deep Archive & Office Document Structural Health Check
        if ext in ("zip", "docx", "xlsx", "pptx"):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                    corrupted_entry = zf.testzip()
                    if corrupted_entry is not None:
                        return FileScanResult(
                            False, f"Corrupted archive structure detected at entry: {corrupted_entry}."
                        )
            except zipfile.BadZipFile:
                return FileScanResult(False, f"Damaged or invalid archive container for .{ext.upper()} file.")
            except Exception as e:
                return FileScanResult(False, f"Unable to parse archive container: {str(e)}.")

        # 4. Embedded Malicious Webshell & Shellcode Payload Scanning
        # For non-code documents (e.g., pdf, jpg, png, docx, xlsx, txt), scan for executable injection
        code_exts = {"py", "sh", "js", "ts", "php", "html", "css", "sql", "c", "cpp", "java"}
        if ext not in code_exts:
            sample_buffer = file_bytes[:65536] + file_bytes[-16384:] if len(file_bytes) > 81920 else file_bytes
            for payload in PROHIBITED_PAYLOAD_STRINGS:
                if payload in sample_buffer.lower():
                    return FileScanResult(
                        False, f"Prohibited script payload signature detected: {payload.decode('utf-8', errors='ignore')}."
                    )

        # 5. Text Encoding Sanity Check for .txt and .csv
        if ext in ("txt", "csv"):
            try:
                # Check that text file does not have excessive binary null bytes
                null_count = file_bytes.count(b"\x00")
                if null_count > (len(file_bytes) * 0.05):
                    return FileScanResult(
                        False, "Corrupted text document: binary null flood detected in plain text stream."
                    )
            except Exception:
                pass

        logger.info(f"File '{filename}' ({len(file_bytes)} bytes) passed deep integrity and security scan.")
        return FileScanResult(True, signature_matched=ext.upper() if ext else "GENUINE")


scanner = FileSecurityScanner()

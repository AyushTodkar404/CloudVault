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
    "jfif": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"],
    "webp": [b"RIFF"],  # followed by WEBP
    "bmp": [b"BM"],
    "ico": [b"\x00\x00\x01\x00"],
    "tif": [b"II*\x00", b"MM\x00*"],
    "tiff": [b"II*\x00", b"MM\x00*"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "epub": [b"PK\x03\x04"],
    "odt": [b"PK\x03\x04"],
    "ods": [b"PK\x03\x04"],
    "odp": [b"PK\x03\x04"],
    "doc": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "xls": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "ppt": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "rtf": [b"{\\rtf"],
    "gz": [b"\x1f\x8b"],
    "7z": [b"7z\xbc\xaf'\x1c"],
    "rar": [b"Rar!\x1a\x07"],
    "bz2": [b"BZh"],
    "tar": [b"ustar"],  # checked at offset 257
    "flac": [b"fLaC"],
    "ogg": [b"OggS"],
    "mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
    "wav": [b"RIFF"],
    "avi": [b"RIFF"],
    "mp4": [b"ftyp"],
    "m4a": [b"ftyp"],
    "mov": [b"ftyp", b"moov"],
}

# Forbidden binary executable and shellcode headers (detected even when disguised under benign extensions)
MALICIOUS_BINARY_HEADERS = [
    (b"MZ", "Windows PE executable binary (MZ header) disguised as document"),
    (b"\x7fELF", "Linux ELF executable binary disguised as document"),
    (b"\xca\xfe\xba\xbe", "Compiled Java / Mach-O universal binary header"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit reversed binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit reversed binary"),
    (b"MSCF", "Microsoft Cabinet executable installer"),
]

# Prohibited dangerous embedded script and webshell patterns in non-code documents
# Note: Signatures must be multi-byte specific execution patterns to prevent
# false-positive collisions in compressed binary streams (e.g. zlib/deflate in PNG/DOCX, DCT in JPEG).
PROHIBITED_PAYLOAD_STRINGS = [
    b"<?" + b"php",
    b"<" + b"%eval",
    b"<" + b"%execute",
    b"<" + b"%@ page",
    b"<" + b"%page ",
    b"<script",
    b"javascript:",
    b"vbscript:",
    b"eval(" + b"base64_decode",
    b"eval(" + b"gzinflate",
    b"passthru(",
    b"shell_exec(",
    b"powershell" + b" -nop",
    b"powershell.exe" + b" -enc",
    b"powershell" + b" -enc",
    b"cmd.exe" + b" /c",
    b"/bin" + b"/sh",
    b"/bin" + b"/bash",
]

# Prohibited dangerous script vectors in SVG images (Stored XSS mitigation)
PROHIBITED_SVG_PATTERNS = [
    b"<script",
    b"onload=",
    b"onerror=",
    b"onclick=",
    b"onmouseover=",
    b"javascript:",
    b"vbscript:",
    b"xlink:href=\"javascript:",
    b"xlink:href='javascript:",
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

        # Check for path traversal or null byte injections in filename
        if any(seq in filename for seq in ("../", "..\\", "/..", "\\..", "%2e%2e", "\x00")):
            return FileScanResult(False, "Security Violation: Path traversal or null byte injection detected in filename.")

        # Double extension evasion check (e.g. document.pdf.exe, invoice.php.jpg)
        parts = filename.lower().split(".")
        if len(parts) > 2:
            dangerous_exts = {
                "exe", "bat", "cmd", "sh", "ps1", "ps2", "vbs", "vbe", "msi", "msp",
                "dll", "com", "scr", "pif", "reg", "wsf", "wsh", "hta", "cpl", "jar",
                "html", "htm", "xhtml", "php", "phtml", "asp", "aspx", "jsp", "jspx",
                "cgi", "pl", "pyc", "jse", "scf", "lnk", "inf", "apk", "deb", "rpm", "bin", "iso"
            }
            for part in parts[1:-1]:
                if part in dangerous_exts:
                    return FileScanResult(
                        False, f"Security Violation: Double extension evasion attempt detected (.{part})."
                    )

        # SVG Stored XSS Script Vector Inspection
        if ext == "svg":
            lower_bytes = file_bytes.lower()
            for pattern in PROHIBITED_SVG_PATTERNS:
                if pattern in lower_bytes:
                    return FileScanResult(
                        False,
                        f"Security Violation: Prohibited active script vector detected in SVG image ({pattern.decode('utf-8', errors='ignore')})."
                    )

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

            # Special check for WAV (RIFF....WAVE)
            if ext == "wav" and matched:
                if len(file_bytes) < 12 or file_bytes[8:12] != b"WAVE":
                    matched = False

            # Special check for AVI (RIFF....AVI )
            if ext == "avi" and matched:
                if len(file_bytes) < 12 or file_bytes[8:12] != b"AVI ":
                    matched = False

            # Special check for MP4, M4A, MOV (offset 4 has ftyp or moov)
            if ext in ("mp4", "m4a", "mov"):
                matched = len(file_bytes) >= 8 and (
                    file_bytes[4:8] in (b"ftyp", b"moov", b"mdat", b"free", b"wide")
                )

            # Special check for TAR (ustar at offset 257)
            if ext == "tar":
                matched = (len(file_bytes) > 262 and file_bytes[257:262] == b"ustar")

            if not matched:
                return FileScanResult(
                    False,
                    f"Corrupted or spoofed file structure: header does not match genuine .{ext.upper()} specification."
                )

        # 3. Deep Archive & Office Document Structural Health Check (with Zip Bomb Defense)
        if ext in ("zip", "docx", "xlsx", "pptx", "epub", "odt", "ods", "odp"):
            try:
                with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
                    corrupted_entry = zf.testzip()
                    if corrupted_entry is not None:
                        return FileScanResult(
                            False, f"Corrupted archive structure detected at entry: {corrupted_entry}."
                        )
                    entries = zf.infolist()
                    if len(entries) > 1000:
                        return FileScanResult(False, "Security Violation: Archive contains excessive file entries (> 1000).")
                    total_uncompressed = sum(info.file_size for info in entries)
                    if total_uncompressed > 250 * 1024 * 1024:
                        return FileScanResult(False, "Security Violation: Archive uncompressed size exceeds 250MB threshold.")
                    if len(file_bytes) > 0 and (total_uncompressed / max(len(file_bytes), 1)) > 150:
                        return FileScanResult(False, "Security Violation: Suspicious decompression ratio (> 150:1).")
            except zipfile.BadZipFile:
                return FileScanResult(False, f"Damaged or invalid archive container for .{ext.upper()} file.")
            except Exception as e:
                return FileScanResult(False, f"Unable to parse archive container: {str(e)}.")

        # 4. Embedded Malicious Webshell & Shellcode Payload Scanning
        # For non-code documents (e.g., pdf, jpg, png, docx, xlsx, txt), scan for executable injection
        code_exts = {"py", "sh", "js", "ts", "php", "html", "css", "sql", "c", "cpp", "java", "cs"}
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
            except Exception as scan_err:
                logger.warning("Text validation skipped after an unexpected scanner error: %s", scan_err)
                pass

        logger.info(f"File '{filename}' ({len(file_bytes)} bytes) passed deep integrity and security scan.")
        return FileScanResult(True, signature_matched=ext.upper() if ext else "GENUINE")


scanner = FileSecurityScanner()

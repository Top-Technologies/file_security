# File Upload Security

Hardens Odoo's file upload pipeline by extending `ir.attachment` to intercept create and write operations. This module provides several layers of protection against malicious file uploads.

## Features

-   **Extension Blocklist**: Pre-configured with 50+ dangerous file types (e.g., `.exe`, `.bat`, `.ps1`, `.php`).
-   **MIME Type Blocklist**: Prevents uploads based on content type (e.g., `application/x-executable`).
-   **Magic-Bytes Validation**: Detects disguised files (e.g., an executable renamed to `.pdf`) by checking actual content.
-   **Double-Extension Prevention**: Identifies and blocks files like `invoice.pdf.exe`.
-   **File Size Limits**: Configurable maximum upload size per file.
-   **ClamAV Antivirus**: Optional integration for real-time virus and malware scanning using a ClamAV daemon.
-   **Audit Logging**: Detailed logs of all blocked upload attempts for security monitoring.
-   **Bypass for Superusers**: Administrative users can bypass extension/MIME/size checks (but NOT virus scanning).

## Dependencies

### Odoo Modules
- `base`
- `base_setup`
- `web`

### Python Libraries
- `pyclamd` (Required for antivirus scanning)

## Configuration

Settings are located under **Settings → General Settings → File Security**.

| Parameter | Default | Description |
| :--- | :--- | :--- |
| **Enabled** | `True` | Global toggle for security checks. |
| **Blocked Extensions** | *Standard list* | Comma-separated list of forbidden extensions. |
| **Blocked MIME Types** | *Standard list* | Comma-separated list of forbidden content types. |
| **Max File Size (MB)** | `25` | Maximum allowed size per upload (0 for unlimited). |
| **Strict Mode** | `True` | Enables magic-bytes content verification. |
| **Enable Antivirus** | `True` | Enables ClamAV scanning. |
| **ClamAV Socket** | `/var/run/clamav/clamd.ctl` | Path to the ClamAV daemon Unix socket. |
| **Block on AV Failure** | `True` | Blocks uploads if the scanner is unreachable. |

## Antivirus Setup

To use the antivirus feature:
1. Install ClamAV on the server: `sudo apt install clamav-daemon`
2. Ensure the Odoo user has read/write access to the ClamAV socket.
3. Install the Python library: `pip install pyclamd`
4. Enable "ClamAV scanning" in Odoo settings.

## Technical Details

The module inherits `ir.attachment` and overrides `_check_contents`. It also extends the web controllers for `binary` and `documents` to handle validation errors gracefully and provide user-friendly notifications in the UI.

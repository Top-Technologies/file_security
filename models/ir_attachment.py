import base64
import logging
import os
import re

from odoo import api, fields, models, _
from odoo.exceptions import ValidationError, UserError
from odoo.tools.mimetypes import guess_mimetype

try:
    import pyclamd
    _PYCLAMD_AVAILABLE = True
except ImportError:
    pyclamd = None
    _PYCLAMD_AVAILABLE = False

_logger = logging.getLogger(__name__)


def _parse_list_param(value):
    """Split a comma-separated config parameter into a cleaned set."""
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(',') if item.strip()}


def _extract_all_extensions(filename):
    """Return every extension segment in *filename* as a set of lowercase
    strings **including** the leading dot.

    Examples
    --------
    >>> _extract_all_extensions('report.pdf')
    {'.pdf'}
    >>> _extract_all_extensions('invoice.pdf.exe')
    {'.pdf', '.exe'}
    >>> _extract_all_extensions('archive')
    set()
    """
    if not filename:
        return set()
    
    basename = filename.lstrip('.')
    parts = basename.split('.')
    return {f'.{ext.lower()}' for ext in parts[1:] if ext}


class IrAttachment(models.Model):
    _inherit = 'ir.attachment'

    # -- Scan result fields (stored for audit trail) -------------------------

    av_scan_status = fields.Selection([
        ('not_scanned', 'Not Scanned'),
        ('clean', 'Clean'),
        ('infected', 'Infected'),
        ('failed', 'Scan Failed'),
    ], string="Antivirus Status", default='not_scanned', readonly=True,
       help="Result of the ClamAV antivirus scan performed during upload.")

    av_scan_detail = fields.Char(
        string="Scan Detail", readonly=True,
        help="Details from the antivirus scan (threat name or error).")

    def _fs_enabled(self):
        """Return True when file-security checks are active."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'file_security.enabled', 'True'
        ).lower() in ('1', 'true', 'yes')

    def _fs_strict_mode(self):
        return self.env['ir.config_parameter'].sudo().get_param(
            'file_security.strict_mode', 'True'
        ).lower() in ('1', 'true', 'yes')

    def _fs_blocked_extensions(self):
        raw = self.env['ir.config_parameter'].sudo().get_param(
            'file_security.blocked_extensions', ''
        )
        exts = _parse_list_param(raw)
        return {ext if ext.startswith('.') else f'.{ext}' for ext in exts}

    def _fs_blocked_mimetypes(self):
        raw = self.env['ir.config_parameter'].sudo().get_param(
            'file_security.blocked_mimetypes', ''
        )
        return _parse_list_param(raw)

    def _fs_max_file_size_bytes(self):
        try:
            mb = int(self.env['ir.config_parameter'].sudo().get_param(
                'file_security.max_file_size_mb', '25'
            ))
        except (ValueError, TypeError):
            mb = 25
        return mb * 1024 * 1024 if mb > 0 else 0  # 0 = unlimited

    # -- ClamAV antivirus helpers -------------------------------------------

    def _fs_antivirus_enabled(self):
        """Return True when ClamAV antivirus scanning is active."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'file_security.antivirus_enabled', 'False'
        ).lower() in ('1', 'true', 'yes')

    def _fs_antivirus_socket(self):
        """Return the path to the ClamAV daemon Unix socket."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'file_security.antivirus_socket', '/var/run/clamav/clamd.ctl'
        )

    def _fs_antivirus_block_on_failure(self):
        """Return True when uploads should be blocked if AV scan fails."""
        return self.env['ir.config_parameter'].sudo().get_param(
            'file_security.antivirus_block_on_failure', 'False'
        ).lower() in ('1', 'true', 'yes')

    def _fs_scan_with_clamav(self, raw, filename):
        """Scan raw bytes with ClamAV. Returns a tuple (status, detail):
        - ('clean', None) if no threat found
        - ('infected', threat_name) if virus detected
        - ('failed', error_message) if scan could not complete
        - (None, None) if scanning was skipped

        Raises :class:`~odoo.exceptions.UserError` if a virus is found
        or if the daemon is unreachable and block-on-failure is enabled.
        """
        if not _PYCLAMD_AVAILABLE:
            _logger.warning(
                "FILE-SECURITY | pyclamd library is not installed. "
                "Antivirus scanning is enabled but will be skipped. "
                "Install it with: pip install pyclamd"
            )
            if self._fs_antivirus_block_on_failure():
                raise UserError(_(
                    "Upload blocked: antivirus scanning is required but the "
                    "scanning library (pyclamd) is not installed. "
                    "Contact your administrator."
                ))
            return ('failed', 'pyclamd library not installed')

        socket_path = self._fs_antivirus_socket()
        _logger.info(
            "FILE-SECURITY | Connecting to ClamAV daemon at %s for file '%s'",
            socket_path, filename,
        )
        try:
            cd = pyclamd.ClamdUnixSocket(filename=socket_path)
            cd.ping()
        except Exception as e:
            _logger.warning(
                "FILE-SECURITY | Cannot connect to ClamAV daemon at %s: %s",
                socket_path, e,
            )
            if self._fs_antivirus_block_on_failure():
                raise UserError(_(
                    "Upload blocked: antivirus scanning is required but the "
                    "ClamAV daemon is unreachable. "
                    "Contact your administrator.",
                ))
            return ('failed', f'Cannot connect to ClamAV: {e}')

        try:
            _logger.info(
                "FILE-SECURITY | Scanning %d bytes for file '%s'",
                len(raw), filename,
            )
            result = cd.scan_stream(raw)
        except Exception as e:
            _logger.warning(
                "FILE-SECURITY | ClamAV scan_stream failed for '%s': %s",
                filename, e,
            )
            if self._fs_antivirus_block_on_failure():
                raise UserError(_(
                    "Upload blocked: antivirus scan failed for '%(filename)s'. "
                    "Contact your administrator.",
                    filename=filename,
                ))
            return ('failed', f'Scan error: {e}')

        if result is None:
            _logger.info(
                "FILE-SECURITY | ClamAV scan CLEAN for file '%s'",
                filename,
            )
            return ('clean', None)

        # result looks like: {'stream': ('FOUND', 'Eicar-Signature')}
        status, threat_name = result.get('stream', ('UNKNOWN', 'unknown'))
        if status == 'FOUND':
            _logger.warning(
                "FILE-SECURITY | ClamAV VIRUS DETECTED in '%s': %s",
                filename, threat_name,
            )
            return ('infected', threat_name)

        return ('clean', None)

    # -- Main validation ----------------------------------------------------

    def _file_security_validate(self, values):
        """Run all file-security checks on *values* dict.

        Raises :class:`~odoo.exceptions.UserError` with a
        user-friendly message when a violation is detected.
        """
        filename = values.get('name', '')
        mimetype = values.get('mimetype', '')

        # --- raw binary data --------------------------------------------------
        raw = None
        if values.get('raw'):
            raw = values['raw']
            if isinstance(raw, str):
                raw = raw.encode()
        elif values.get('datas'):
            try:
                raw = base64.b64decode(values['datas'])
            except Exception:
                raw = None

        # ---- 5. ClamAV antivirus scan (runs for ALL users including superuser) --
        if self._fs_antivirus_enabled() and raw:
            _logger.info(
                "FILE-SECURITY | Antivirus scan triggered for '%s' "
                "(user=%s, is_superuser=%s)",
                filename, self.env.user.login, self.env.is_superuser(),
            )
            scan_status, scan_detail = self._fs_scan_with_clamav(raw, filename)

            # Store scan result in values for later persistence
            values['av_scan_status'] = scan_status
            values['av_scan_detail'] = scan_detail or ''

            if scan_status == 'infected':
                self._fs_log_blocked(
                    filename,
                    f'Virus detected by ClamAV: {scan_detail}',
                )
                raise UserError(_(
                    "Upload blocked: the file '%(filename)s' was flagged by "
                    "the antivirus scanner as containing a threat "
                    "(%(threat)s). The file has been rejected. "
                    "Contact your administrator if you believe this is an error.",
                    filename=filename, threat=scan_detail,
                ))
            elif scan_status == 'clean':
                _logger.info(
                    "FILE-SECURITY | File '%s' passed antivirus scan",
                    filename,
                )
        elif self._fs_antivirus_enabled() and not raw:
            _logger.info(
                "FILE-SECURITY | Antivirus scan skipped for '%s' (no raw data)",
                filename,
            )

        # Superusers bypass extension/MIME/size checks but NOT virus scan
        if self.env.is_superuser():
            _logger.debug(
                "FILE-SECURITY | Superuser bypass for non-AV checks on '%s'",
                filename,
            )
            return

        if not self._fs_enabled():
            return

        # ---- 1. File-size limit -----------------------------------------------
        max_bytes = self._fs_max_file_size_bytes()
        if max_bytes and raw and len(raw) > max_bytes:
            size_mb = len(raw) / (1024 * 1024)
            limit_mb = max_bytes / (1024 * 1024)
            self._fs_log_blocked(filename, f'File size {size_mb:.1f} MB exceeds limit of {limit_mb:.0f} MB')
            raise UserError(_(
                "Upload blocked: the file '%(filename)s' is %(size).1f MB, "
                "which exceeds the maximum allowed size of %(limit).0f MB.",
                filename=filename, size=size_mb, limit=limit_mb,
            ))

        # ---- 2. Extension blocklist -------------------------------------------
        blocked_exts = self._fs_blocked_extensions()
        if blocked_exts and filename:
            file_exts = _extract_all_extensions(filename)
            matched = file_exts & blocked_exts
            if matched:
                ext_str = ', '.join(sorted(matched))
                self._fs_log_blocked(filename, f'Blocked extension(s): {ext_str}')
                raise UserError(_(
                    "Upload blocked: the file '%(filename)s' contains a "
                    "forbidden file extension (%(extensions)s). "
                    "Contact your administrator if you believe this is an error.",
                    filename=filename, extensions=ext_str,
                ))

        # ---- 3. MIME-type blocklist -------------------------------------------
        blocked_mimes = self._fs_blocked_mimetypes()
        if blocked_mimes and mimetype and mimetype.lower() in blocked_mimes:
            self._fs_log_blocked(filename, f'Blocked MIME type: {mimetype}')
            raise UserError(_(
                "Upload blocked: the file '%(filename)s' has a forbidden "
                "content type (%(mimetype)s). "
                "Contact your administrator if you believe this is an error.",
                filename=filename, mimetype=mimetype,
            ))

        # ---- 4. Magic-bytes / strict mode -------------------------------------
        if self._fs_strict_mode() and raw and blocked_exts:
            detected_mime = guess_mimetype(raw)
            if detected_mime and detected_mime != 'application/octet-stream':
                # Check if the *real* content type is on the blocked MIME list
                if blocked_mimes and detected_mime.lower() in blocked_mimes:
                    self._fs_log_blocked(
                        filename,
                        f'Magic-bytes detected dangerous MIME: {detected_mime} '
                        f'(declared: {mimetype})',
                    )
                    raise UserError(_(
                        "Upload blocked: the actual content of "
                        "'%(filename)s' was detected as %(detected)s, "
                        "which is a forbidden content type. The file may be "
                        "disguised. Contact your administrator.",
                        filename=filename, detected=detected_mime,
                    ))

    def _fs_log_blocked(self, filename, reason):
        user = self.env.user
        _logger.warning(
            "FILE-SECURITY BLOCKED | user=%s (id=%s) | file=%s | reason=%s",
            user.login, user.id, filename, reason,
        )

    def _check_contents(self, values):
        """Extend the base check to enforce file-security rules *after*
        the standard MIME computation but *before* post-processing."""
        values = super()._check_contents(values)
        self._file_security_validate(values)
        return values

import base64
import logging
import os
import re

from odoo import api, models, _
from odoo.exceptions import ValidationError, UserError
from odoo.tools.mimetypes import guess_mimetype

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

    def _file_security_validate(self, values):
        """Run all file-security checks on *values* dict.

        Raises :class:`~odoo.exceptions.ValidationError` with a
        user-friendly message when a violation is detected.
        """
        # Superusers bypass everything
        if self.env.is_superuser():
            return

        if not self._fs_enabled():
            return

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

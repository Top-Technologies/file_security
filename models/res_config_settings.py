# Part of Odoo. See LICENSE file for full copyright and licensing details.

from odoo import api, fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    file_security_enabled = fields.Boolean(
        string="Enable File Upload Security",
        config_parameter='file_security.enabled',
        default=True,
    )
    file_security_blocked_extensions = fields.Char(
        string="Blocked File Extensions",
        config_parameter='file_security.blocked_extensions',
        help="Comma-separated list of blocked file extensions (without dots). "
             "Example: exe,bat,sh,php",
    )
    file_security_blocked_mimetypes = fields.Char(
        string="Blocked MIME Types",
        config_parameter='file_security.blocked_mimetypes',
        help="Comma-separated list of blocked MIME types. "
             "Example: application/x-executable,application/x-msdownload",
    )
    file_security_max_file_size_mb = fields.Integer(
        string="Maximum File Size (MB)",
        config_parameter='file_security.max_file_size_mb',
        default=25,
        help="Maximum allowed file size in megabytes. Set to 0 for no limit.",
    )
    file_security_strict_mode = fields.Boolean(
        string="Strict Mode (Magic-Bytes Verification)",
        config_parameter='file_security.strict_mode',
        default=True,
        help="When enabled, the module inspects the actual binary content "
             "(magic bytes) of uploaded files to detect disguised executables, "
             "even if the file extension appears safe.",
    )
    file_security_antivirus_enabled = fields.Boolean(
        string="Antivirus Scanning (ClamAV)",
        config_parameter='file_security.antivirus_enabled',
        default=False,
        help="When enabled, uploaded files are scanned for viruses using "
             "the ClamAV daemon. Requires clamav-daemon to be installed "
             "and running on the server.",
    )
    file_security_antivirus_socket = fields.Char(
        string="ClamAV Socket Path",
        config_parameter='file_security.antivirus_socket',
        default='/var/run/clamav/clamd.ctl',
        help="Path to the ClamAV daemon Unix socket. "
             "Default: /var/run/clamav/clamd.ctl",
    )
    file_security_antivirus_block_on_failure = fields.Boolean(
        string="Block Uploads on Scan Failure",
        config_parameter='file_security.antivirus_block_on_failure',
        default=False,
        help="When enabled, file uploads are blocked if the antivirus "
             "scanner is unreachable or fails. When disabled, uploads are "
             "allowed with a warning in the log.",
    )

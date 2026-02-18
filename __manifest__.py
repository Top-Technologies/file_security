# Part of Odoo. See LICENSE file for full copyright and licensing details.
{
    'name': 'File Upload Security',
    'version': '18.0.1.0.0',
    'category': 'Tools/Security',
    'summary': 'Block dangerous file uploads with configurable extension/MIME blocklists, magic-bytes validation, and file size limits',
    'description': """
File Upload Security
====================
Hardens Odoo's file upload pipeline by extending ir.attachment to intercept
create and write operations. Provides:

* Configurable extension blocklist (50+ dangerous types pre-configured)
* MIME type blocklist validation
* Magic-bytes content verification (detects disguised executables)
* Double-extension attack prevention (e.g., report.pdf.exe)
* Configurable maximum file size limit
* Audit logging of all blocked upload attempts
* Settings UI under General Settings → File Security

All checks can be toggled on/off from the settings panel.
Superusers bypass all restrictions.
    """,
    'author': 'Top-Tech',
    'website': '',
    'depends': ['base', 'base_setup','web'],
    'data': [
        'data/ir_config_parameter_data.xml',
        'views/res_config_settings_views.xml',
    ],
    'installable': True,
    'auto_install': False,
    'application': False,
    'license': 'LGPL-3',
}

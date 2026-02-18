# -*- coding: utf-8 -*-
import base64
import json
import logging
import unicodedata

from odoo import http, _
from odoo.http import request
from odoo.addons.web.controllers.binary import Binary
from odoo.exceptions import UserError, AccessError

_logger = logging.getLogger(__name__)

def clean(name):
    return name.replace('\x3c', '')

class BinaryCustom(Binary):
    @http.route('/web/binary/upload_attachment', type='http', auth="user")
    def upload_attachment(self, model, id, ufile, callback=None):
        files = request.httprequest.files.getlist('ufile')
        Model = request.env['ir.attachment']
        out = """<script language="javascript" type="text/javascript">
                    var win = window.top.window;
                    win.jQuery(win).trigger(%s, %s);
                </script>"""
        args = []
        for ufile in files:
            filename = ufile.filename
            if request.httprequest.user_agent.browser == 'safari':
                # Safari sends NFD UTF-8 (where é is composed by 'e' and [accent])
                # we need to send it the same stuff, otherwise it'll fail
                filename = unicodedata.normalize('NFD', ufile.filename)
            try:
                attachment = Model.create({
                    'name': filename,
                    'raw': ufile.read(),
                    'res_model': model,
                    'res_id': int(id)
                })
                attachment._post_add_create()
            except UserError as e:
                # Catch file security errors and return the specific message
                args.append({'error': str(e)})
                _logger.warning("File security blocked upload: %s - %s", filename, str(e))
            except AccessError:
                args.append({'error': _("You are not allowed to upload an attachment here.")})
            except Exception:
                args.append({'error': _("Something horrible happened")})
                _logger.exception("Fail to upload attachment %s", ufile.filename)
            else:
                args.append({
                    'filename': clean(filename),
                    'mimetype': attachment.mimetype,
                    'id': attachment.id,
                    'size': attachment.file_size
                })
        return out % (json.dumps(clean(callback)), json.dumps(args)) if callback else json.dumps(args)

    @http.route('/web/binary/upload', type='http', auth="user")
    def upload(self, model, id, ufile, callback=None):
        # Alias for upload_attachment if needed by some clients
        return self.upload_attachment(model, id, ufile, callback=callback)

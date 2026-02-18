# -*- coding: utf-8 -*-
from odoo import http
from odoo.http import request
from odoo.addons.documents.controllers.documents import ShareRoute
from odoo.exceptions import UserError

class ShareRouteCustom(ShareRoute):
    
    # Re-define the helper to use in the route decorator
    def _max_content_length(self):
        return request.env['documents.document'].get_document_max_upload_limit()

    @http.route(['/documents/upload/', '/documents/upload/<access_token>'],
                type='http', auth='public', methods=['POST'],
                max_content_length=_max_content_length)
    def documents_upload(self, ufile, access_token='', owner_id='', partner_id='', res_id='', res_model='', allowed_company_ids=''):
        try:
            return super(ShareRouteCustom, self).documents_upload(
                ufile, access_token, owner_id, partner_id, res_id, res_model, allowed_company_ids
            )
        except UserError as e:
            return request.make_response(str(e), [('Content-Type', 'text/plain')], status=400)

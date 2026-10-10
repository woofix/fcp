# Copyright 2026 Eric TOMAS and FCP contributors
# SPDX-License-Identifier: Apache-2.0
# Modified for the portable FCP distribution.
"""Authenticate every application route. Use HTTPS for any remote access."""
import hmac
import os
from flask import request, Response


def install_auth(app):
    username = os.environ.get('FCP_ADMIN_USER', 'admin')
    password = os.environ.get('FCP_ADMIN_PASSWORD', '')
    if len(password) < 20:
        raise RuntimeError('Set FCP_ADMIN_PASSWORD to a unique password of at least 20 characters.')

    @app.before_request
    def authenticate():
        auth = request.authorization
        if (auth and auth.type.lower() == 'basic'
                and hmac.compare_digest((auth.username or '').encode(), username.encode())
                and hmac.compare_digest((auth.password or '').encode(), password.encode())):
            return None
        return Response('Authentication required', 401, {
            'WWW-Authenticate': 'Basic realm="FCP", charset="UTF-8"',
            'Cache-Control': 'no-store',
        })

    @app.after_request
    def private_response(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        return response

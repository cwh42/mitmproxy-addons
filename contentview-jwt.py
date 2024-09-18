"""
Pretty View decoded JWTokens

Usage:

    mitmproxy -s contentview-jwt.py --set cert=/path/to/cert.pem
"""

import jwt
import logging
from functools import lru_cache
from typing import Any
from cryptography.x509 import load_pem_x509_certificate
from mitmproxy import ctx, contentviews, flow, exceptions
from mitmproxy.contentviews.json import parse_json, format_json, ViewJSON

PARSE_ERROR = object()
INVALID_CERT = object()
AUTH_HDR = 'Authorization'

@lru_cache(1)
def decode_token(token: str, key) -> Any:
    decoded = jwt.decode(token, key, algorithms=["RS256"], options={"verify_signature": False})
    return decoded

def fetch_token(s: bytes) -> Any:
    j = parse_json(s)
    if 'token' not in j: return PARSE_ERROR
    return j['token']

def has_bearer_token(f: flow.Flow):
    return bool(AUTH_HDR in f.request.headers and f.request.headers[AUTH_HDR].startswith('Bearer'))

class ViewJWT(ViewJSON):
    name = "JWT"
    key = ''

    def __call__(self, data, *, flow: flow.Flow | None = None, **metadata):
        if data:
            token = fetch_token(data)
        else:
            if has_bearer_token(flow):
                token = flow.request.headers[AUTH_HDR].rpartition(' ')[-1]

        if token and token is not PARSE_ERROR:
            data = decode_token(token, self.key)
            return self.name, format_json(data)

    def set_key(self, key):
        self.key = key

    def render_priority(
        self, data: bytes, *, content_type: str | None = None, flow: flow.Flow | None = None, **metadata
    ) -> float:
        if not data:
            if has_bearer_token(flow):
                return 1
            return 0
        if (
          content_type == "application/json"
          and 'token' in parse_json(data)
        ):
            return 1
        return 0


view = ViewJWT()

def load(l):
    l.add_option(
        name="cert",
        typespec=str,
        default='',
        help="Certificate containing public key for token decryption."
    )
    contentviews.add(view)

def configure(updates):
    if "cert" in updates:
        try:
            with open(ctx.options.cert) as certificate:
                cert_str = certificate.read()

            cert = bytes(cert_str, 'utf-8')
            cert_obj = load_pem_x509_certificate(cert)
        except Exception as err:
            raise exceptions.OptionsError(err)
        else:
            view.set_key(cert_obj.public_key())
            logging.info('Read new key from "' + str(ctx.options.cert) + '".')

def done():
    contentviews.remove(view)

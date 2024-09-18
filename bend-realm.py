"""
Replace realm in Www-Authenticate header

Usage:

    mitmproxy -s bend-realm.py --set realm=http://localhost:3000/auth
"""
import re
from mitmproxy import ctx

def load(loader):
    loader.add_option(
        name="realm",
        typespec=str,
        default='',
        help="Replace Www-Authenticate realm by this one"
    )

def response(flow):
    if ctx.options.realm == '': return
    auth = flow.response.headers.get("Www-Authenticate")
    if auth is None: return
    auth = re.sub(r'realm=".*?"', f'realm="{ctx.options.realm}"', auth)
    flow.response.headers["Www-Authenticate"] = auth

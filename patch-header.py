"""
Find and replace in Headers

Usage:

    mitmproxy -s patch-header.py  --set in_hdr=Location --set find=http://localhost:3000/auth --set replace=http://localhost
"""
from mitmproxy import ctx

def load(loader):
    loader.add_option(
        name="in_hdr",
        typespec=str,
        default='',
        help="header"
    )
    loader.add_option(
        name="find",
        typespec=str,
        default='',
        help="find"
    )
    loader.add_option(
        name="replace",
        typespec=str,
        default='',
        help="replace"
    )

def response(flow):
    if ctx.options.in_hdr == '': return
    hdr = flow.response.headers.get(ctx.options.in_hdr)
    if hdr is None: return
    hdr = hdr.replace(ctx.options.find, ctx.options.replace)
    flow.response.headers[ctx.options.in_hdr] = hdr

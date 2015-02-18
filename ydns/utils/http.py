##
# YDNS Core
#
# Copyright (c) 2015 Christian Jurk <commx@commx.ws>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
##

from django.core.urlresolvers import reverse

def absolute_url(request, url, suffix=None, *args, **kwargs):
    """
    Build absolute URL by using a resolver pattern.

    :param request: HttpRequest
    :param url: URL pattern or absolute path (str)
    :param suffix: Optional suffix (str)
    :param args: Arguments to be passed to the URL resolver (tuple)
    :param kwargs: Keyword arguments to be passed to the URL resolver (dict)
    :return: str
    """
    real_url = reverse(url, *args, **kwargs)

    if suffix:
        real_url += suffix

    scheme = 'https' if request.is_secure() else 'http'

    return scheme + '://' + request.get_host() + real_url
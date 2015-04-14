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

from django.conf import settings
from requests.exceptions import RequestException

import requests


# Verification URL
_url_verify = 'https://www.google.com/recaptcha/api/siteverify'


class RecaptchaError(ValueError):
    pass


def verify(response, remote_ip=None):
    """
    Verify user response.

    Raises RecaptchaError in case the response cannot be verified or is invalid.

    :param response: User response (str)
    :param remote_ip: Remote IP (optional)
    """
    data = {'secret': settings.RECAPTCHA_PRIVATE_KEY,
            'response': response}

    if remote_ip:
        data['remoteip'] = remote_ip

    try:
        r = requests.post(_url_verify, data=data)
    except RequestException as exc:
        raise RecaptchaError(str(exc))
    else:
        reply = r.json()

        if not reply['success']:
            raise RecaptchaError(', '.join(reply['error-codes']))
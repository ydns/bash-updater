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

from accounts.models import User
from time import time
from urllib.parse import quote

import base64
import hashlib
import hmac
import struct

class InvalidTokenError(ValueError):
    """
    A exception which is raised when the token is invalid.
    """
    pass

class IncorrectTokenError(ValueError):
    """
    A exception which is raised when the token is incorrect.
    """
    pass

def generate_secret():
    """
    Generate a 10 character secret that can be used for OTP.
    The secret is encoded with Base32 encoding.

    :return: Base32 encoded string
    """
    s = User.objects.make_random_password(10, allowed_chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
    return base64.b32encode(s.encode('ascii'))

def get_totp_key_uri(email, secret, issuer):
    """
    Provision a TOTP key URI for use with Google Chart to generate
    an appropriate QR Code.

    :param email: E-mail address of user
    :param secret: Base32 encoded secret
    :param issuer: Name of issuer
    :return: TOTP key URI
    """
    issuer = quote(issuer)
    return 'otpauth://totp/%s:%s?secret=%s&issuer=%s' % (issuer, email, secret, issuer)

def get_hotp_token(secret, interval):
    """
    Get a HMAC-based one-time password on the basis of a given secret
    and a specified interval number.

    :param secret: Base32 encoded secret
    :param interval: Interval
    :return: Generated token
    """
    key = base64.b32decode(secret, True)
    msg = struct.pack('>Q', interval)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    v = (struct.unpack('>I', h[o:o + 4])[0] & 0x7fffffff) % 1000000
    return v

def get_totp_token(secret):
    """
    Get a time-based one-time password on the basis of given
    secret and time.

    :param secret: Base32 encoded secret
    :return: Generated token
    """
    return get_hotp_token(secret, int(time()) // 30)

def is_valid_token(token):
    """
    Test whether the specified token is valid.
    A valid token consists of digits and has a maximum of 6 digits within.

    :param token: Token to test
    :return: True when the token is valid, otherwise False
    """
    if not isinstance(token, bytes):
        token = bytes(str(token).encode('ascii'))
    return token.isdigit() and len(token) <= 6

def verify_totp_token(token, secret):
    """
    Verify whether the specified time-based token is valid.

    :param token: Token to test
    :param secret: Base64 encoded secret
    :return: True if the tokens match, otherwise False
    """
    if not is_valid_token(token):
        raise InvalidTokenError('Not a valid token: %r' % token)
    elif int(token) != get_totp_token(secret):
        raise IncorrectTokenError('Incorrect token (%d)' % int(token))
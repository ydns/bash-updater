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

from .common import PRIMARY_NS, SECONDARY_NS
from .enum import DomainValidationResult

import dns.resolver


def validate_domain_name(name):
    """
    Validate a domain name.

    :param name: Domain name (str)
    :return: server list (list)
    :raises: DomainValidationError
    """
    has_primary = False
    has_secondary = False
    servers = []

    try:
        answers = dns.resolver.query(name, 'NS')
    except dns.resolver.NXDOMAIN:  # domain does not exist
        return DomainValidationResult.NOT_FOUND, servers, None
    except Exception as exc:  # any other exception has been raised
        return DomainValidationResult.EXCEPTION_RAISED, servers, str(exc)
    else:
        for rdata in answers:
            rt = rdata.to_text()

            if rt.endswith('.'):
                rt = rt[:-1]

            if rt in PRIMARY_NS:
                has_primary = True
            elif rt in SECONDARY_NS:
                has_secondary = True

            servers.append(rt)

        if not has_primary:
            return DomainValidationResult.MISSING_PRIMARY, servers, None
        elif not has_secondary:
            return DomainValidationResult.MISSING_SECONDARY, servers, None
        else:
            return DomainValidationResult.OK, servers, None
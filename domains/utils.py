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

from django.utils import timezone
from enum import IntEnum

import dns.resolver

PRIMARY_NS = (
    'ns1.ydns.eu',
    'ns1.commx.ws',  # alias for "ns1.ydns.eu"
)

SECONDARY_NS = (
    'ns2.ydns.eu',   # Frankfurt am Main (DE)
    'ns3.ydns.eu',   # New York City (VM)
    'ns2.commx.ws',  # alias for ns2.ydns.eu
)

class ValidationResult(IntEnum):
    ok = 0
    domain_not_found = 1
    exception_raised = 2
    missing_primary = 3
    missing_secondary = 4

def validate(domain):
    """
    Validate a domain's nameserver records.

    :param domain: Domain
    :return:
    """
    has_primary = False
    has_secondary = False
    servers = []

    try:
        answers = dns.resolver.query(domain.name, 'NS')
    except dns.resolver.NXDOMAIN:  # domain is gone
        if domain.is_active:
            domain.is_active = False
            domain.save()
            domain.add_message(tag='disable_domain',
                               result_code=ValidationResult.domain_not_found.value)
        return (ValidationResult.domain_not_found, servers, None)
    except Exception as exc:  # any other exception has occurred
        if domain.is_active:
            domain.is_active = False
            domain.save()
            domain.add_message(tag='disable_domain',
                               result_code=ValidationResult.exception_raised.value,
                               message=str(exc))
        return (ValidationResult.exception_raised, servers, str(exc))
    else:
        for rdata in answers:
            rt = rdata.to_text()

            if rt.endswith('.'):
                rt = rt[:-1]  # strip for PowerDNS-compatibility

            if rt in PRIMARY_NS:
                has_primary = True
            elif rt in SECONDARY_NS:
                has_secondary = True

            servers.append(rt)

    if not has_primary:
        if domain.is_active:
            domain.is_active = False
            domain.save()
            domain.add_message(tag='disable_domain',
                               result_code=ValidationResult.missing_primary.value)
        return (ValidationResult.missing_primary, servers, None)
    elif not has_secondary:
        if domain.is_active:
            domain.is_active = False
            domain.save()
            domain.add_message(tag='disable_domain',
                               result_code=ValidationResult.missing_secondary.value)
        return (ValidationResult.missing_secondary, servers, None)

    # Validation is fine so far
    if not domain.is_active:
        domain.is_active = True

    domain.date_last_validated = timezone.now()
    domain.save()

    return (ValidationResult.ok, servers, None)
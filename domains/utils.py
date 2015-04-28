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

from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from .common import PRIMARY_NS, SECONDARY_NS
from .enum import DomainValidationResult
from .records.enum import RecordType

import dns.resolver


def create_basic_records(domain):
    """
    Create basic records for a new domain.

    :param domain: Domain
    """

    # Start of Authority (SOA)
    update_serial(domain)

    # Name server (NS)
    for s in (PRIMARY_NS[0], SECONDARY_NS[0]):
        domain.records.create(name=domain.name,
                              domain=domain,
                              type=RecordType.NS,
                              content=s,
                              owner=domain.owner)


def update_serial(domain):
    """
    Update serial for a domain.

    If no SOA record exists, such record is created and returned.
    Otherwise, the serial is updated.

    :param domain: Domain
    :return: Record
    """
    s = timezone.now().strftime('%Y%m%d')
    content = '{name}. hostmaster.yns.io. ({serial} 3600 1800 604800 600)'

    try:
        soa_record = domain.records.get(type=RecordType.SOA)
    except ObjectDoesNotExist:
        s += '00'
        soa_record = domain.records.create(domain=domain,
                                           name=domain.name,
                                           type=RecordType.SOA,
                                           content=content.format(name=domain.name, serial=s),
                                           owner=domain.owner)
        return soa_record

    else:
        inc = int(soa_record.content[8:])

        if soa_record.content[:8] == s:
            inc += 1

        s += '{0:02}'.format(inc)
        soa_record.content = content.format(name=domain.name, serial=s)
        soa_record.date_modified = timezone.now()
        soa_record.save()
        return soa_record


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
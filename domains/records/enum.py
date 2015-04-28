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

from ydns.utils.enum import StrEnum


class RecordType(StrEnum):
    """
    Supported DNS resource record types (RR).
    """
    A = 'A'
    AAAA = 'AAAA'
    AFSDB = 'AFSDB'
    CERT = 'CERT'
    CNAME = 'CNAME'
    DNSKEY = 'DNSKEY'
    DS = 'DS'
    HINFO = 'HINFO'
    KEY = 'KEY'
    LOC = 'LOC'
    MX = 'MX'
    NAPTR = 'NAPTR'
    NS = 'NS'
    NSEC = 'NSEC'
    PTR = 'PTR'
    RP = 'RP'
    RRSIG = 'RSIG'
    SOA = 'SOA'
    SPF = 'SPF'
    SSHFP = 'SSHFP'
    SRV = 'SRV'
    TLSA = 'TLSA'
    TXT = 'TXT'

    @property
    def is_usable(self):
        """
        Return whether a record type is usable for users.

        :return: bool
        """
        return self in (RecordType.A,
                        RecordType.AAAA,
                        RecordType.AFSDB,
                        RecordType.CERT,
                        RecordType.CNAME,
                        RecordType.DNSKEY,
                        RecordType.DS,
                        RecordType.HINFO,
                        RecordType.KEY,
                        RecordType.LOC,
                        RecordType.MX,
                        RecordType.NAPTR,
                        RecordType.NSEC,
                        RecordType.PTR,
                        RecordType.RP,
                        RecordType.RRSIG,
                        RecordType.SPF,
                        RecordType.SSHFP,
                        RecordType.SRV,
                        RecordType.TLSA,
                        RecordType.TXT)
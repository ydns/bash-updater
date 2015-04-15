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


class DomainAccessType(StrEnum):
    """
    Domain access type enumeration.
    """
    PUBLIC = 'Public'
    PRIVATE = 'Private'
    MODERATED = 'Moderated'


class DomainStatus(StrEnum):
    OK = 'OK'
    ERROR = 'Error'


class DomainType(StrEnum):
    """
    PowerDNS specific domain types.
    """
    NATIVE = 'NATIVE'
    MASTER = 'MASTER'
    SLAVE = 'SLAVE'
    SUPERSLAVE = 'SUPERSLAVE'


class DomainValidationResult(StrEnum):
    OK = 'OK'
    NOT_FOUND = 'Domain does not exist'
    EXCEPTION_RAISED = 'An exception has been raised'
    MISSING_PRIMARY = 'Missing primary name server'
    MISSING_SECONDARY = 'Missing secondary name server'

    def __str__(self):
        return self.value
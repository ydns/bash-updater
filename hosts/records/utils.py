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

from django.utils.translation import ugettext_lazy as _

__all__ = ['supported_resource_types']

# The following resource record types are supported
supported_resource_types = (
    ('A', _("Stores a static IP address (IPv4)")),
    ('AAAA', _("Stores a static IP address (IPv6)")),
    ('CNAME', _("Canonical name to a host")),
    ('MX', _("Mail Exchanger")),
    ('NS', _("Hostname of authoriative nameserver")),
    ('SPF', _("Sender Policy Framework")),
    ('SRV', _("Service Provider")),
    ('SSHFP', _("Fingerprint of SSH keys")),
    ('TXT', _('Freely usable text field')),
)
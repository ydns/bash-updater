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

from django.db import models
from django.utils import timezone
from django.utils.safestring import mark_safe
from ydns.fields import EnumField
from .enum import DomainAccessType, DomainStatus, DomainType
from .records.models import Record


class Domain(models.Model):
    """
    PowerDNS based domain model.

    Not all fields are used by YDNS; they're listed here to
    create a fully functional database layout to work with recent
    PowerDNS versions.
    """
    class Meta:
        db_table = 'domains'
        ordering = ('name',)

    name = models.CharField(max_length=255, unique=True)
    master = models.CharField(max_length=128, null=True)
    last_check = models.IntegerField(null=True)
    type = EnumField(DomainType)
    notified_serial = models.IntegerField(null=True)
    account = models.CharField(max_length=40, null=True)

    date_created = models.DateTimeField(default=timezone.now)
    owner = models.ForeignKey('accounts.User', null=True)
    access_type = EnumField(DomainAccessType)
    active = models.BooleanField(default=True)
    public_owner = models.BooleanField(default=False)
    status = EnumField(DomainStatus)

    def __str__(self):
        return self.name.encode('ascii').decode('idna')

    def delete(self, using=None):
        self.records.all().delete()
        return super(Domain, self).delete(using)

    def get_permissions(self, user):
        s = set()

        if not user.is_authenticated():
            if self.access_type == DomainAccessType.PUBLIC:
                s.add('r')
        elif user.is_admin or user == self.owner:
            for k in 'rwa':
                s.add(k)

        return s

    @property
    def is_idn(self):
        """
        Return whether the domain is an international domain name.

        :return: bool
        """
        return self.name != str(self)

    @property
    def records(self):
        return Record.objects.filter(domain=self)

    @property
    def status_label(self):
        if self.status == DomainStatus.OK:
            s = '<span class="text-success">OK</span>'
        elif self.status == DomainStatus.ERROR:
            s = '<span class="text-danger">Error</span>'
        else:
            s = '???'
        return mark_safe(s)
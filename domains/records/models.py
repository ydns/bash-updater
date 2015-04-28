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

from domains.enum import DomainAccessType
from django.db import models
from django.utils import timezone
from django.utils.safestring import mark_safe
from ydns.fields import EnumField, JsonField
from ydns.utils import user_agent
from .enum import RecordType


class Record(models.Model):
    """
    PowerDNS based record.
    """
    class Meta:
        db_table = 'records'
        ordering = ('name',)

    domain = models.ForeignKey('domains.Domain', on_delete=models.PROTECT)
    name = models.CharField(max_length=255, null=True)
    type = EnumField(RecordType)
    content = models.TextField(null=True)
    ttl = models.IntegerField(null=True)
    prio = models.IntegerField(null=True)
    change_date = models.IntegerField(null=True)
    disabled = models.BooleanField(default=False)
    ordername = models.CharField(max_length=255, null=True)
    auth = models.BooleanField(default=True)

    date_created = models.DateTimeField(default=timezone.now)
    date_modified = models.DateTimeField(default=timezone.now)
    owner = models.ForeignKey('accounts.User', null=True)

    def __str__(self):
        return self.name.encode('ascii').decode('idna')

    def get_permissions(self, user):
        s = set()

        if not user.is_authenticated():
            return set()
        elif user.is_admin:
            for k in 'rwa':
                s.add(k)
        elif self.domain.access_type == DomainAccessType.PRIVATE and user == self.domain.owner:
            for k in 'rwa':
                s.add(k)
        elif self.domain.access_type == DomainAccessType.PUBLIC and user == self.owner:
            for k in 'rw':
                s.add(k)

        return s

    @property
    def is_deletable(self):
        """
        Return whether the record can be deleted safely.

        :return: bool
        """
        if str(self.domain) == str(self) and self.type in (RecordType.SOA, RecordType.NS):
            return False

        return True

    @property
    def is_editable(self):
        return self.is_deletable

    @property
    def padded_id(self):
        """
        Return padded version of ID.

        :return: str
        """
        return '{:05}'.format(self.id)

    @property
    def recent_updates(self):
        return self.updates.order_by('-date_created')

    @property
    def status_label(self):
        if self.disabled:
            s = '<span class="text-muted">Disabled</span>'
        else:
            s = '<span class="text-success">Active</span>'
        return mark_safe(s)

    @property
    def updates(self):
        return Update.objects.filter(record=self)


class Update(models.Model):
    """
    Record updates.
    """
    class Meta:
        db_table = 'record_updates'
        ordering = ('date_created',)

    date_created = models.DateTimeField(default=timezone.now)
    record = models.ForeignKey(Record)
    changes = JsonField()
    user_agent = models.TextField(null=True)

    @property
    def summary(self):
        cc = len(self.changes.keys())

        if cc == 1:
            for k, v in self.changes.items():
                ks = k.capitalize()

                if ks == 'Ttl':
                    ks = ks.upper()

                return '{}: {} -> {}'.format(ks, v[0], v[1])
        else:
            return '{} change{}'.format(cc, '' if cc == 1 else 's')

    @property
    def ua(self):
        if self.user_agent:
            data = user_agent.parse(self.user_agent)
            s = None

            if data['browser']:
                s = data['browser']
                if data['os']:
                    s += ' ({})'.format(data['os'])

                    if data['os'] == 'OS X':
                        data['icon'] = 'apple'
                    elif data['os'] == 'Windows':
                        data['icon'] = 'windows'
                    elif data['os'] == 'Linux':
                        data['icon'] = 'linux'

            if s:
                data['s'] = s

            return data

        return None
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

from django.db import models, connection
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _
from enum import Enum, IntEnum

class BlacklistedDomain(models.Model):
    """
    Model for a blacklisted domain pattern.
    """
    name = models.TextField()
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    reason = models.TextField(null=True)

    class Meta:
        db_table = 'domains_bl'
        ordering = ('name',)

class BlacklistedHost(models.Model):
    """
    Model for a blacklisted host pattern.
    """
    name = models.TextField()
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    reason = models.TextField(null=True)

    class Meta:
        db_table = 'hosts_bl'

class DomainType(Enum):
    """
    Domain type enumeration.
    """
    native = 'NATIVE'
    master = 'MASTER'
    slave = 'SLAVE'

class DomainAccessType(IntEnum):
    """
    Domain access type enumeration.
    """
    public = 1
    private = 2
    moderated = 3

    @staticmethod
    def from_string(s):
        """
        Get enumeration instance by string.

        :param s: Name of enumeration item
        :return: str
        """
        if s == 'public':
            return DomainAccessType.public
        elif s == 'private':
            return DomainAccessType.private
        elif s == 'moderated':
            return DomainAccessType.moderated

        raise ValueError('invalid access type: %r' % s)

    def get_label(self):
        """
        Get label HTML code.

        :return: str
        """
        cls = ''

        if self.value == DomainAccessType.public:
            cls = 'success'
        elif self.value == DomainAccessType.private:
            cls = 'info'
        elif self.value == DomainAccessType.moderated:
            cls = 'warning'
        else:
            return ''

        return mark_safe('<span class="label label-subtle label-%s">%s</span>' % (cls, str(self)))

    def __str__(self):
        """
        Get translated string representation of the access type.

        :return: str
        """
        if self.value == DomainAccessType.public.value:
            return _("Public")
        elif self.value == DomainAccessType.private.value:
            return _("Private")
        elif self.value == DomainAccessType.moderated.value:
            return _("Moderated")

        return super(DomainAccessType, self).__str__()


class Domain(models.Model):
    """
    Domain model.
    """
    name = models.CharField(max_length=255, unique=True)
    master = models.CharField(max_length=128, null=True)
    last_check = models.IntegerField(null=True)
    type = models.CharField(max_length=6, default=DomainType.native.value)
    date_created = models.DateTimeField(default=timezone.now)
    date_last_validated = models.DateTimeField(null=True)
    owner = models.ForeignKey('accounts.User', null=True)
    public_owner = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_official = models.BooleanField(default=False)
    access_type = models.SmallIntegerField(default=DomainAccessType.private.value)

    class Meta:
        db_table = 'domains'
        ordering = ('name',)

    def add_message(self, ip, user, **meta):
        """
        Add a message to the domain log.

        :param ip: IP address (str)
        :param user: User
        :param meta: Additional arguments (dict)
        """
        DomainLogMessage.objects.create(domain=self,
                                        user=user,
                                        ip=ip,
                                        meta=meta)

    def can_create_hosts(self, user):
        """
        Returns whether a user can create hosts with this domain.

        Returns True if the user is allowed to do so,
        False if not and None in case the creation request must be moderated.

        :return: bool
        """
        if self.access_type == DomainAccessType.public.value:
            return True
        elif self.access_type == DomainAccessType.private.value:
            return self.owner == user
        elif self.access_type == DomainAccessType.moderated.value:
            if self.owner == user:
                return True
            else:
                return None  # special case: moderation required

        return False

    def delete(self, using=None):
        """
        Delete a domain.

        :param using: Optional database connection
        """
        DomainLogMessage.objects.filter(domain=self).delete()

        for host in Host.objects.filter(records__domain=self):
            host.delete()

        return super(Domain, self).delete(using=using)

    def get_access_type(self):
        """
        Get enumeration instance of domain access type.

        :return: DomainAccessType
        """
        return DomainAccessType(self.access_type)

    def get_host_requests(self):
        """
        Get domain host requests.

        :return: QuerySet
        """
        return HostRequest.objects.filter(domain=self)

    def get_status_label(self):
        """
        Get HTML code for the domain status.

        :return: str
        """
        cls = ''
        label = ''

        if self.is_active:
            cls = 'success'
            label = _("Good")
        else:
            cls = 'danger'
            label = _("Bad")

        return mark_safe('<span class="label label-subtle label-%s">%s</span>' % (cls, label))

    @property
    def hosts(self):
        """
        Get hosts for this domain.

        :return: QuerySet
        """
        return Host.objects.filter(domain=self)

    @staticmethod
    def is_blacklisted(name):
        """
        Test whether a specific domain name pattern is blacklisted.

        :param name: Domain name
        :return: bool
        """
        cursor = connection.cursor()
        cursor.execute('SELECT COUNT(*) FROM domains_bl WHERE %s ~ name', [name])
        result = cursor.fetchone()
        cursor.close()

        return result[0] > 0

    def is_manager(self, request):
        """
        Return whether a user request got manager privileges for this domain.

        :return: bool
        """
        return request.user.is_admin or (self.owner and request.user == self.owner)

    @property
    def is_moderated(self):
        """
        Return whether the domain is moderated.

        :return: bool
        """
        return self.access_type == DomainAccessType.moderated.value

    @property
    def journal(self):
        """
        Returns the domain journal.

        :return: QuerySet
        """
        return DomainLogMessage.objects.filter(domain=self)

    def notify_all(self, reason):
        """
        Notify owner and users using this domain.
        """
        if reason == 'delete':
            pass  # TODO: Send mail

    def __str__(self):
        """
        Get real domain name (IDNA decoded).

        :return: str
        """
        return self.name.encode('ascii').decode('idna')

class DomainLogMessage(models.Model):
    """
    Domain journal log message.
    """
    domain = models.ForeignKey(Domain)
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    ip = models.GenericIPAddressField(unpack_ipv4=True, null=True)
    meta = models.TextField()

    class Meta:
        db_table = 'domains_log'
        ordering = ('date_created',)

    @property
    def message(self):
        """
        Get translated version of a log message entry.

        :return: str
        """
        tag = self.meta.get('tag')

        if tag == 'create_domain':
            return _("Domain created")
        elif tag == 'public_owner_enabled':
            return _("Owner contact details are now public")
        elif tag == 'public_owner_disabled':
            return _("Owner contact details are now private")
        elif tag == 'access_type_changed':
            access_type = str(DomainAccessType(self.meta['access_type']))
            return _("Access type changed to \"%(access_type)s\"") % {'access_type': access_type}
        elif tag == 'host_created':
            return _("Host \"%s\" created") % self.meta['host_name'].encode('ascii').decode('idna')
        elif tag == 'host_deleted':
            return _("Host \"%s\" deleted") % self.meta['host_name'].encode('ascii').decode('idna')

        return tag

class Host(models.Model):
    """
    A host groups records of a same name.
    It must be checked that all records that are created for a host
    have the same name.
    """
    user = models.ForeignKey('accounts.User', null=True)
    name = models.CharField(max_length=255)
    domain = models.ForeignKey(Domain)
    date_created = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    records = models.ManyToManyField('Record', null=True)

    class Meta:
        db_table = 'hosts'
        ordering = ('name',)

    def add_message(self, tag, ip=None, user=None, **meta):
        """
        Add a message to the host journal.

        :param tag: Log tag (str)
        :param ip: IP address (str)
        :param user: User
        :param meta: Optional arguments (dict)
        """
        HostLogMessage.objects.create(host=self,
                                        user=user,
                                        ip=ip,
                                        tag=tag,
                                        meta=meta)

    def delete(self, using=None):
        """
        Delete the host.

        :param using: Optional database connection
        """
        HostLogMessage.objects.filter(host=self).delete()
        self.records.all().delete()
        return super(Host, self).delete(using=using)

    def get_latest_record(self):
        """
        Get the record that was updated most recently.

        :return: Record or None
        """
        all_records = self.records.order_by('date_last_modified')

        if all_records.count() > 0:
            return all_records.last()

        return None

    def get_status_label(self):
        """
        Get HTML code for the host status label.

        :return: str
        """
        s = ''

        if not self.is_active:
            s = '<span class="label label-subtle">%s</span>' % _("Disabled")
        elif self.is_good:
            s = '<span class="label label-subtle label-success">%s</span>' % _("Good")
        else:
            s = '<span class="label label-subtle label-danger">%s</span>' % _("Bad")

        return mark_safe(s)

    @staticmethod
    def is_blacklisted(name):
        """
        Test whether a specific host name pattern is blacklisted.

        Use explicitly raw SQL to improve lookup performance.

        :param name: Domain name (str)
        :return: bool
        """
        cursor = connection.cursor()
        cursor.execute('SELECT COUNT(*) FROM hosts_bl WHERE %s ~ name', [name])
        result = cursor.fetchone()
        cursor.close()

        return result[0] > 0

    @property
    def is_good(self):
        """
        Test whether the host status is considered fine.

        This applies when the host has records and at least one
        record was updated recently.

        :return: bool
        """
        if self.records.count() == 0:
            return False

        latest = self.get_latest_record()

        if not latest.date_last_modified:
            return False

        return True

    @property
    def is_underlying_disabled(self):
        """
        Returns whether all underlying records are disabled.

        :return: bool
        """
        if self.records.count() > 0 and self.records.filter(disabled=True).count() == self.records.count():
            return True

        return False

    @property
    def journal(self):
        """
        Get the host journal.

        :return: QuerySet
        """
        return HostLogMessage.objects.filter(host=self)

    def __str__(self):
        """
        Get string representation of the hostname (IDNA decoded).

        :return: str
        """
        return self.name.encode('ascii').decode('idna')

class HostLogMessage(models.Model):
    """
    A host journal log message.
    """
    host = models.ForeignKey(Host)
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    ip = models.GenericIPAddressField(unpack_ipv4=True, null=True)
    tag = models.CharField(max_length=255)
    meta = models.TextField()

    class Meta:
        db_table = 'hosts_log'
        ordering = ('date_created',)

    @property
    def message(self):
        """
        Get translated version of a log message entry.

        :return: str
        """
        message = self.tag

        if self.tag == 'host_request':
            message = _("Host request")
        elif self.tag == 'host_created':
            message = _("Host created")
        elif self.tag == 'enable_host':
            message = _("Host enabled")
        elif self.tag == 'disable_host':
            message = _("Host disabled")
        elif self.tag == 'record_created':
            message = _("Record created (%s)") % self.meta['rr_type']
        elif self.tag == 'record_deleted':
            message = _("Record deleted")
        elif self.tag == 'record_updated':
            message = _("Record updated")
        elif self.tag == 'record_enabled':
            message = _("Record enabled")
        elif self.tag == 'record_disabled':
            message = _("Record disabled")
        elif self.tag == 'journal_cleared':
            message = _("Journal cleared")

        return message

class HostRequest(models.Model):
    """
    Moderation request for a host.
    """
    user = models.ForeignKey('accounts.User')
    domain = models.ForeignKey(Domain)
    name = models.CharField(max_length=255)
    date_created = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'hosts_request'

    def __str__(self):
        """
        Get string representation of the host (IDNA decoded) including the domain name.

        :return: str
        """
        decoded_name = self.name.encode('ascii').decode('idna')
        return decoded_name + '.' + str(self.domain)


class Message(models.Model):
    class Meta:
        db_table = 'messages'
        ordering = ('date_created',)

    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='ref+')
    date_created = models.DateTimeField(default=timezone.now)
    message = models.TextField()


class Record(models.Model):
    """
    A DNS record.
    """
    domain = models.ForeignKey(Domain)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10)
    content = models.CharField(max_length=65535)
    ttl = models.IntegerField(null=True)
    prio = models.IntegerField(null=True)
    disabled = models.BooleanField(default=False)
    auth = models.BooleanField(default=True)
    date_created = models.DateTimeField(default=timezone.now)
    date_last_modified = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'records'
        ordering = ('name',)

    def get_status_label(self):
        """
        Get HTML code for the record status label.

        :return: str
        """
        if not self.disabled:
            return '<span class="label label-subtle label-success">%s</span>' % _("Good")
        else:
            return '<span class="label label-subtle">%s</span>' % _("Disabled")
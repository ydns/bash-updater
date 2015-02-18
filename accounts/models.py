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

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.urlresolvers import reverse
from django.db import models
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from enum import IntEnum
from jsonfield import JSONField
from ydns.models import Domain, Host

class BetaInvitation(models.Model):
    email = models.EmailField(max_length=256)
    code = models.CharField(max_length=64)
    date_created = models.DateTimeField(default=timezone.now)
    invited_by = models.ForeignKey('accounts.User')

class ActivationRequest(models.Model):
    user = models.ForeignKey('User')
    date_created = models.DateTimeField(default=timezone.now)
    token = models.CharField(max_length=64)

    class Meta:
        db_table = 'activation_requests'

class BlacklistedEmail(models.Model):
    name = models.TextField()
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    reason = models.TextField(null=True)

    class Meta:
        db_table = 'ebl'

class ResetPasswordRequest(models.Model):
    user = models.ForeignKey('User')
    date_created = models.DateTimeField(default=timezone.now)
    token = models.CharField(max_length=64)

    class Meta:
        db_table = 'password_reset_requests'

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **kwargs):
        user = self.model(email=self.normalize_email(email), **kwargs)
        user.set_password(password)
        user.save(using=self._db)

        return user

class UserType(IntEnum):
    """
    User account types.
    """
    native = 1
    google = 2
    facebook = 3
    twitter = 4
    github = 5

    def to_str(self):
        if self.value == UserType.native.value:
            return _('Native')
        elif self.value == UserType.google.value:
            return _('Google')
        elif self.value == UserType.facebook.value:
            return _('Facebook')
        elif self.value == UserType.github.value:
            return _('GitHub')
        elif self.value == UserType.twitter.value:
            return _('Twitter')
        else:
            return str(self)

class User(AbstractBaseUser):
    alias = models.CharField(max_length=16)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    type = models.SmallIntegerField(default=UserType.native)
    language = models.CharField(max_length=5, null=True)
    otp_secret = models.CharField(max_length=10, null=True)
    otp_active = models.BooleanField(default=False)
    api_password = models.CharField(max_length=40, default='')
    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'

    class Meta:
        db_table = 'users'

    def add_message(self, ip=None, **meta):
        return UserLogMessage.objects.create(user=self,
                                             ip=ip,
                                             meta=meta)

    def delete(self, using=None):
        UserLogMessage.objects.filter(user=self).delete()
        OtpRecoveryCode.objects.filter(user=self).delete()
        UserBan.objects.filter(user=self).delete()

        from ydns.models import Host, Domain

        for domain in Domain.objects.filter(owner=self):
            domain.owner = None
            domain.save()

        Host.objects.filter(user=self).delete()

        return super(User, self).delete(using=using)

    @property
    def domains(self):
        return Domain.objects.filter(owner=self)

    def get_ban(self):
        try:
            ban = UserBan.objects.get(user=self)
        except UserBan.DoesNotExist:
            return None
        else:
            return ban

    def get_log_messages(self):
        return UserLogMessage.objects.filter(user=self)

    def get_priv_label(self):
        cls = ''
        label = ''

        if self.is_admin:
            cls = ' label-danger'
            label = _("Administrator")
        else:
            cls = ' label-info'
            label = _("Normal")

        return mark_safe('<span class="label%s">%s</span>' % (cls, label))

    def get_status_label(self):
        cls = ''
        label = ''

        if self.get_ban():
            cls = ' label-danger'
            label = _("Banned")
        elif not self.is_active:
            cls = ' label-info'
            label = _("Pending activation")
        else:
            cls = ' label-success'
            label = _("Active")

        return mark_safe('<span class="label label-subtle%s">%s</span>' % (cls, label))

    def get_type(self):
        return UserType(self.type)

    def get_type_label(self):
        cls = ''
        label = UserType(self.type).to_str()

        if self.type == UserType.native:
            cls = ' label-success'

        return mark_safe('<span class="label label-subtle%s">%s</span>' % (cls, label))

    @property
    def hosts(self):
        return Host.objects.filter(user=self)

    @property
    def is_native(self):
        return self.type == UserType.native

class UserBan(models.Model):
    user = models.ForeignKey(User)
    date_created = models.DateTimeField(default=timezone.now)
    banned_by = models.ForeignKey(User, null=True, related_name='banned_by')
    reason = models.TextField()

    class Meta:
        db_table = 'users_ban'

class UserLogMessage(models.Model):
    user = models.ForeignKey(User)
    date_created = models.DateTimeField(default=timezone.now)
    ip = models.GenericIPAddressField(unpack_ipv4=True, null=True)
    meta = JSONField()

    class Meta:
        db_table = 'users_log'
        ordering = ('date_created',)

    def get_translated_message(self):
        tag = self.meta.get('tag')
        message = tag

        if tag == 'signup':
            message = _("Sign up")
        elif tag == 'login':
            message = _("Login")
        elif tag == 'enable_otp':
            message = _("Two-factor authentication enabled")
        elif tag == 'disable_otp':
            message = _("Two-factor authentication disabled")
        elif tag == 'clear_journal':
            message = _("Journal cleared")
        elif tag == 'api_password_set':
            message = _("API password set (auto)")
        elif tag == 'api_password_reset':
            message = _("API password reset")
        elif tag == 'create_domain':
            idna_name = self.meta['name'].encode('idna').decode('ascii')
            html = ''

            try:
                Domain.objects.get(name=idna_name)
            except Domain.DoesNotExist:
                html = '<em>%s</em>' % self.meta['name']
            else:
                url = reverse('domains:detail', args=(idna_name,))
                html = '<a href="%s">%s</a>' % (url, self.meta['name'])

            message = mark_safe(_('Domain %s created') % (html,))
        elif tag == 'account_banned':
            message = _("Account banned: %s") % (self.meta['reason'],)
        elif tag == 'account_unbanned':
            message = _("Account ban removed")
        elif tag == 'activate':
            message = _("Account activated")

        return message

    def get_user_agent(self):
        ua = self.guess_user_agent(self.meta.get('user_agent') or '')
        s = ''

        if ua['os']:
            if ua['os'] == 'Windows':
                s = '<i class="fa fa-windows fa-fw"></i> '
            elif ua['os'] == 'Mac':
                s = '<i class="fa fa-apple fa-fw"></i> '
            elif ua['os'] == 'Linux':
                s = '<i class="fa fa-linux fa-fw"></i> '

        if ua['browser']:
            s += ua['browser']

        if not s:
            ua = self.meta.get('user_agent')
        else:
            s = mark_safe(s)

        return s

    def guess_user_agent(self, s):
        os = ''
        browser = ''
        browser_version = ''

        if 'Macintosh' in s:
            os = 'Mac'
        elif 'NT ' in s:
            os = 'Windows'
        elif 'Linux ' in s:
            os = 'Linux'

        if 'Safari/' in s and 'Version/' in s:
            browser = 'Safari'
        elif 'Chrome/' in s:
            browser = 'Chrome'
        elif 'Firefox/' in s:
            browser = 'Firefox'
        elif 'MSIE ' in s:
            browser = 'Internet Explorer'

        return {'os': os, 'browser': browser, 'browser_version': browser_version}

class OtpRecoveryCode(models.Model):
    user = models.ForeignKey(User)
    code = models.CharField(max_length=24)

    class Meta:
        db_table = 'otp_recovery_codes'
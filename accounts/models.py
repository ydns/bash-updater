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
from django.db import models
from django.utils import timezone
from ydns.fields import EnumField
from ydns.models import Domain, Host
from .enum import UserType


class ActivationRequest(models.Model):
    """
    Activation request for new accounts.
    """
    class Meta:
        db_table = 'activation_request'

    user = models.ForeignKey('User', on_delete=models.CASCADE)
    date_created = models.DateTimeField(default=timezone.now)
    token = models.CharField(max_length=64)


class BlacklistedEmail(models.Model):
    """
    Blacklisted email address pattern.
    """
    class Meta:
        db_table = 'ebl'

    name = models.TextField()
    user = models.ForeignKey('accounts.User', null=True)
    date_created = models.DateTimeField(default=timezone.now)
    reason = models.TextField(null=True)


class ResetPasswordRequest(models.Model):
    user = models.ForeignKey('User')
    date_created = models.DateTimeField(default=timezone.now)
    token = models.CharField(max_length=64)

    class Meta:
        db_table = 'password_reset_requests'


class UserManager(BaseUserManager):
    """
    User object manager.
    """
    def create_user(self, email, password=None, **kwargs):
        user = self.model(email=self.normalize_email(email), **kwargs)
        user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """
    Custom user model.
    """
    class Meta:
        db_table = 'users'
        ordering = ('date_joined',)

    alias = models.CharField(max_length=16)
    email = models.EmailField(max_length=255, unique=True)
    is_active = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    type = EnumField(UserType, default=UserType.NATIVE)
    otp_secret = models.CharField(max_length=10, null=True)
    otp_active = models.BooleanField(default=False)
    api_password = models.CharField(max_length=40)
    date_joined = models.DateTimeField(default=timezone.now)
    journal = models.ManyToManyField('ydns.Message', related_name='user_journal')

    objects = UserManager()

    USERNAME_FIELD = 'email'

    def add_to_log(self, message):
        """
        Add a message to the journal.

        :param message: Message
        :return: Message
        """
        return self.journal.create(message=message, user=self)

    @property
    def domains(self):
        return Domain.objects.filter(owner=self)

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    @property
    def hosts(self):
        return Host.objects.filter(user=self)


class OtpRecoveryCode(models.Model):
    """
    One-time passwords recovery codes.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=24)

    class Meta:
        db_table = 'otp_recovery_codes'
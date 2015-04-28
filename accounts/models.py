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
from django.utils.safestring import mark_safe
from ydns.fields import EnumField
from .enum import UserType


class _UserTokenModel(models.Model):
    """
    Abstract model for user tokens.
    """
    class Meta:
        abstract = True

    user = models.ForeignKey('User', on_delete=models.CASCADE)
    date_created = models.DateTimeField(default=timezone.now)
    token = models.TextField()


class ActivationRequest(_UserTokenModel):
    """
    Activation request for new accounts.
    """
    class Meta:
        db_table = 'activation_requests'


class PasswordRequest(_UserTokenModel):
    """
    Password reset requests.
    """
    class Meta:
        db_table = 'password_requests'


class UserManager(BaseUserManager):
    """
    User object manager.
    """
    def create_user(self, email, password=None, **kwargs):
        """
        Create user account.

        :param email: Email address
        :param password: Optional password
        :param kwargs: Keyword arguments
        :return: User instance
        """
        api_password = self.make_random_password(40)

        # Create account
        user = self.model(email=self.normalize_email(email),
                          alias=self.get_alias(),
                          api_password=api_password,
                          **kwargs)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def get_alias(self):
        """
        Get a random alias which is not in use.

        :return: str
        """
        while True:
            alias = self.make_random_password(16)

            try:
                self.get(alias=alias)
            except self.model.DoesNotExist:
                return alias


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
    api_password = models.CharField(max_length=40)
    date_joined = models.DateTimeField(default=timezone.now)
    timezone = models.CharField(max_length=100, null=True)
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

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    @property
    def status_label(self):
        if self.is_active:
            s = '<span class="label label-success label-subtle">Active</span>'
        elif ActivationRequest.objects.filter(user=self).count() > 0:
            s = '<span class="label label-info label-subtle">New</span>'
        else:
            s = '<span class="label label-default label-subtle">Inactive</span>'
        return mark_safe(s)

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

from accounts.enum import UserType
from accounts.models import User
from accounts.utils import activate_timezone, deactivate_timezone
from collections import OrderedDict
from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseNotFound
from ydns.views import FormView, TemplateView
from . import forms

import pytz


class _BaseView(TemplateView):
    """
    Common view template.
    """
    require_login = True
    require_admin = False


class ApiAccessView(_BaseView):
    """
    Display API Access credentials.
    """
    template_name = 'accounts/settings/api_access.html'


class ChangePasswordView(_BaseView, FormView):
    """
    Change the account password.
    """
    form_class = forms.ChangePasswordForm
    template_name = 'accounts/settings/change_password.html'

    def dispatch(self, request, *args, **kwargs):
        if request.user.type != UserType.NATIVE:
            return HttpResponseNotFound()
        return super(ChangePasswordView, self).dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        if not self.request.user.check_password(form.cleaned_data['current']):
            form.add_error('current', 'Incorrect password')
        if form.cleaned_data['new'] != form.cleaned_data['repeat']:
            for k in ('new', 'repeat'):
                form.add_error(k, 'The passwords do not match')

        if not form.is_valid():
            return self.form_invalid(form)

        self.request.user.set_password(form.cleaned_data['new'])
        self.request.user.save()
        self.request.user.add_to_log('Password changed')

        messages.success(self.request, 'Your password hs been updated.')
        return self.redirect('accounts:settings:change_password')


class ClearJournalView(_BaseView):
    """
    Clear the user journal.
    """
    def get(self, request, *args, **kwargs):
        request.user.journal.all().delete()
        request.user.add_to_log('Journal cleared')

        messages.info(request, 'The journal has been cleared.')
        return self.redirect('accounts:settings:journal')


class DeleteAccountView(_BaseView):
    """
    Delete user account.
    """
    template_name = 'accounts/settings/delete_account.html'

    def post(self, request, *args, **kwargs):
        request.user.delete()
        messages.info(request, 'Your account has been deleted.')
        return self.redirect('home')


class HomeView(_BaseView):
    """
    Settings landing page.
    """
    template_name = 'accounts/settings/home.html'


class JournalView(_BaseView):
    """
    Display user journal.
    """
    template_name = 'accounts/settings/journal.html'


class ResetApiPasswordView(_BaseView):
    """
    Reset API password.
    """
    def get(self, request, *args, **kwargs):
        request.user.api_password = User.objects.make_random_password(40)
        request.user.save()
        request.user.add_to_log('API Password reset')

        messages.info(request, 'Your API password has been reset. Please make sure to adjust your updater '
                               'configuration to use the new API password.')

        return self.redirect('accounts:settings:api_access')


class TimezoneView(_BaseView, FormView):
    """
    View or modify account timezone.
    """
    form_class = forms.ChangeTimezoneForm
    template_name = 'accounts/settings/timezone.html'

    def form_valid(self, form):
        tzname = form.cleaned_data['timezone']
        user = self.request.user

        if tzname == settings.TIME_ZONE:
            if user.timezone:
                user.timezone = None
                user.save()
                user.add_to_log('Timezone setting removed')
                messages.info(self.request, 'Timezone setting removed.')
                deactivate_timezone(self.request)
        elif tzname != user.timezone:
            user.timezone = tzname
            user.save()
            user.add_to_log('Timezone set to {}'.format(tzname))
            messages.info(self.request, 'Timezone set to {}'.format(tzname))
            activate_timezone(self.request)

        return self.redirect('accounts:settings:timezone')

    def get_form_kwargs(self):
        kwargs = super(TimezoneView, self).get_form_kwargs()
        kwargs['timezone_choices'] = self.get_timezone_choices()
        return kwargs

    def get_initial(self):
        initial = super(TimezoneView, self).get_initial()

        if self.request.user.timezone:
            initial['timezone'] = self.request.user.timezone
        else:
            initial['timezone'] = settings.TIME_ZONE

        return initial

    @staticmethod
    def get_timezone_choices():
        """
        Collect grouped timezone choices.

        :return: tuple
        """
        tz_group = OrderedDict()

        for tz in pytz.common_timezones:
            if '/' in tz:
                a, b = tz.split('/', 1)
            else:
                a, b = 'Other', tz

            if a not in tz_group:
                tz_group[a] = []

            tz_group[a].append((tz, b.replace('_', ' ')))

        for k in tz_group.keys():
            tz_group[k] = tuple(sorted(tz_group[k], key=lambda x: x[1]))

        return tuple(tz_group.items())
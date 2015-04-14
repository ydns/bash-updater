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
from django.http import HttpResponseNotFound
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.views import FormView, TemplateView
from . import forms

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

    def delete_account(self, request):
        email = request.user.email

        request.user.delete()

        msg = EmailMessage(_('Account deletion'),
                           tpl='accounts/settings/delete_account.mail')
        msg.send(to=[email])

        messages.info(request,
                      _("Your account including all associated data has been deleted."),
                      _("Account deletion"))

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.delete_account(request)
            return self.redirect('home')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('delete'):
            errors['delete'] = _("You must check this box in order to proceed")
        else:
            cleaned_data['delete'] = True

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data


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
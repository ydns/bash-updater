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

from accounts.models import User, UserType, OtpRecoveryCode
from accounts.utils import otp
from django.http import HttpResponse, HttpResponseNotFound
from django.utils.translation import check_for_language, ugettext as _, LANGUAGE_SESSION_KEY
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.views import TemplateView, View

class ApiAccessView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/api_access.html'

    def get(self, request, *args, **kwargs):
        if not request.user.api_password:
            request.user.api_password = User.objects.make_random_password(40)
            request.user.save()

            request.user.add_message(request.META['REMOTE_ADDR'],
                                     tag='api_password_set',
                                     user_agent=request.META.get('HTTP_USER_AGENT'))

        return super(ApiAccessView, self).get(request, *args, **kwargs)

class ChangePasswordView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/change_password.html'

    def change_password(self, request, cleaned_data):
        request.user.set_password(cleaned_data['password'])
        request.user.save()

        request.user.add_message(request.META['REMOTE_ADDR'],
                                 tag='change_password',
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

        messages.success(request,
                         _("Your password has been changed."),
                         _("Change password"))

    def get(self, request, *args, **kwargs):
        if not request.user.type == UserType.native:
            messages.error(request,
                           _("Passwords can be changed for native accounts only."),
                           _("Request Error"))
            return self.redirect('accounts:settings:home')

        return super(ChangePasswordView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if not request.user.type == UserType.native:
            messages.error(request,
                           _("Passwords can be changed for native accounts only."),
                           _("Request Error"))
            return self.redirect('accounts:settings:home')

        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.change_password(request, cleaned_data)
            return self.redirect('accounts:settings:home')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('current_password'):
            errors['current_password'] = _("Enter your current password")
        elif not request.user.check_password(request.POST['current_password']):
            errors['current_password'] = _("Incorrect password")
        else:
            cleaned_data['current_password'] = request.POST['current_password']

        if not request.POST.get('password'):
            errors['password'] = _("Enter a new password")
        elif len(request.POST['password']) < 6:
            errors['password'] = _("The new password must have at least 6 characters")
        elif request.user.check_password(request.POST['password']):
            errors['password'] = _("The new password must not match the current one")
        else:
            cleaned_data['password'] = request.POST['password']

        if not request.POST.get('password_rpt'):
            errors['password_rpt'] = _("Repeat the new password")
        elif request.POST.get('password') != request.POST.get('password_rpt'):
            for k in ('password', 'password_rpt'):
                errors[k] = _("The passwords don't match")

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class ClearJournalView(View):
    requires_admin = False
    requires_login = True

    def get(self, request, *args, **kwargs):
        request.user.get_log_messages().delete()
        request.user.add_message(request.META['REMOTE_ADDR'],
                                 tag='clear_journal',
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

        messages.info(request,
                      _("The journal has been cleared."),
                      _("Journal cleared"))

        return self.redirect('accounts:settings:journal')

class DeleteAccountView(TemplateView):
    requires_admin = False
    requires_login = True
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

class HomeView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/home.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.save(request, cleaned_data)
            return self.redirect('accounts:settings:home')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def save(self, request, cleaned_data):
        """
        Save changes.

        :param cleaned_data: dict
        """
        request.user.language = cleaned_data.get('lang') or None
        request.user.save()

        if request.user.language:
            request.session[LANGUAGE_SESSION_KEY] = request.user.language
            request.session.modified = True

        messages.success(request,
                         _("Your changes have been saved."),
                         _("Success"))

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if request.POST.get('lang'):
            if not check_for_language(request.POST['lang']):
                errors['lang'] = _("Invalid language chosen")
            else:
                cleaned_data['lang'] = request.POST['lang']

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class JournalView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/journal.html'

class ResetApiPasswordView(View):
    requires_admin = False
    requires_login = True

    def get(self, request, *args, **kwargs):
        request.user.api_password = User.objects.make_random_password(40)
        request.user.save()

        request.user.add_message(request.META['REMOTE_ADDR'],
                                 tag='api_password_reset',
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

        messages.info(request,
                      _("Your API password has been reset. Please make sure to adjust your updater "
                        "configuration to use the new API password."))

        return self.redirect('accounts:settings:api_access')

class TwoFactorAuthView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/two_factor_auth.html'

class TwoFactorInstallInstructionsView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/two_factor_instructions.html'

    def get_context_data(self, **kwargs):
        context = super(TwoFactorInstallInstructionsView, self).get_context_data(**kwargs)
        context['google_totp_uri'] = otp.get_totp_key_uri(self.request.user.email,
                                                          self.request.user.otp_secret,
                                                          'YDNS')
        return context

class TwoFactorRecoveryCodesView(View):
    requires_admin = False
    requires_login = True

    def get(self, request, *args, **kwargs):
        if not request.user.otp_active:
            return HttpResponseNotFound()

        codes = []

        for otp_rec in OtpRecoveryCode.objects.filter(user=request.user):
            codes.append(otp_rec.code)

        codes.insert(0, '# Two-factor auth recovery codes for account %s (%s)' % (request.user.email, UserType(request.user.type).name))
        codes.insert(1, '# PLEASE BACKUP THIS FILE AND KEEP IT SECRET!')
        codes.insert(2, '')
        response = HttpResponse('\r\n'.join(codes), content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="ydns-2fa-recovery-codes.txt"'
        return response

class TwoFactorSetupView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'accounts/settings/two_factor_setup.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.setup(request, cleaned_data)

            if request.user.otp_active:
                return self.redirect('accounts:settings:two_factor_instructions')
            else:
                return self.redirect('accounts:settings:two_factor_auth')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def setup(self, request, cleaned_data):
        if cleaned_data.get('enable') and not request.user.otp_active:
            request.user.otp_secret = otp.generate_secret()
            request.user.otp_active = True
            request.user.save()

            # Generate a few recovery codes
            OtpRecoveryCode.objects.filter(user=request.user).delete()

            for i in range(3):
                code_seg = []

                for i2 in range(4):
                    s = User.objects.make_random_password(4, allowed_chars='abcdefghjklmnpqrstuvwxyz23456789')
                    code_seg.append(s)

                code_s = '-'.join(code_seg)
                OtpRecoveryCode.objects.create(user=request.user, code=code_s)

            request.user.add_message(request.META['REMOTE_ADDR'],
                                     tag='enable_otp',
                                     secret=request.user.otp_secret.decode('utf-8'),
                                     user_agent=request.META.get('HTTP_USER_AGENT'))

            messages.success(request,
                             _("Two-factor authentication has been enabled, please follow the installation "
                               "instructions to create the appropriate account on your phone."),
                             _("Two-factor authentication enabled"))
        elif not cleaned_data.get('enable') and request.user.otp_active:
            request.user.otp_secret = None
            request.user.otp_active = False
            request.user.save()

            # Delete recovery codes
            OtpRecoveryCode.objects.filter(user=request.user).delete()

            request.user.add_message(request.META['REMOTE_ADDR'],
                                     tag='disable_otp',
                                     secret=request.user.otp_secret,
                                     user_agent=request.META.get('HTTP_USER_AGENT'))

            messages.success(request,
                             _("Two-factor authentication has been disabled for your account."),
                             _("Two-factor authentication disabled"))

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if request.user.is_native:
            if not request.POST.get('current_password'):
                errors['current_password'] = _("Enter your current password")
            elif not request.user.check_password(request.POST['current_password']):
                errors['current_password'] = _("Incorrect password")

        if request.POST.get('enable') == 'enable':
            cleaned_data['enable'] = True

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data
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

from accounts.oauth import facebook, github, google
from accounts.models import ActivationRequest, ResetPasswordRequest, User, UserType, BetaInvitation
from accounts.utils import otp
from accounts.utils.common import is_blacklisted_email
from dateutil.relativedelta import relativedelta
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.core.urlresolvers import reverse
from django.core.validators import validate_email, ValidationError
from django.http import HttpResponseRedirect, HttpResponseNotFound, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.http import is_safe_url
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _, check_for_language, LANGUAGE_SESSION_KEY
from googler.recaptcha import captcha
from ydns.utils import messages
from ydns.utils.http import absolute_url
from ydns.utils.mail import EmailMessage
from ydns.views import TemplateView, View

import json

class ActivationView(View):
    requires_admin = False
    requires_login = False

    def get(self, request, *args, **kwargs):
        alias = request.GET.get('u')
        token = request.GET.get('token')

        if not alias:
            return self.response_error(request, _("Missing alias parameter"), _("Request error"))
        elif not token:
            return self.response_error(request, _("Missing token parameter"), _("Request error"))

        try:
            activation = ActivationRequest.objects.get(user__alias=alias, token=token)
        except ActivationRequest.DoesNotExist:
            return self.response_error(request, _("Activation link is unknown or has expired."), _("Request error"))
        else:
            if activation.user.is_active:
                return self.response_error(request, _("Your account is already activated"), _("Request error"))
            else:
                activation.user.is_active = True
                activation.user.save()

                activation.user.add_message(request.META['REMOTE_ADDR'],
                                            tag='activate',
                                            user_agent=request.META.get('HTTP_USER_AGENT'))

                # Delete the activation request
                activation.delete()

                messages.success(request, _("Your account has been activated successfully."), _("Success"))

                return self.redirect('accounts:login')

    def response_error(self, request, message, title):
        messages.error(request, message, title)
        return self.redirect('accounts:login')

class FacebookSignInView(View):
    """
    OAuth2 based login via Facebook Connect.

    For this, we use the "email" scope for accessing
    the email address of the user. It is then used
    to maintain a local user account associated with
    that email address.
    """
    requires_admin = False
    requires_login = False

    URL_GET_TOKEN = 'https://graph.facebook.com/oauth/access_token'
    URL_PROFILE = 'https://graph.facebook.com/me?'

    def create_user(self, email):
        """
        Create a new user account.

        :param email: Email address
        :return:
        """
        alias = None

        while True:
            alias = User.objects.make_random_password(16)

            try:
                User.objects.get(alias=alias)
            except User.DoesNotExist:
                break

        user = User.objects.create_user(email,
                                        type=UserType.facebook,
                                        alias=alias,
                                        is_active=True)

        user.add_message(self.request.META['REMOTE_ADDR'],
                         tag='signup',
                         type='facebook',
                         user_agent=self.request.META.get('HTTP_USER_AGENT'))

        # Send welcome Email
        context = {'user': user}
        msg = EmailMessage(_('Welcome to YDNS'),
                           tpl='accounts/welcome_facebook.mail',
                           context=context)
        msg.send(to=[user.email])

        return user

    def do_login(self, request, user):
        """
        Perform actual login.

        :param request: HttpRequest
        :param user: User
        """
        user.add_message(request.META['REMOTE_ADDR'],
                         tag='login',
                         type='facebook',
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        if user.otp_active:
            request.session['otp_uid'] = user.id
            request.session.modified = True
            return self.redirect('accounts:login_otp')
        else:
            LoginOtpView.login(request, user)
            return self.redirect('dashboard')

    def get(self, request, *args, **kwargs):
        """
        Verify the OAuth2 response from Facebook.

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        if not request.GET.get('state'):
            return self.response_error(request, _("Missing state property."), title=_("Facebook OAuth2 error"))
        elif not request.GET.get('code'):
            return self.response_error(request, _("Missing code property."), title=_("Facebook OAuth2 error"))

        state = request.GET['state']
        code = request.GET['code']

        if state != request.session.get('fb_state'):
            return self.response_error(request, _("Invalid state"), title=_("Facebook OAuth2 error"))

        facebook.redirect_uri = absolute_url(request, 'accounts:facebook_sign_in')
        facebook.scope = ''  # need to reset scope to '', because otherwise we'll get trouble

        try:
            facebook.fetch_token(self.URL_GET_TOKEN,
                               code=code,
                               client_secret=settings.FACEBOOK_APP_SECRET)
        except Exception:
            return self.response_error(request,
                                       _("An error occurred while verifying Facebook's response. "
                                         "Please try again later"),
                                       _("Facebook OAuth2 error"))

        response = facebook.get(self.URL_PROFILE)

        try:
            data = json.loads(response.content.decode('utf-8'))
        except ValueError:
            return self.response_error(request,
                                       _("Facebook's response has an invalid format."),
                                       _("Facebook OAuth2 error"))

        email_address = None

        if isinstance(data, dict) and data.get('email'):
            email_address = data['email']

        if not email_address:
            return self.response_error(request,
                                       _("No valid account-based email address found."),
                                       _("Facebook OAuth2 error"))

        # Now check if the account exists and login
        try:
            user = User.objects.get(email__iexact=email_address)
        except User.DoesNotExist:
            # TODO: Beta check
            try:
                BetaInvitation.objects.get(email__iexact=email_address)
            except BetaInvitation.DoesNotExist:
                return self.response_error(request,
                                           _("Your email address is not permitted to participate on the beta test."),
                                           _("Facebook OAuth2 error"))

            user = self.create_user(email_address)

        # Check if the user is banned
        ban = user.get_ban()

        if ban:
            return self.response_error(request,
                                       _("Your user account is banned: %s") % ban.reason,
                                       _("Facebook OAuth2 error"))

        if user.type == UserType.facebook:
            self.do_login(request, user)
            return self.redirect('home')
        else:
            return self.response_error(request,
                                       _("There is already an account with the same Email address, "
                                         "but with a different account type."),
                                       _("Login aborted"))

    def post(self, request, *args, **kwargs):
        """
        Request a OAuth2 login via Facebook.

        This has to be done through POST to ensure that no
        cross-site requests are happening (CSRF protection).

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        facebook.redirect_uri = absolute_url(request, 'accounts:facebook_sign_in')
        facebook.scope = 'email'

        authorization_url, state = facebook.authorization_url('https://www.facebook.com/dialog/oauth')

        request.session['fb_state'] = state

        return self.redirect(authorization_url)

    def response_error(self, request, message, title):
        messages.error(request, message, title)
        return self.redirect('accounts:login')

class GithubSignInView(View):
    """
    OAuth2 based login via GitHub.

    No scope is used; the default is to have read-only
    access to profile details, which is fine for us.
    """
    requires_admin = False
    requires_login = False

    URL_GET_TOKEN = 'https://github.com/login/oauth/access_token'
    URL_USER_PROFILE = 'https://api.github.com/user'

    def create_user(self, email):
        """
        Create a new user account.

        :param email: Email address
        :return:
        """
        alias = None

        while True:
            alias = User.objects.make_random_password(16)

            try:
                User.objects.get(alias=alias)
            except User.DoesNotExist:
                break

        user = User.objects.create_user(email,
                                        type=UserType.github,
                                        alias=alias,
                                        is_active=True)

        user.add_message(self.request.META['REMOTE_ADDR'],
                         tag='signup',
                         type='github',
                         user_agent=self.request.META.get('HTTP_USER_AGENT'))

        # Send welcome Email
        context = {'user': user}
        msg = EmailMessage(_('Welcome to YDNS'),
                           tpl='accounts/welcome_github.mail',
                           context=context)
        msg.send(to=[user.email])

        return user

    def do_login(self, request, user):
        """
        Perform actual login.

        :param request: HttpRequest
        :param user: User
        """
        user.add_message(request.META['REMOTE_ADDR'],
                         tag='login',
                         type='github',
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        if user.otp_active:
            request.session['otp_uid'] = user.id
            request.session.modified = True
            return self.redirect('accounts:login_otp')
        else:
            LoginOtpView.login(request, user)
            return self.redirect('dashboard')

    def get(self, request, *args, **kwargs):
        """
        Verify the OAuth2 response from Github.

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        if not request.GET.get('state'):
            return self.response_error(request, _("Missing state property."), title=_("GitHub OAuth2 error"))
        elif not request.GET.get('code'):
            return self.response_error(request, _("Missing code property."), title=_("GitHub OAuth2 error"))

        state = request.GET['state']
        code = request.GET['code']

        if state != request.session.get('github_state'):
            return self.response_error(request, _("Invalid state"), title=_("GitHub OAuth2 error"))

        github.redirect_uri = absolute_url(request, 'accounts:github_sign_in')
        github.scope = ''  # need to reset scope to '', because otherwise we'll get trouble

        try:
            github.fetch_token(self.URL_GET_TOKEN,
                               code=code,
                               client_secret=settings.GITHUB_CLIENT_SECRET)
        except Exception:
            return self.response_error(request,
                                       _("An error occurred while verifying GitHub's response. "
                                         "Please try again later"),
                                       _("GitHub OAuth2 error"))

        response = github.get(self.URL_USER_PROFILE)

        try:
            data = json.loads(response.content.decode('utf-8'))
        except ValueError:
            return self.response_error(request,
                                       _("GitHub's response has an invalid format."),
                                       _("GitHub OAuth2 error"))

        email_address = None

        if isinstance(data, dict) and data.get('email'):
            email_address = data['email']

        if not email_address:
            return self.response_error(request,
                                       _("No valid account-based email address found."),
                                       _("GitHub OAuth2 error"))

        # Now check if the account exists and login
        try:
            user = User.objects.get(email__iexact=email_address)
        except User.DoesNotExist:
            # TODO: Beta check
            try:
                BetaInvitation.objects.get(email__iexact=email_address)
            except BetaInvitation.DoesNotExist:
                return self.response_error(request,
                                           _("Your email address is not permitted to participate on the beta test."),
                                           _("GitHub OAuth2 error"))

            user = self.create_user(email_address)

        # Check if the user is banned
        ban = user.get_ban()

        if ban:
            return self.response_error(request,
                                       _("Your user account is banned: %s") % ban.reason,
                                       _("GitHub OAuth2 error"))

        if user.type == UserType.github:
            self.do_login(request, user)
            return self.redirect('home')
        else:
            return self.response_error(request,
                                       _("There is already an account with the same Email address, "
                                         "but with a different account type."),
                                       _("Login aborted"))

    def post(self, request, *args, **kwargs):
        """
        Request a OAuth2 login via GitHub.

        This has to be done through POST to ensure that no
        cross-site requests are happening (CSRF protection).

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        github.redirect_uri = absolute_url(request, 'accounts:github_sign_in')
        github.scope = None

        authorization_url, state = github.authorization_url('https://github.com/login/oauth/authorize')

        request.session['github_state'] = state

        return self.redirect(authorization_url)

    def response_error(self, request, message, title):
        messages.error(request, message, title)
        return self.redirect('accounts:login')

class GoogleSignInView(TemplateView):
    """
    OAuth2 based login via Google.

    For this, we use the "email" scope for accessing
    the email address of the user. It is then used
    to maintain a local user account associated with
    that email address.
    """
    requires_admin = False
    requires_login = False

    URL_GET_TOKEN = 'https://accounts.google.com/o/oauth2/token'
    URL_PLUS_API_PEOPLE_GET = 'https://www.googleapis.com/plus/v1/people/me'

    def create_user(self, email):
        """
        Create a new user account.

        :param email: Email address
        :return:
        """
        alias = None

        while True:
            alias = User.objects.make_random_password(16)

            try:
                User.objects.get(alias=alias)
            except User.DoesNotExist:
                break

        user = User.objects.create_user(email,
                                        type=UserType.google,
                                        alias=alias,
                                        is_active=True)

        user.add_message(self.request.META['REMOTE_ADDR'],
                         tag='signup',
                         type='google',
                         user_agent=self.request.META.get('HTTP_USER_AGENT'))

        # Send welcome Email
        context = {'user': user}
        msg = EmailMessage(_('Welcome to YDNS'),
                           tpl='accounts/welcome_google.mail',
                           context=context)
        msg.send(to=[user.email])

        return user

    def do_login(self, request, user):
        """
        Perform actual login.

        :param request: HttpRequest
        :param user: User
        """
        user.add_message(request.META['REMOTE_ADDR'],
                         tag='login',
                         type='google',
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        if user.otp_active:
            request.session['otp_uid'] = user.id
            request.session.modified = True
            return self.redirect('accounts:login_otp')
        else:
            LoginOtpView.login(request, user)
            return self.redirect('dashboard')

    def get(self, request, *args, **kwargs):
        """
        Verify the OAuth2 response from Google.

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        if not request.GET.get('state'):
            return self.response_error(request, _("Missing state property."), title=_("Google OAuth2 error"))
        elif not request.GET.get('code'):
            return self.response_error(request, _("Missing code property."), title=_("Google OAuth2 error"))

        state = request.GET['state']
        code = request.GET['code']

        if state != request.session.get('gapi_state'):
            return self.response_error(request, _("Invalid state"), title=_("Google OAuth2 error"))

        google.redirect_uri = absolute_url(request, 'accounts:google_sign_in')
        google.scope = ''  # need to reset scope to '', because otherwise we'll get trouble

        try:
            google.fetch_token(self.URL_GET_TOKEN,
                               code=code,
                               client_secret=settings.GAPI_CLIENT_SECRET)
        except Exception:
            return self.response_error(request,
                                       _("An error occurred while verifying Google's response. "
                                         "Please try again later"),
                                       _("Google OAuth2 error"))

        response = google.get(self.URL_PLUS_API_PEOPLE_GET)

        try:
            data = json.loads(response.content.decode('utf-8'))
        except ValueError:
            return self.response_error(request,
                                       _("Google's response has an invalid format."),
                                       _("Google OAuth2 error"))

        email_address = None

        if isinstance(data, dict) and data.get('emails'):
            for i in data['emails']:
                if i['type'] == 'account':
                    email_address = i['value']
                    break

        if not email_address:
            return self.response_error(request,
                                       _("No valid account-based email address found."),
                                       _("Google OAuth2 error"))

        # Now check if the account exists and login
        try:
            user = User.objects.get(email__iexact=email_address)
        except User.DoesNotExist:
            # TODO: Beta check
            try:
                BetaInvitation.objects.get(email__iexact=email_address)
            except BetaInvitation.DoesNotExist:
                return self.response_error(request,
                                           _("Your email address is not permitted to participate on the beta test."),
                                           _("Google OAuth2 error"))

            user = self.create_user(email_address)

        # Check if the user is banned
        ban = user.get_ban()

        if ban:
            return self.response_error(request,
                                       _("Your user account is banned: %s") % ban.reason,
                                       _("Google OAuth2 error"))

        if user.type == UserType.google:
            return self.do_login(request, user)
        else:
            return self.response_error(request,
                                       _("There is already an account with the same Email address, "
                                         "but with a different account type."),
                                       _("Login aborted"))

    def post(self, request, *args, **kwargs):
        """
        Request a OAuth2 login via Google.

        This has to be done through POST to ensure that no
        cross-site requests are happening (CSRF protection).

        :param request: HttpRequest
        :param args: tuple
        :param kwargs: dict
        :return: HttpResponse
        """
        google.redirect_uri = absolute_url(request, 'accounts:google_sign_in')
        google.scope = 'email'

        authorization_url, state = google.authorization_url(
            'https://accounts.google.com/o/oauth2/auth',
            access_type='offline',
            approval_prompt='force')

        request.session['gapi_state'] = state

        return self.redirect(authorization_url)

    def response_error(self, request, message, title):
        messages.error(request, message, title)
        return self.redirect('accounts:login')

class LoginOtpView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'accounts/login_otp.html'

    def get_context_data(self, **kwargs):
        context = super(LoginOtpView, self).get_context_data(**kwargs)

        if not self.request.session.get('otp_uid'):
            raise Http404

        context['next'] = self.request.GET.get('next', self.request.POST.get('next'))

        return context

    @staticmethod
    def login(request, user):
        if not hasattr(user, 'backend'):
            user.backend = settings.AUTHENTICATION_BACKENDS[0]

        login(request, user)

        if user.language and check_for_language(user.language):
            request.session[LANGUAGE_SESSION_KEY] = user.language
            request.session.modified = True

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            user = cleaned_data['user']
            LoginOtpView.login(request, user)
            return self.redirect(context['next'] or 'home')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        try:
            user = User.objects.get(id=request.session['otp_uid'])
        except:
            errors['code'] = _("Missing context")
        else:
            if not request.POST.get('code'):
                errors['code'] = _("Enter the code")
            else:
                try:
                    code = int(request.POST['code'])
                except Exception:
                    errors['code'] = _("The code must be a number")
                else:
                    try:
                        otp.verify_totp_token(code, user.otp_secret)
                    except otp.InvalidTokenError:
                        errors['code'] = _('Invalid code')
                    except otp.IncorrectTokenError:
                        errors['code'] = _('Incorrect code')
                    else:
                        cleaned_data['user'] = user

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class LoginView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'accounts/login.html'

    def do_login(self, request, user, next=None):
        if user.otp_active:
            request.session['otp_uid'] = user.id
            request.session.modified = True

            suffix = '?next={path}'.format(path=next) if next else None
            return self.redirect('accounts:login_otp', suffix=suffix)
        else:
            LoginOtpView.login(request, user)
            return self.redirect(next or 'dashboard')

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        context['next'] = self.request.GET.get('next', self.request.POST.get('next'))
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            return self.do_login(request, cleaned_data['user'], context['next'])
        else:
            if 'require_otp' in errors:
                self.template_name = 'accounts/login_otp.html'
            else:
                context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if request.POST.get('type') == 'otp':
            if not request.POST.get('code'):
                errors['code'] = _('Missing code')
            else:
                errors['code'] = "Unable to verify right now"
        else:
            if not request.POST.get('email'):
                errors['email'] = _('Field missing')
            else:
                try:
                    validate_email(request.POST['email'])
                except ValidationError:
                    errors['email'] = _('Invalid Email address')
                else:
                    cleaned_data['email'] = request.POST['email']

            if not request.POST.get('password'):
                errors['password'] = _('Field missing')
            else:
                cleaned_data['password'] = request.POST['password']

            if not errors:
                user = authenticate(email=cleaned_data['email'], password=cleaned_data['password'])

                if user is not None:
                    if not user.is_active:
                        errors['email'] = _('Account is not activated')
                    else:
                        ban = user.get_ban()

                        if ban:
                            errors['email'] = _('Your account is banned: %s') % ban.reason
                        else:
                            cleaned_data['user'] = user
                else:
                    errors['email'] = _('Invalid Email and/or password')

        if errors:
            cleaned_data = {}

        return errors, cleaned_data

class LogoutView(View):
    """
    Perform account logout.
    """
    requires_login = False
    requires_admin = False

    def get(self, request, *args, **kwargs):
        logout(request)
        return self.redirect('home')

class ResetPasswordView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'accounts/reset_password.html'

    def create_token(self, request, user):
        """
        Create password change request.

        :param request: HttpRequest
        :param user: User
        :return:
        """
        token = User.objects.make_random_password(64)
        rp = ResetPasswordRequest.objects.create(user=user, token=token)

        user.add_message(self.request.META['REMOTE_ADDR'],
                         tag='reset_password',
                         token=token,
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        # Send welcome Email
        suffix = '?u=' + user.alias + '&token=' + token
        activation_url = absolute_url(self.request, 'accounts:reset_password_update', suffix=suffix)
        context = {'user': user, 'token': token, 'activation_url': activation_url}
        msg = EmailMessage(_('Reset password'),
                           tpl='accounts/reset_password.mail',
                           context=context)
        msg.send(to=[user.email])

        messages.success(self.request,
                         _("We've sent instructions to your Email address on how to update your password.\n"
                                     "Please check your mail box in a few moments."),
                         _("Success"))

    def get_context_data(self, **kwargs):
        context = super(ResetPasswordView, self).get_context_data(**kwargs)
        context['recaptcha_html'] = captcha.get_html(settings.RECAPTCHA['public_key'])
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.create_token(request, cleaned_data['user'])
            return self.redirect('accounts:login')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('email'):
            errors['email'] = _('Field missing')
        else:
            try:
                validate_email(request.POST['email'])
            except ValidationError:
                errors['email'] = _('Invalid Email address')
            else:
                try:
                    user = User.objects.get(email__iexact=request.POST['email'])
                except User.DoesNotExist:
                    errors['email'] = _('This Email address is not known in our system')
                else:
                    ban = user.get_ban()

                    if ban or user.type != UserType.native:
                        errors['email'] = _("Password resets are not available for this account")
                    else:
                        delta = timezone.now() - relativedelta(hours=24)
                        qs = ResetPasswordRequest.objects.filter(user=user, date_created__gte=delta)

                        if qs.count() > 0:
                            errors['email'] = _("There is already a password reset request made within "
                                                "the last 24 hours.")
                        else:
                            cleaned_data['user'] = user

        # reCAPTCHA
        if not request.POST.get('recaptcha_challenge_field'):
            errors['recaptcha'] = _('Missing challenge field value')
        if not request.POST.get('recaptcha_response_field'):
            errors['recaptcha'] = _('Missing answer')

        if not errors:
            try:
                captcha.verify(request.POST['recaptcha_challenge_field'],
                               request.POST['recaptcha_response_field'],
                               settings.RECAPTCHA['private_key'],
                               request.META['REMOTE_ADDR'])
            except captcha.IncorrectRecaptchaSolution:
                errors['recaptcha'] = _('Incorrect captcha answer')
            except captcha.RecaptchaError:
                errors['recaptcha'] = _('reCAPTCHA error')

        if errors:
            cleaned_data = {}

        return errors, cleaned_data

class ResetPasswordUpdateView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'accounts/reset_password_update.html'

    def get_context_data(self, **kwargs):
        context = super(ResetPasswordUpdateView, self).get_context_data(**kwargs)

        if not self.request.GET.get('u'):
            return HttpResponseNotFound()
        if not self.request.GET.get('token'):
            return HttpResponseNotFound()

        delta = timezone.now() - relativedelta(hours=24)
        context['reset_password_request'] = get_object_or_404(ResetPasswordRequest,
                                                              user__alias=self.request.GET['u'],
                                                              token=self.request.GET['token'],
                                                              date_created__gte=delta)
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.update_password(request, context['reset_password_request'], cleaned_data['password'])
            return self.redirect('accounts:login')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def update_password(self, request, reset_password_request, password):
        """
        Update the user account password.

        :param request: HttpRequest
        :param reset_password_request: ResetPasswordRequest
        :param password: str
        :return:
        """
        user = reset_password_request.user
        user.set_password(password)
        user.save()

        user.add_message(request.META['REMOTE_ADDR'],
                         tag='update_password',
                         token=reset_password_request.token,
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        # Delete password reset request
        reset_password_request.delete()

        messages.success(request,
                         _("Your account password has been updated."),
                         _("Success"))

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('password'):
            errors['password'] = _('Field missing')
        elif len(request.POST['password']) < 6:
            errors['password'] = _("The password must contain at least 6 characters")
        if not request.POST.get('password_rpt'):
            errors['password_rpt'] = _('Field missing')

        if not errors and request.POST['password'] != request.POST['password_rpt']:
            for k in ('password', 'password_rpt'):
                errors[k] = _("The password don't match")

        if not errors:
            cleaned_data['password'] = request.POST['password']
        else:
            cleaned_data = {}

        return errors, cleaned_data

class SetLanguageView(View):
    requires_admin = False
    requires_login = False

    def get(self, request, *args, **kwargs):
        return self.set_language(request, kwargs['lc'])

    def set_language(self, request, lang_code):
        """
        Set the language.

        :param request: HttpRequest instance
        :param lang_code: str instance
        :return: HttpResponse
        """
        next = request.GET.get('next', request.POST.get('next'))

        if not is_safe_url(url=next, host=request.get_host()):
            next = request.META.get('HTTP_REFERER')

            if not is_safe_url(url=next, host=request.get_host()):
                next = reverse('home')

        response = HttpResponseRedirect(next)

        if lang_code and check_for_language(lang_code):
            if hasattr(request, 'session'):
                request.session[LANGUAGE_SESSION_KEY] = lang_code
            else:
                response.set_cookie(settings.LANGUAGE_COOKIE_NAME,
                                    lang_code,
                                    max_age=settings.LANGUAGE_COOKIE_AGE,
                                    path=settings.LANGUAGE_COOKIE_PATH,
                                    domain=settings.LANGUAGE_COOKIE_DOMAIN)

        return response

class SignupView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'accounts/signup.html'

    def create_account(self, cleaned_data):
        alias = None

        while True:
            alias = User.objects.make_random_password(16)

            try:
                User.objects.get(alias=alias)
            except User.DoesNotExist:
                break

        user = User.objects.create_user(cleaned_data['email'],
                                        cleaned_data['password'],
                                        alias=alias)

        user.add_message(self.request.META['REMOTE_ADDR'],
                         tag='signup',
                         type='native',
                         user_agent=self.request.META.get('HTTP_USER_AGENT'))

        # Create an activation request
        token = User.objects.make_random_password(64)
        acr = ActivationRequest.objects.create(user=user,
                                               token=token)

        # Send welcome Email
        suffix = '?u=' + user.alias + '&token=' + token
        activation_url = absolute_url(self.request, 'accounts:activate', suffix=suffix)
        context = {'user': user, 'token': token, 'activation_url': activation_url}
        msg = EmailMessage(_('Welcome to YDNS'),
                           tpl='accounts/welcome.mail',
                           context=context)
        msg.send(to=[user.email])

        messages.success(self.request,
                         mark_safe(_("We've sent activation instructions to your Email address.\n"
                                     "Please check your mail box in a few moments.")),
                         _("Sign up succeeded"))

    def get_context_data(self, **kwargs):
        context = super(SignupView, self).get_context_data(**kwargs)
        context['recaptcha_html'] = captcha.get_html(settings.RECAPTCHA['public_key'])
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if request.GET.get('from') == 'homepage':
            for k in ('password_rpt', 'recaptcha'):
                if k in errors:
                    del errors[k]

            context.update(errors=errors,
                           post=request.POST,
                           from_homepage=True)
            return self.render_to_response(context)

        if not errors:
            self.create_account(cleaned_data)
            return self.redirect('home')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('email'):
            errors['email'] = _('Field missing')
        else:
            try:
                validate_email(request.POST['email'])
            except ValidationError:
                errors['email'] = _('Invalid Email address')
            else:
                try:
                    User.objects.get(email__iexact=request.POST['email'])
                except User.DoesNotExist:
                    if is_blacklisted_email(request.POST['email'].strip()):
                        errors['email'] = _('This Email address cannot be used for registration')
                    else:
                        cleaned_data['email'] = request.POST['email']
                else:
                    errors['email'] = _('This Email address is already used')

                # TODO: Remove this after the beta is over
                if not errors:
                    try:
                        BetaInvitation.objects.get(email__iexact=request.POST['email'])
                    except BetaInvitation.DoesNotExist:
                        errors['email'] = _('Your email address is not permitted to participate on the beta program.')

        if not request.POST.get('password'):
            errors['password'] = _('Field missing')
        elif len(request.POST['password']) < 6:
            errors['password'] = _("The password must contain at least 6 characters")
        if not request.POST.get('password_rpt'):
            errors['password_rpt'] = _('Field missing')

        if not errors and request.POST['password'] != request.POST['password_rpt']:
            for k in ('password', 'password_rpt'):
                errors[k] = _("The password don't match")

        if not errors:
            cleaned_data['password'] = request.POST['password']

        # reCAPTCHA
        if not request.POST.get('recaptcha_challenge_field'):
            errors['recaptcha'] = _('Missing challenge field value')
        if not request.POST.get('recaptcha_response_field'):
            errors['recaptcha'] = _('Missing answer')

        if not errors:
            try:
                captcha.verify(request.POST['recaptcha_challenge_field'],
                               request.POST['recaptcha_response_field'],
                               settings.RECAPTCHA['private_key'],
                               request.META['REMOTE_ADDR'])
            except captcha.IncorrectRecaptchaSolution:
                errors['recaptcha'] = _('Incorrect captcha answer')
            except captcha.RecaptchaError:
                errors['recaptcha'] = _('reCAPTCHA error')

        if not request.POST.get('terms'):
            errors['terms'] = _("You must read and accept our Terms to sign up")

        if errors:
            cleaned_data = {}

        return errors, cleaned_data

class TwitterSignInView(View):
    """
    OAuth2 based login via Twitter.

    No idea why this does not work yet.
    """
    requires_admin = False
    requires_login = False

    def post(self, request, *args, **kwargs):
        messages.error(request,
                       _("Twitter sign in is currently not available"),
                       _("Login error"))
        return self.redirect('accounts:login')
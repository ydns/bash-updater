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

from accounts.models import User, BetaInvitation
from django.core.mail import send_mail
from django.core.validators import validate_email, ValidationError
from ydns.utils import messages
from cp.views import BaseView

class HomeView(BaseView):
    template_name = 'cp/beta/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        context['beta_invitations'] = BetaInvitation.objects.all()
        return context

class InviteView(BaseView):
    def post(self, request, *args, **kwargs):
        if not request.POST.get('email'):
            messages.error(request, 'No email address specified')
            return self.redirect('cp:beta:home')
        else:
            try:
                validate_email(request.POST['email'])
            except ValidationError:
                messages.error(request, 'Invalid email address')
                return self.redirect('cp:beta:home')
            else:
                try:
                    User.objects.get(email__iexact=request.POST['email'])
                except User.DoesNotExist:
                    try:
                        BetaInvitation.objects.get(email=request.POST['email'])
                    except BetaInvitation.DoesNotExist:
                        pass
                    else:
                        messages.error(request, 'That email address has been invited, but no account created yet.')
                        return self.redirect('cp:beta:home')
                else:
                    messages.error(request, 'That email address is already participating on the beta program.')
                    return self.redirect('cp:beta:home')

        # Create beta code
        bi = BetaInvitation.objects.create(email=request.POST['email'],
                                           code=User.objects.make_random_password(64),
                                           invited_by=request.user)

        subject = "YDNS Beta Program Invitation"
        message = """
Hi,

you have been invited to participate on the YDNS beta program.

Your email address "%s" has been permitted to register/login.

For regular sign ups (native accounts), you can sign up using your email address. If you'd like to login using Google, Facebook or GitHub, please make sure that your account's email address matches the email address above; otherwise, the OAuth login will be denied.

With best regards,
Your YDNS team""" % (bi.email,)

        send_mail(subject, message, None, [bi.email])

        messages.info(request, "Invitation sent to %s" % bi.email)

        return self.redirect('cp:beta:home')
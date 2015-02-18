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

from accounts.models import User
from django.core.mail import send_mail, get_connection
from django.core.validators import validate_email, ValidationError
from django.utils.translation import ugettext as _
from ydns.utils import messages
from ydns.views import TemplateView
from .utils import mail_footer

class BaseView(TemplateView):
    requires_admin = True
    requires_login = True

class BroadcastView(BaseView):
    """
    Create a new broadcast mail, which is sent to all YDNS user accounts.
    """
    template_name = 'cp/mail/broadcast.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            return self.send(cleaned_data)
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def send(self, cleaned_data):
        connection = get_connection()
        qs = User.objects.filter(is_active=True)

        for user in qs:
            send_mail(cleaned_data['subject'],
                      cleaned_data['message'] + mail_footer,
                      None,
                      [user.email],
                      connection=connection)

        messages.info(self.request, _("Broadcast sent successfully to %d recipients.") % qs.count())

        return self.redirect('cp:home')

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('subject'):
            errors['subject'] = _("Missing subject")
        else:
            cleaned_data['subject'] = request.POST['subject'].strip()

        if not request.POST.get('message'):
            errors['message'] = _("Missing message")
        else:
            cleaned_data['message'] = request.POST['message']

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class CreateView(BaseView):
    """
    Create a new mail, which is sent to one or more recipients.
    """
    template_name = 'cp/mail/create.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            return self.send(cleaned_data)
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def send(self, cleaned_data):
        send_mail(cleaned_data['subject'],
                  cleaned_data['message'] + mail_footer,
                  None,
                  [cleaned_data['email']])

        messages.info(self.request, _("Email sent successfully."))

        return self.redirect('cp:home')

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('recp'):
            errors['recp'] = _("Missing recipient")
        else:
            try:
                validate_email(request.POST['recp'])
            except ValidationError:
                errors['recp'] = _("Not a valid email address")
            else:
                try:
                    user = User.objects.get(email__iexact=request.POST['recp'])
                except User.DoesNotExist:
                    errors['recp'] = _("No such user account")
                else:
                    cleaned_data['email'] = user.email

        if not request.POST.get('subject'):
            errors['subject'] = _("Missing subject")
        else:
            cleaned_data['subject'] = request.POST['subject'].strip()

        if not request.POST.get('message'):
            errors['message'] = _("Missing message")
        else:
            cleaned_data['message'] = request.POST['message']

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data
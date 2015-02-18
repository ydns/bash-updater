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

from accounts.utils.i18n import TranslationContext
from django.shortcuts import get_object_or_404, Http404
from django.utils.translation import ugettext as _
from ydns.models import Domain, Host, HostRequest
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.views import TemplateView

class BaseDomainView(TemplateView):
    def get_context_data(self, **kwargs):
        context = super(BaseDomainView, self).get_context_data(**kwargs)
        context['domain'] = self.get_domain()
        context['is_manager'] = context['domain'].is_manager(self.request)
        return context

    def get_domain(self):
        domain = get_object_or_404(Domain, name=self.kwargs['name'])

        if domain.is_manager(self.request):
            return domain

        raise Http404

class ChoiceView(BaseDomainView):
    requires_admin = False
    requires_login = True

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        choice = kwargs['choice']
        full_name = context['hr'].name + '.' + context['hr'].domain.name
        decoded_name = full_name.encode('ascii').decode('idna')

        if choice == 'accept':
            try:
                Host.objects.get(name=full_name)
            except Host.DoesNotExist:
                host = Host.objects.create(user=context['hr'].user,
                                           name=full_name,
                                           domain=context['hr'].domain)
                host.add_message('host_request',
                                 user=context['hr'].user)
                host.add_message('host_created',
                                 user=context['hr'].user,
                                 ip=request.META['REMOTE_ADDR'],
                                 user_agent=request.META.get('HTTP_USER_AGENT'),
                                 choice_by=request.user.email)
                messages.success(request,
                                 _("The host <strong>%s</strong> was accepted and created.") % decoded_name)

                with TranslationContext(context['hr'].user):
                    msg = EmailMessage(_("Host request accepted (%s)") % decoded_name,
                                       'domains/mq/host_accepted.mail',
                                       {'name': decoded_name})
                    msg.send(to=[context['hr'].user.email])
            else:
                messages.error(request,
                               _("Cannot create host, because the name is already used."))

                with TranslationContext(context['hr'].user):
                    msg = EmailMessage(_("Host request failed (%s)") % decoded_name,
                                       'domains/mq/host_failed.mail',
                                       {'name': decoded_name})
                    msg.send(to=[context['hr'].user.email])
        else:
            with TranslationContext(context['hr'].user):
                msg = EmailMessage(_("Host request rejected (%s)") % decoded_name,
                                   'domains/mq/host_rejected.mail',
                                   {'name': decoded_name})
                msg.send(to=[context['hr'].user.email])

            messages.info(request,
                          _("The host <strong>%s</strong> was rejected.") % decoded_name)

        context['hr'].delete()  # delete the host request

        return self.redirect('domains:mq:home', args=(context['domain'].name,))

    def get_context_data(self, **kwargs):
        context = super(ChoiceView, self).get_context_data(**kwargs)
        context['hr'] = get_object_or_404(HostRequest,
                                          domain=context['domain'],
                                          name=self.kwargs['host'])
        return context

class HomeView(BaseDomainView):
    requires_admin = False
    requires_login = True
    template_name = 'domains/mq/home.html'

class MassChoiceView(BaseDomainView):
    requires_admin = False
    requires_login = True

    def make_choice(self, choice, hr):
        full_name = hr.name + '.' + hr.domain.name
        decoded_name = full_name.encode('ascii').decode('idna')

        if choice == 'accept':
            try:
                Host.objects.get(name=full_name)
            except Host.DoesNotExist:
                host = Host.objects.create(user=hr.user,
                                           name=full_name,
                                           domain=hr.domain)
                host.add_message('host_request',
                                 user=hr.user)
                host.add_message('host_created',
                                 user=hr.user,
                                 ip=self.request.META['REMOTE_ADDR'],
                                 user_agent=self.request.META.get('HTTP_USER_AGENT'),
                                 choice_by=self.request.user.email)
                messages.success(self.request,
                                 _("The host <strong>%s</strong> was accepted and created.") % decoded_name)

                with TranslationContext(hr.user):
                    msg = EmailMessage(_("Host request accepted (%s)") % decoded_name,
                                       'domains/mq/host_accepted.mail',
                                       {'name': decoded_name})
                    msg.send(to=[hr.user.email])
            else:
                messages.error(self.request,
                               _("Cannot create host, because the name is already used (%s).") % decoded_name)

                with TranslationContext(hr.user):
                    msg = EmailMessage(_("Host request failed (%s)") % decoded_name,
                                       'domains/mq/host_failed.mail',
                                       {'name': decoded_name})
                    msg.send(to=[hr.user.email])
        else:
            with TranslationContext(hr.user):
                msg = EmailMessage(_("Host request rejected (%s)") % decoded_name,
                                   'domains/mq/host_rejected.mail',
                                   {'name': decoded_name})
                msg.send(to=[hr.user.email])

            messages.info(self.request,
                          _("The host <strong>%s</strong> was rejected.") % decoded_name)

        hr.delete()  # delete the host request

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            hrl = cleaned_data.get('hrl') or []

            if hrl:
                for hr in hrl:
                    self.make_choice(cleaned_data['choice'], hr)

        return self.redirect('domains:mq:home', args=(context['domain'].name,))

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('choice'):
            errors['choice'] = _("No choice made")
        elif request.POST['choice'] not in ('accept', 'reject'):
            errors['choice'] = _("Invalid choice")
        else:
            cleaned_data['choice'] = request.POST['choice']

        hr = request.POST.getlist('hr')

        if not hr:
            errors['hr'] = _("No host request selected")
        else:
            hrl = []

            for i in hr:
                try:
                    x = HostRequest.objects.get(domain__name=self.kwargs['name'],
                                                name=i)
                except HostRequest.DoesNotExist:
                    pass
                else:
                    hrl.append(x)

            cleaned_data['hrl'] = hrl

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data
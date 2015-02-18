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
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _
from hosts import utils
from ydns.models import Domain, DomainAccessType, Host, HostRequest
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.utils.http import absolute_url
from ydns.views import TemplateView, View

class BaseView(TemplateView):
    requires_admin = False
    requires_login = True

    def get_context_data(self, **kwargs):
        context = super(BaseView, self).get_context_data(**kwargs)
        context['host'] = get_object_or_404(Host, user=self.request.user, name=self.kwargs['host'])
        return context

class ChangeStatusView(BaseView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        host = context['host']

        if kwargs['status'] == 'enable':
            if not host.is_active:
                host.is_active = True
                host.save()

                # Enable all underlying records as well
                for record in host.records.all():
                    record.disabled = False
                    record.save()

                host.add_message('enable_host',
                                 user=request.user,
                                 ip=request.META['REMOTE_ADDR'],
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

                messages.success(request,
                                 _("Host <strong>%s</strong> has been enabled.") % str(host))
        elif kwargs['status'] == 'disable':
            if host.is_active:
                host.is_active = False
                host.save()

                # Disable all underlying records as well
                for record in host.records.all():
                    record.disabled = True
                    record.save()

                host.add_message('disable_host',
                                 user=request.user,
                                 ip=request.META['REMOTE_ADDR'],
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

                messages.info(request,
                              _("Host <strong>%s</strong> has been disabled.") % str(host))

        return self.redirect('hosts:detail', args=(kwargs['host'],))

class ClearJournalView(BaseView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        host = context['host']

        # clear the journal entries
        host.journal.delete()

        host.add_message('journal_cleared',
                         user=request.user,
                         ip=request.META['REMOTE_ADDR'],
                         user_agent=request.META.get('HTTP_USER_AGENT'))

        messages.info(request,
                      _("The journal has been cleared."))

        return self.redirect('hosts:journal', args=(host.name,))

class CreateView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'hosts/create.html'

    def create_host(self, request, cleaned_data):
        """
        Create a host.

        Note: For moderated domains, we will create a host request instead of
        an actual host entry; The domain owner has to approve it first, before
        it's written to the host table.

        :param request: HttpRequest
        :param cleaned_data: dict
        :return:
        """
        if cleaned_data.get('moderation_required'):
            hr = HostRequest.objects.create(user=request.user,
                                            domain=cleaned_data['domain'],
                                            name=cleaned_data['name'])

            domain = cleaned_data['domain']

            if domain.owner and domain.owner.email:
                with TranslationContext(domain.owner):
                    accept_url = absolute_url(request, 'domains:mq:choice',
                                              args=(domain.name, cleaned_data['name'], 'accept'))
                    reject_url = absolute_url(request, 'domains:mq:choice',
                                              args=(domain.name, cleaned_data['name'], 'reject'))
                    msg = EmailMessage(_("Moderation request: %(name)s") % {'name': str(hr)},
                                       'hosts/moderation_request.mail',
                                       {'hr': hr, 'accept_url': accept_url, 'reject_url': reject_url})
                    msg.send(to=[domain.owner.email])

            messages.info(request,
                          _("Your host request requires moderation of the domain owner. "
                            "You'll get notified once your request is accepted or rejected."))
        else:
            name_idna = cleaned_data['name'] + '.' + cleaned_data['domain'].name
            host = Host.objects.create(user=request.user, name=name_idna, domain=cleaned_data['domain'])
            host.domain.add_message(request.META['REMOTE_ADDR'],
                                    user=request.user,
                                    tag='host_created',
                                    host_name=name_idna)
            host.add_message('host_created',
                             user=request.user,
                             ip=request.META['REMOTE_ADDR'],
                             user_agent=request.META.get('HTTP_USER_AGENT'))

            messages.success(request,
                             _("Your host was created successfully."))

    def get_context_data(self, **kwargs):
        context = super(CreateView, self).get_context_data(**kwargs)

        all_domains = Domain.objects.filter(is_active=True)
        domains = {'official': [], 'other': []}

        for domain in all_domains:
            if domain.access_type == DomainAccessType.private.value:
                if not domain.is_manager(self.request):
                    continue

            if domain.is_official:
                domains['official'].append(domain)
            else:
                domains['other'].append(domain)

        context['domains'] = domains

        if self.request.method == 'GET' and self.request.GET.get('domain'):
            if all_domains.filter(name=self.request.GET['domain']).count() > 0:
                context['current_domain'] = self.request.GET['domain']

        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.create_host(request, cleaned_data)
            return self.redirect('dashboard')  # TODO: redirect to hosts home
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('domain'):
            errors['domain'] = _("No domain chosen")
        else:
            try:
                domain = Domain.objects.get(name=request.POST['domain'])
            except Domain.DoesNotExist:
                errors['domain'] = _("No such domain")
            else:
                res = domain.can_create_hosts(request.user)

                if res is False:
                    errors['domain'] = _("You cannot create hosts with this domain")
                else:
                    cleaned_data['domain'] = domain
                    cleaned_data['moderation_required'] = res is None

            if not request.POST.get('name'):
                errors['name'] = _("Missing name")
            else:
                idna_name = request.POST['name'].encode('idna').decode('ascii').lower()
                idna_full = idna_name + '.' + cleaned_data['domain'].name
                idna_full_decoded = idna_full.encode('ascii').decode('idna')

                if not utils.is_valid_hostname(idna_name):
                    errors['name'] = _("Invalid host name")
                elif Host.is_blacklisted(idna_full):
                    errors['name'] = _("This host name is not available")
                else:
                    try:
                        Host.objects.get(name=idna_full)
                    except Host.DoesNotExist:
                        cleaned_data['name'] = idna_name
                    else:
                        errors['name'] = _("<strong>%(host)s</strong> is already taken") % {'host': idna_full_decoded}

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class DeleteView(BaseView):
    template_name = 'hosts/delete.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        host = context['host']
        host_name = str(host)
        domain = host.domain

        # delete the host
        host.delete()

        domain.add_message(request.META['REMOTE_ADDR'],
                           user=request.user,
                           tag='host_deleted',
                           host_name=self.kwargs['host'])

        messages.info(request,
                      _("Host <strong>%s</strong> was deleted.") % host_name)

        return self.redirect('hosts:home')

class DetailView(BaseView):
    template_name = 'hosts/detail.html'

class HomeView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'hosts/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        context['hosts'] = Host.objects.filter(user=self.request.user)

        style = 'cols'

        if self.request.GET.get('style') == 'list':
            style = 'list'

        context['style'] = style

        if style == 'cols':
            context['rows'] = self.get_rows(context['hosts'])

        return context

    def get_rows(self, hosts):
        cols_per_row = 4
        hostcount = hosts.count()
        n = round((hostcount / cols_per_row) + 0.5)
        rows = []

        for i in range(n):
            s0 = i * cols_per_row
            s1 = s0 + (cols_per_row - 1)

            slice = hosts[s0:s1]
            if slice:
                rows.append(slice)

        return rows

class JournalView(BaseView):
    template_name = 'hosts/journal.html'

class XhrCheckAvailabilityView(View):
    requires_admin = False
    requires_login = True

    def post(self, request, *args, **kwargs):
        errors, cleaned_data = self.validate(request)

        if not errors:
            name = cleaned_data['name'].encode('ascii').decode('idna')
            full_name = name + '.' + str(cleaned_data['domain'])
            message = _("<strong>%(full_name)s</strong> is available") % {'full_name': full_name}

            if cleaned_data.get('moderation_required'):
                message = _("<strong>%(full_name)s</strong> is available, but requires approval "
                            "by the domain owner") % {'full_name': full_name}

            result = {'message': message, 'success': True}

            return JsonResponse(result)
        else:
            message = '\n'.join(errors.values())
            return JsonResponse({'message': message, 'success': False})

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('domain'):
            errors['domain'] = _("No domain chosen")
        else:
            try:
                domain = Domain.objects.get(name=request.POST['domain'])
            except Domain.DoesNotExist:
                errors['domain'] = _("No such domain")
            else:
                res = domain.can_create_hosts(request.user)

                if res is True:
                    cleaned_data['domain'] = domain
                elif res is False:
                    errors['domain'] = _("You have no access to this domain")
                elif res is None:
                    cleaned_data['domain'] = domain
                    cleaned_data['moderation_required'] = True

        if not errors:
            if not request.POST.get('name'):
                errors['name'] = _("Missing name")
            else:
                idna_name = request.POST['name'].encode('idna').decode('ascii').lower()
                idna_full = idna_name + '.' + cleaned_data['domain'].name
                idna_full_decoded = idna_full.encode('ascii').decode('idna')

                if not utils.is_valid_hostname(idna_name):
                    errors['name'] = _("Invalid host name")
                elif Host.is_blacklisted(idna_full):
                    errors['name'] = _("<strong>%(host)s</strong> is not available") % {'host': idna_full_decoded}
                else:
                    try:
                        Host.objects.get(name=idna_full)
                    except Host.DoesNotExist:
                        cleaned_data['name'] = idna_name
                    else:
                        errors['name'] = _("<strong>%(host)s</strong> is already taken") % {'host': idna_full_decoded}

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data
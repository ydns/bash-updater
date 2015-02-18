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

from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _
from ydns.models import Domain, DomainAccessType
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.views import TemplateView

import dns.resolver

class BaseDomainView(TemplateView):
    requires_write = False

    def get_context_data(self, **kwargs):
        context = super(BaseDomainView, self).get_context_data(**kwargs)
        context['domain'] = self.get_domain()
        context['is_manager'] = context['domain'].is_manager(self.request)
        return context

    def get_domain(self):
        domain = get_object_or_404(Domain, name=self.kwargs['name'])

        if domain.access_type == DomainAccessType.public.value:
            return domain
        elif domain.access_type == DomainAccessType.private.value:
            if domain.is_manager(self.request):
                return domain
        elif domain.access_type == DomainAccessType.moderated.value:
            if self.requires_write and not domain.is_manager(self.request):
                pass
            else:
                return domain

        raise Http404

class CreateView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'domains/create.html'

    def create_domain(self, request, cleaned_data):
        domain = Domain(name=cleaned_data['name'],
                        owner=request.user,
                        public_owner=cleaned_data.get('public_owner') is True,
                        access_type=cleaned_data['type'])
        domain.save()

        domain.add_message(request.META['REMOTE_ADDR'],
                           request.user,
                           tag='create_domain',
                           name=domain.name,
                           domain_id=domain.id)

        request.user.add_message(request.META['REMOTE_ADDR'],
                                 tag='create_domain',
                                 name=domain.name)

        messages.success(request,
                         mark_safe(_("The domain <strong>%(name)s</strong> has been "
                                     "created successfully.") % {'name': domain.name}),
                         _("Domain created"))

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.create_domain(request, cleaned_data)
            return self.redirect('dashboard')
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('name'):
            errors['name'] = _("Enter domain name")
        else:
            name_idna = request.POST['name'].encode('idna').decode('ascii')  # use IDNA encoded name
            name_idna = name_idna.lower()

            if len(name_idna) > 255:
                errors['name'] = _("Name length exceeded")
            elif Domain.is_blacklisted(name_idna):
                errors['name'] = _("This domain is not available for use")

            if not errors:
                try:
                    Domain.objects.get(name=name_idna)
                except Domain.DoesNotExist:
                    pass
                else:
                    errors['name'] = _("This domain is already registered")

            # Check if the domain exists
            try:
                dns.resolver.query(name_idna, 'SOA')
            except dns.resolver.NXDOMAIN:
                errors['name'] = _("This domain does not exist")
            except dns.resolver.NoAnswer:
                errors['name'] = _("No SOA record returned")

            if not errors:
                cleaned_data['name'] = name_idna

        if not request.POST.get('type'):
            errors['type'] = _("No type chosen")
        else:
            try:
                access_type = DomainAccessType.from_string(request.POST['type'])
            except ValueError:
                errors['type'] = _("Invalid access type")
            else:
                cleaned_data['type'] = access_type

        if request.POST.get('public') == 'public':
            cleaned_data['public'] = True

        if request.POST.get('public_owner') == 'public_owner':
            cleaned_data['public_owner'] = True

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class DeleteView(BaseDomainView):
    requires_admin = False
    requires_login = True
    requires_write = True
    template_name = 'domains/delete.html'

    def delete_domain(self, request, domain):
        domain_name = str(domain)
        email = domain.owner.email if domain.owner else None

        domain.notify_all('delete')
        domain.delete()

        if email:
            msg = EmailMessage(_('Domain deleted'),
                               tpl='domains/delete_domain.mail',
                               context={'domain_name': domain_name})
            msg.send(to=[email])

        messages.info(request,
                      mark_safe(_("The domain <strong>%s</strong> including all hosts and records "
                                  "has been deleted.") % domain_name))

    def get_context_data(self, **kwargs):
        context = super(DeleteView, self).get_context_data(**kwargs)

        if not context['is_manager']:
            raise Http404

        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.delete_domain(request, context['domain'])
            return self.redirect('dashboard')
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

class DetailView(BaseDomainView):
    requires_admin = False
    requires_login = False
    requires_write = False
    template_name = 'domains/detail.html'

class HomeView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'domains/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        context['domains'] = Domain.objects.filter(qs_LOL)
        return context

class JournalView(BaseDomainView):
    requires_admin = False
    requires_login = True
    requires_write = True
    template_name = 'domains/journal.html'

class SettingsView(BaseDomainView):
    requires_admin = False
    requires_login = True
    requires_write = True
    template_name = 'domains/settings.html'

    def get_context_data(self, **kwargs):
        context = super(SettingsView, self).get_context_data(**kwargs)

        if not context['is_manager']:
            raise Http404

        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.save_changes(context['domain'], cleaned_data)
            return self.redirect('domains:detail', args=(context['domain'].name,))
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def save_changes(self, domain, cleaned_data):
        if cleaned_data.get('public_owner') is True:
            if not domain.public_owner:
                domain.public_owner = True
                domain.add_message(self.request.META['REMOTE_ADDR'],
                                   self.request.user,
                                   tag='public_owner_enabled')
        else:
            if domain.public_owner:
                domain.public_owner = False
                domain.add_message(self.request.META['REMOTE_ADDR'],
                                   self.request.user,
                                   tag='public_owner_disabled')

        if cleaned_data['type'] != domain.get_access_type():
            domain.access_type = cleaned_data['type'].value
            domain.add_message(self.request.META['REMOTE_ADDR'],
                               self.request.user,
                               tag='access_type_changed',
                               access_type=cleaned_data['type'].value)

        domain.save()

        messages.info(self.request,
                      _("The changes have been saved."))

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if request.POST.get('public_owner') == 'yes':
            cleaned_data['public_owner'] = True

        if not request.POST.get('type'):
            errors['type'] = _("No type chosen")
        else:
            try:
                access_type = DomainAccessType.from_string(request.POST['type'])
            except ValueError:
                errors['type'] = _("Invalid access type")
            else:
                cleaned_data['type'] = access_type

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data
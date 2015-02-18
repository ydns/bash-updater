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

from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _
from hosts.utils import is_valid_hostname
from netaddr import IPAddress, AddrFormatError, AddrConversionError
from ydns.models import Host
from ydns.utils import messages
from ydns.views import TemplateView
from .utils import supported_resource_types

import dns.resolver

class BaseView(TemplateView):
    """
    Base view for host-based views.

    This takes care that only hte owner of a particular host can access
    the resources for this host.
    """
    requires_admin = False
    requires_login = True

    def get_context_data(self, **kwargs):
        context = super(BaseView, self).get_context_data(**kwargs)
        context['host'] = get_object_or_404(Host, user=self.request.user, name=self.kwargs['host'])
        return context

class ChangeStatusView(BaseView):
    """
    Change the status of a record.

    This basically only changes the value of the "disabled" attribute of the
    underlying model.
    """
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        choice = self.kwargs['choice']
        record = context['record']
        host = context['host']

        if choice == 'enable':
            if record.disabled:
                record.disabled = False
                record.save()

                host.add_message('record_enabled',
                                 ip=request.META['REMOTE_ADDR'],
                                 user=request.user,
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

                messages.success(request,
                                 _("The record has been enabled."))
        else:
            if not record.disabled:
                record.disabled = True
                record.save()

                host.add_message('record_disabled',
                                 ip=request.META['REMOTE_ADDR'],
                                 user=request.user,
                                 user_agent=request.META.get('HTTP_USER_AGENT'))

                messages.info(request,
                              _("The record has been disabled."))

        return self.redirect('hosts:records:home', args=(host.name,))

    def get_context_data(self, **kwargs):
        context = super(ChangeStatusView, self).get_context_data(**kwargs)
        context['record'] = get_object_or_404(context['host'].records, id=int(self.kwargs['record_id']))
        return context

class CreateView(BaseView):
    template_name = 'hosts/records/create.html'

    def create_record(self, request, cleaned_data, host):
        more = {}

        if cleaned_data['type'] == 'MX':
            more['ttl'] = cleaned_data['ttl']
            more['prio'] = cleaned_data['prio']

        record = host.records.create(domain=host.domain,
                                     name=host.name,
                                     type=cleaned_data['type'],
                                     content=cleaned_data['content'],
                                     **more)
        host.add_message('record_created',
                         user=request.user,
                         ip=request.META['REMOTE_ADDR'],
                         user_agent=request.META.get('HTTP_USER_AGENT'),
                         rr_type=cleaned_data['type'])

        messages.success(request,
                         _("The record has been created."))

    def get_context_data(self, **kwargs):
        context = super(CreateView, self).get_context_data(**kwargs)
        context['supported_resource_types'] = supported_resource_types
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.create_record(request, cleaned_data, context['host'])
            return self.redirect('hosts:records:home', args=(context['host'].name,))
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        strict_validation = request.POST.get('strict') == 'strict'

        if not request.POST.get('type'):
            errors['type'] = _("No type chosen")
        else:
            rr_types = [x[0] for x in supported_resource_types]

            if request.POST['type'] not in rr_types:
                errors['type'] = _("Unsupported resource record type")
            else:
                cleaned_data['type'] = request.POST['type']

        if not request.POST.get('content'):
            errors['content'] = _("Missing content")

        if not errors:
            rr_type = cleaned_data['type']

            if rr_type == 'A':
                try:
                    ip = IPAddress(request.POST['content'])
                except (AddrFormatError, AddrConversionError):
                    errors['content'] = _("Not a valid IP address")
                else:
                    if ip.version != 4:
                        errors['content'] = _("Not an IPv4 address")
                    else:
                        cleaned_data['content'] = request.POST['content']
            elif rr_type == 'AAAA':
                try:
                    ip = IPAddress(request.POST['content'])
                except (AddrFormatError, AddrConversionError):
                    errors['content'] = _("Not a valid IP address")
                else:
                    if ip.version != 6:
                        errors['content'] = _("Not an IPv6 address")
                    else:
                        cleaned_data['content'] = request.POST['content']
            elif rr_type in ('CNAME', 'MX'):
                is_valid = True

                for i in request.POST['content'].split('.'):
                    try:
                        s = i.encode('idna').decode('ascii')
                    except Exception:
                        errors['content'] = _("Invalid value")
                    else:
                        if not is_valid_hostname(s):
                            is_valid = False
                            break

                if not is_valid:
                    errors['content'] = _("Invalid value - not a valid hostname")
                else:
                    if strict_validation:
                        try:
                            answers = dns.resolver.query(request.POST['content'], 'A')
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            try:
                                answers = dns.resolver.query(request.POST['content'], 'AAAA')
                            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                errors['content'] = _("Host <strong>%s</strong> does not "
                                                      "return a valid IP address") % request.POST['content']

                    if not errors:
                        cleaned_data['content'] = request.POST['content'].encode('idna').decode('ascii')

            if rr_type == 'MX':
                if not request.POST.get('ttl'):
                    errors['ttl'] = _("Missing TTL")
                else:
                    try:
                        n = int(request.POST['ttl'])
                    except (ValueError, TypeError):
                        errors['ttl'] = _("TTL must be a numeric value")
                    else:
                        if n < 0 and n > (2 ** 32):
                            errors['ttl'] = _("TTL out of range (must be between 0 and 2^32)")
                        else:
                            cleaned_data['ttl'] = n

                if not request.POST.get('prio'):
                    errors['prio'] = _("Missing Priority")
                else:
                    try:
                        n = int(request.POST['prio'])
                    except (ValueError, TypeError):
                        errors['prio'] = _("Priority must be a numeric value")
                    else:
                        if n < 1 and n > (2 ** 32):
                            errors['prio'] = _("Priority out of range (must be between 1 and 2^32)")
                        else:
                            cleaned_data['prio'] = n

        if cleaned_data.get('content') and len(cleaned_data['content']) > 65535:
            errors['content'] = _("Content is too long")

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class DeleteView(BaseView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        record = context['record']

        context['host'].add_message('record_deleted',
                                    ip=request.META['REMOTE_ADDR'],
                                    user=request.user,
                                    user_agent=request.META.get('HTTP_USER_AGENT'))

        # Delete record
        context['host'].records.filter(id=record.id).delete()

        messages.info(request,
                      _("The record has been deleted."))

        return self.redirect('hosts:records:home', args=(context['host'].name,))

    def get_context_data(self, **kwargs):
        context = super(DeleteView, self).get_context_data(**kwargs)
        context['record'] = get_object_or_404(context['host'].records, id=int(self.kwargs['record_id']))
        return context

class EditView(BaseView):
    template_name = 'hosts/records/edit.html'

    def get_context_data(self, **kwargs):
        context = super(EditView, self).get_context_data(**kwargs)
        context['record'] = get_object_or_404(context['host'].records, id=int(self.kwargs['record_id']))
        return context

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request, context['record'])

        if not errors:
            self.update_record(context['record'], cleaned_data, context['host'])
            return self.redirect('hosts:records:home', args=(context['host'].name,))
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def update_record(self, record, cleaned_data, host):
        changes = 0

        if record.type == 'MX':
            if cleaned_data['ttl'] != record.ttl:
                record.ttl = cleaned_data['ttl']
                changes += 1
            if cleaned_data['prio'] != record.prio:
                record.prio = cleaned_data['prio']
                changes += 1

        if cleaned_data['content'] != record.content:
            record.content = cleaned_data['content']
            changes += 1

        if changes > 0:
            record.save()
            host.add_message('record_updated',
                             user=self.request.user,
                             ip=self.request.META['REMOTE_ADDR'],
                             user_agent=self.request.META.get('HTTP_USER_AGENT'),
                             rr_type=record.type)

        messages.info(self.request,
                      _("The record has been updated."))

    def validate(self, request, record):
        errors = {}
        cleaned_data = {}

        strict_validation = request.POST.get('strict') == 'strict'

        if not request.POST.get('content'):
            errors['content'] = _("Missing content")

        if not errors:
            rr_type = record.type

            if rr_type == 'A':
                try:
                    ip = IPAddress(request.POST['content'])
                except (AddrFormatError, AddrConversionError):
                    errors['content'] = _("Not a valid IP address")
                else:
                    if ip.version != 4:
                        errors['content'] = _("Not an IPv4 address")
                    else:
                        cleaned_data['content'] = request.POST['content']
            elif rr_type == 'AAAA':
                try:
                    ip = IPAddress(request.POST['content'])
                except (AddrFormatError, AddrConversionError):
                    errors['content'] = _("Not a valid IP address")
                else:
                    if ip.version != 6:
                        errors['content'] = _("Not an IPv6 address")
                    else:
                        cleaned_data['content'] = request.POST['content']
            elif rr_type in ('CNAME', 'MX'):
                is_valid = True

                for i in request.POST['content'].split('.'):
                    try:
                        s = i.encode('idna').decode('ascii')
                    except Exception:
                        errors['content'] = _("Invalid value")
                    else:
                        if not is_valid_hostname(s):
                            is_valid = False
                            break

                if not is_valid:
                    errors['content'] = _("Invalid value - not a valid hostname")
                else:
                    if strict_validation:
                        try:
                            answers = dns.resolver.query(request.POST['content'], 'A')
                        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                            try:
                                answers = dns.resolver.query(request.POST['content'], 'AAAA')
                            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                                errors['content'] = _("Host <strong>%s</strong> does not "
                                                      "return a valid IP address") % request.POST['content']

                    if not errors:
                        cleaned_data['content'] = request.POST['content'].encode('idna').decode('ascii')

            if rr_type == 'MX':
                if not request.POST.get('ttl'):
                    errors['ttl'] = _("Missing TTL")
                else:
                    try:
                        n = int(request.POST['ttl'])
                    except (ValueError, TypeError):
                        errors['ttl'] = _("TTL must be a numeric value")
                    else:
                        if n < 0 and n > (2 ** 32):
                            errors['ttl'] = _("TTL out of range (must be between 0 and 2^32)")
                        else:
                            cleaned_data['ttl'] = n

                if not request.POST.get('prio'):
                    errors['prio'] = _("Missing Priority")
                else:
                    try:
                        n = int(request.POST['prio'])
                    except (ValueError, TypeError):
                        errors['prio'] = _("Priority must be a numeric value")
                    else:
                        if n < 1 and n > (2 ** 32):
                            errors['prio'] = _("Priority out of range (must be between 1 and 2^32)")
                        else:
                            cleaned_data['prio'] = n

        if cleaned_data.get('content') and len(cleaned_data['content']) > 65535:
            errors['content'] = _("Content is too long")

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class HomeView(BaseView):
    template_name = 'hosts/records/home.html'
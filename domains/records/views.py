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

from domains.models import Domain
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from ydns.utils.navbar import NavBarDivider, NavBarHeader, NavBarItem
from ydns.utils.pagination import Pagination
from ydns.views import FormView, TemplateView
from . import forms
from .enum import RecordType


class _DomainView(TemplateView):
    require_login = True
    require_admin = False
    require_domain_perms = ''

    def dispatch(self, request, *args, **kwargs):
        if self.require_domain_perms:
            context = self.get_context_data(**kwargs)
            s = context['domain_permissions']

            for c in self.require_domain_perms:
                if c not in s:
                    return self.redirect_insufficient_privileges(request)

        return super(_DomainView, self).dispatch(request, *args, **kwargs)

    @property
    def domain(self):
        if not hasattr(self, '_domain'):
            self._domain = self.get_context_data(**self.kwargs)['domain']
        return self._domain

    def get_context_data(self, **kwargs):
        context = super(_DomainView, self).get_context_data(**kwargs)
        context['domain'] = get_object_or_404(Domain, name=self.kwargs['name'])
        context['domain_permissions'] = context['domain'].get_permissions(self.request.user)
        return context

    def get_navbar_context(self):
        """
        Contextual navbar context.

        :param request: HttpRequest
        :return:
        """
        context = self.get_context_data(**self.kwargs)
        perms = context['domain_permissions']
        entries = [
            NavBarItem('Overview', reverse('domains:detail', args=(self.domain.name,)))
        ]

        if 'w' in perms or 'a' in perms:
            entries.append(NavBarItem('Records', reverse('domains:records:home', args=(self.domain.name,))))

        context = (
            NavBarItem(str(self.domain), id='domain-ctx', children=entries),
        )

        return context


class _RecordView(_DomainView):
    require_record_perms = ''

    def dispatch(self, request, *args, **kwargs):
        if self.require_record_perms:
            context = self.get_context_data(**kwargs)
            s = context['record_permissions']

            for c in self.require_record_perms:
                if c not in s:
                    return self.redirect_insufficient_privileges(request)

        return super(_RecordView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(_RecordView, self).get_context_data(**kwargs)
        context['record'] = get_object_or_404(context['domain'].records, id=int(self.kwargs['record_id']))
        context['record_permissions'] = context['record'].get_permissions(self.request.user)
        return context

    def get_navbar_context(self):
        """
        Contextual navbar context.

        :param request: HttpRequest
        :return:
        """
        context = self.get_context_data(**self.kwargs)
        d_perms = context['domain_permissions']
        r_perms = context['record_permissions']
        entries = [
            NavBarItem('Overview', reverse('domains:detail', args=(self.domain.name,)))
        ]

        if 'w' in d_perms or 'a' in d_perms:
            entries.append(NavBarItem('Records', reverse('domains:records:home', args=(self.domain.name,))))

        entries.append(NavBarDivider())
        entries.append(NavBarHeader('Record {!s}'.format(self.record)))

        if 'w' in r_perms and self.record.is_editable:
            entries.append(NavBarItem('Edit Record', reverse('domains:records:edit', args=(self.domain.name,
                                                                                           self.record.padded_id))))
        if 'w' in r_perms and self.record.is_editable:
            entries.append(NavBarItem('Delete Record', reverse('domains:records:delete', args=(self.domain.name,
                                                                                               self.record.padded_id))))

        context = (
            NavBarItem(str(self.domain), id='domain-ctx', children=entries),
        )

        return context

    @property
    def record(self):
        if not hasattr(self, '_record'):
            self._record = self.get_context_data(**self.kwargs)['record']
        return self._record


class CreateView(_DomainView, FormView):
    """
    Create a new record for a domain.
    """
    form_class = forms.CreateForm
    require_domain_perms = 'rw'
    template_name = 'domains/records/create.html'

    def form_valid(self, form):
        domain = self.domain
        name = form.cleaned_data['name']

        # if name does not end with domain name, append it
        s = '.{!s}'.format(domain)
        if name != str(domain) and not name.endswith(s):
            name += s

        # IDNA
        name = name.encode('idna').decode('ascii')

        # create record
        record = domain.records.create(domain=domain,
                                       name=name,
                                       type=form.cleaned_data['type'],
                                       content=form.cleaned_data['content'],
                                       ttl=form.cleaned_data.get('ttl') or None,
                                       prio=form.cleaned_data.get('prio') or None,
                                       owner=self.request.user)
        messages.success(self.request, 'Record "{!s}" created.'.format(record))
        return self.redirect('domains:records:home', args=(domain.name,))

    def get_form_kwargs(self):
        kwargs = super(CreateView, self).get_form_kwargs()
        kwargs['type_choices'] = [(str(x), str(x)) for x in RecordType if x.is_usable]
        return kwargs


class DeleteView(_RecordView):
    require_record_perms = 'rw'

    def get(self, request, *args, **kwargs):
        domain = self.domain

        if not self.record.is_deletable:
            messages.error(request, 'The record cannot be deleted.')
            return self.redirect('domains:records:detail', args=(self.domain.name, self.record.padded_id))
        else:
            self.record.delete()
            messages.info(request, 'Record deleted.')
            return self.redirect('domains:records:home', args=(domain.name,))


class DetailView(_RecordView):
    require_record_perms = 'r'
    template_name = 'domains/records/detail.html'


class EditView(_RecordView, FormView):
    form_class = forms.EditForm
    require_record_perms = 'rw'
    template_name = 'domains/records/edit.html'

    def form_valid(self, form):
        domain = self.domain
        record = self.record
        name = form.cleaned_data['name']

        # if name does not end with domain name, append it
        s = '.{!s}'.format(domain)
        if name != str(domain) and not name.endswith(s):
            name += s

        # IDNA
        name = name.encode('idna').decode('ascii')

        # apply changes
        changes = {}

        if record.name != name:
            changes['name'] = (record.name, name)
            record.name = name
        if record.type != form.cleaned_data['type']:
            changes['type'] = (str(record.type), str(form.cleaned_data['type']))
            record.type = form.cleaned_data['type']
        if record.content != form.cleaned_data['content']:
            changes['content'] = (record.content, form.cleaned_data['content'])
            record.content = form.cleaned_data['content']
        if record.ttl != form.cleaned_data.get('ttl') or None:
            changes['ttl'] = (record.ttl, form.cleaned_data.get('ttl') or None)
            record.ttl = form.cleaned_data.get('ttl') or None
        if record.prio != form.cleaned_data.get('prio') or None:
            changes['prio'] = (record.prio, form.cleaned_data.get('prio') or None)
            record.prio = form.cleaned_data.get('prio') or None

        if changes:
            record.date_modified = timezone.now()
            record.save()

            # Add update record
            user_agent = self.request.META.get('HTTP_USER_AGENT') or None
            record.updates.create(record=record, changes=changes, user_agent=user_agent)

            messages.success(self.request, 'Record "{!s}" updated.'.format(record))
        else:
            messages.info(self.request, 'No changes made.')

        return self.redirect('domains:records:detail', args=(domain.name, record.padded_id))

    def get_form_kwargs(self):
        kwargs = super(EditView, self).get_form_kwargs()
        kwargs['type_choices'] = [(str(x), str(x)) for x in RecordType if x.is_usable]
        return kwargs

    def get_initial(self):
        initial = super(EditView, self).get_initial()
        initial['name'] = str(self.record)
        initial['type'] = str(self.record.type)
        initial['content'] = self.record.content

        if self.record.ttl:
            initial['ttl'] = self.record.ttl
        if self.record.prio:
            initial['prio'] = self.record.prio

        return initial


class HomeView(_DomainView):
    require_domain_perms = 'r'
    template_name = 'domains/records/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        domain = context['domain']
        objects = domain.records.all()
        context['pagination'] = Pagination(objects,
                                           25,
                                           reverse('domains:records:home', args=(domain.name,)),
                                           self.request.GET.get('p'))
        return context
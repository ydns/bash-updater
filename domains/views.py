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

from django.contrib import messages
from django.shortcuts import get_object_or_404
from ydns.views import FormView, TemplateView
from .enum import DomainAccessType, DomainStatus, DomainType
from .models import Domain
from . import forms


class _BaseView(TemplateView):
    require_login = True
    require_admin = False


class _DomainView(_BaseView):
    def get_context_data(self, **kwargs):
        context = super(_DomainView, self).get_context_data(**kwargs)
        context['domain'] = get_object_or_404(Domain, name=self.kwargs['name'])
        return context


class CreateView(_BaseView, FormView):
    form_class = forms.CreateForm
    template_name = 'domains/create.html'

    def form_valid(self, form):
        try:
            Domain.objects.get(name=form.cleaned_data['name'])
        except Domain.DoesNotExist:
            pass
        else:
            form.add_error('name', 'That domain name is already in our system')
            return self.form_invalid(form)

        domain = Domain.objects.create(name=form.cleaned_data['name'],
                                       type=DomainType.NATIVE,
                                       owner=self.request.user,
                                       access_type=form.cleaned_data['access_type'],
                                       public_owner=form.cleaned_data['public_owner'],
                                       status=DomainStatus.OK)
        messages.success(self.request, 'Domain "%s" added.' % domain)
        return self.redirect('dashboard')

    @staticmethod
    def get_access_type_choices():
        return [(str(x), str(x)) for x in DomainAccessType]

    def get_form_kwargs(self):
        kwargs = super(CreateView, self).get_form_kwargs()
        kwargs['access_type_choices'] = self.get_access_type_choices()
        return kwargs


class DetailView(_DomainView):
    template_name = 'domains/detail.html'
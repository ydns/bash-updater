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

from django.shortcuts import get_object_or_404, Http404
from ydns.models import Domain, DomainAccessType
from ydns.views import TemplateView

class BaseDomainView(TemplateView):
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
            if domain.is_manager(self.request):
                return domain

        raise Http404

class HomeView(BaseDomainView):
    requires_admin = False
    requires_login = True
    template_name = 'domains/hosts/home.html'
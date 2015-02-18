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

from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _
from django.views import generic
from ydns.utils import messages
from ydns.utils.http import absolute_url
from .models import Domain, DomainLogMessage, Host

class PermissionMixin(object):
    requires_login = True
    requires_admin = True

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated():
            if self.requires_login or self.requires_admin:
                return self.redirect_login(request)
        else:
            if self.requires_admin and not request.user.is_admin:
                return self.redirect_login(request)

        return super(PermissionMixin, self).dispatch(request, *args, **kwargs)

    def redirect(self, url, suffix=None, *args, **kwargs):
        if not url.startswith('/') and not url.startswith('http'):
            url = reverse(url, *args, **kwargs)
        if suffix:
            url += suffix
        return HttpResponseRedirect(url)

    def redirect_login(self, request):
        messages.info(request, _("Insufficient privileges"))
        return self.redirect('accounts:login', suffix='?next={path}'.format(path=request.path))

class View(PermissionMixin, generic.View):
    pass

class TemplateView(PermissionMixin, generic.TemplateView):
    pass

class BlogView(View):
    requires_login = False
    requires_admin = False

    def get(self, request, *args, **kwargs):
        return self.redirect('http://blog.ydns.eu')

class DashboardView(TemplateView):
    requires_admin = False
    requires_login = True
    template_name = 'dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['recent_activity'] = self.get_recent_activity()
        context['hosts'] = Host.objects.filter(user=self.request.user)
        context['domains'] = Domain.objects.filter(owner=self.request.user)
        return context

    def get_recent_activity(self):
        from .models import HostLogMessage
        recent_messages = []

        for i in HostLogMessage.objects.filter(host__user=self.request.user):
            message = '<a href="%s">%s</a> &mdash; %s' % (absolute_url(self.request,
                                                                'hosts:detail',
                                                                args=(i.host.name,)),
                                                   str(i.host),
                                                   i.message)
            recent_messages.append({'date_created': i.date_created,
                                    'message': mark_safe(message)})

        for i in DomainLogMessage.objects.filter(domain__owner=self.request.user):
            message = '<a href="%s">%s</a> &mdash; %s' % (absolute_url(self.request,
                                                                'domains:detail',
                                                                args=(i.domain.name,)),
                                                   str(i.domain),
                                                   i.message)
            recent_messages.append({'date_created': i.date_created,
                                    'message': mark_safe(message)})

        recent_messages = list(sorted(recent_messages, key=lambda x: x['date_created'], reverse=True))

        return recent_messages[:10]

class DonateView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'donate.html'

class HomeView(TemplateView):
    requires_login = False
    requires_admin = False
    template_name = 'home.html'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            return self.redirect('dashboard')
        return super(HomeView, self).get(request, *args, **kwargs)

class ImprintView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'imprint.html'

class TermsView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'terms.html'
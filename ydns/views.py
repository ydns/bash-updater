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
from django.views import generic
from ydns.utils import messages
from ydns.utils.http import absolute_url
from .models import Domain, DomainLogMessage, Host


class _BaseMixin(generic.View):
    """
    Base mixin for class-based views (CBV).

    This takes care of required attributes, such as login and/or admin privileges.
    For security reasons, by default this class will require both admin and login
    status.
    """
    require_login = True
    require_admin = True

    def dispatch(self, request, *args, **kwargs):
        """
        Request dispatch method.

        This method is invoked when HTTP request for a view is received,
        regardless which method has been used.

        :param request: HttpRequest
        :param args: Arguments
        :param kwargs: Keyword arguments
        :return: HttpResponse
        """
        if not request.user.is_authenticated():
            if self.require_login or self.require_admin:
                return self.redirect_insufficient_privileges(request)
        elif self.require_admin and not request.user.is_admin:
            return self.redirect_insufficient_privileges(request)

        return super(_BaseMixin, self).dispatch(request, *args, **kwargs)

    @staticmethod
    def redirect(url, suffix=None, *args, **kwargs):
        """
        Redirection response.

        :param url: URL
        :param suffix: URL suffix (optional)
        :param args: Arguments to be passed to url resolver
        :param kwargs: Keyword arguments to be passed to url resolver
        :return: HttpResponseRedirect
        """
        if not url.startswith('/') and not url.startswith('http://') and not url.startswith('https://'):
            url = reverse(url, *args, **kwargs)
        if suffix:
            url += suffix
        return HttpResponseRedirect(url)

    @classmethod
    def redirect_insufficient_privileges(cls, request):
        """
        Redirect to login site and display an alert message.

        :param request: HttpRequest
        :return: HttpResponseRedirect
        """
        messages.error(request, 'You have insufficient privileges to access this page.')
        return cls.redirect('login', suffix='?next={}'.format(request.path))


class View(_BaseMixin):
    pass


class FormView(_BaseMixin, generic.FormView):
    pass


class TemplateView(_BaseMixin, generic.TemplateView):
    pass


class DashboardView(TemplateView):
    require_admin = False
    require_login = True
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
    require_admin = False
    require_login = False
    template_name = 'donate.html'


class HomeView(TemplateView):
    require_login = False
    require_admin = False
    template_name = 'home.html'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            return self.redirect('dashboard')
        return super(HomeView, self).get(request, *args, **kwargs)


class GetStartedView(TemplateView):
    require_admin = False
    require_login = False
    template_name = 'get_started.html'


class ImprintView(TemplateView):
    require_admin = False
    require_login = False
    template_name = 'imprint.html'


class TermsView(TemplateView):
    require_admin = False
    require_login = False
    template_name = 'terms.html'
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
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.views import generic
from domains.models import Domain


class _BaseMixin(object):
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
        elif self.require_admin and not request.user.admin:
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


class View(_BaseMixin, generic.View):
    pass


class TemplateView(_BaseMixin, generic.TemplateView):
    pass


class FormView(TemplateView):
    """
    A form view modeled after Django's very own one.
    """
    initial = {}
    form_class = None

    def form_invalid(self, form):
        return self.render_to_response(self.get_context_data(form=form))

    def form_valid(self, form):
        raise NotImplementedError()

    def get(self, request, *args, **kwargs):
        form = self.get_form()
        return self.render_to_response(self.get_context_data(form=form))

    def get_initial(self):
        return self.initial.copy()

    def get_form_class(self):
        return self.form_class

    def get_form(self, form_class=None):
        if form_class is None:
            form_class = self.get_form_class()
        return form_class(**self.get_form_kwargs())

    def get_form_kwargs(self):
        kwargs = {'initial': self.get_initial()}

        if self.request.method in ('POST', 'PUT'):
            kwargs.update(data=self.request.POST, files=self.request.FILES)

        return kwargs

    def post(self, request, *args, **kwargs):
        form = self.get_form()

        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

    def put(self, request, *args, **kwargs):
        return self.post(request, *args, **kwargs)


class _AnonymousView(TemplateView):
    require_admin = False
    require_login = False


class DashboardView(TemplateView):
    require_admin = False
    require_login = True
    template_name = 'dashboard.html'

    def get_context_data(self, **kwargs):
        context = super(DashboardView, self).get_context_data(**kwargs)
        context['domains'] = self.get_domains(self.request.user)
        return context

    @staticmethod
    def get_domains(user):
        """
        Get domains a specific user has access to.

        :param user: User instance
        :return:
        """
        domains = set()

        for domain in Domain.objects.all():
            if domain.owner == user:
                domains.add(domain)
            else:
                # TODO: Look if the user has any records in this domain
                # TODO: Look if the user has any pending host requests
                pass

        return domains


class DonateView(_AnonymousView):
    template_name = 'donate.html'


class HomeView(_AnonymousView):
    template_name = 'home.html'

    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            return self.redirect('dashboard')
        return super(HomeView, self).get(request, *args, **kwargs)


class GetStartedView(_AnonymousView):
    template_name = 'get_started.html'


class ImprintView(_AnonymousView):
    template_name = 'imprint.html'


class TermsView(_AnonymousView):
    template_name = 'terms.html'
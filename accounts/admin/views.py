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

from accounts.models import User
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.shortcuts import get_object_or_404
from ydns.utils.pagination import Pagination
from ydns.views import TemplateView


class _BaseView(TemplateView):
    require_admin = True
    require_login = True


class _UserView(_BaseView):
    def get_context_data(self, **kwargs):
        context = super(_UserView, self).get_context_data(**kwargs)
        context['current_user'] = get_object_or_404(User, id=int(self.kwargs['uid']))
        return context


class DeleteView(_UserView):
    template_name = 'accounts/admin/delete.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        user = context.pop('current_user')
        user.delete()

        messages.info(request, 'User deleted.')
        return self.redirect('accounts:admin:home')


class DetailView(_UserView):
    template_name = 'accounts/admin/detail.html'


class HomeView(_BaseView):
    template_name = 'accounts/admin/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        objects = User.objects.all()
        context['pagination'] = Pagination(objects,
                                           50,
                                           reverse('accounts:admin:home'),
                                           self.request.GET.get('p'))
        return context


class LockView(_UserView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        user = context.pop('current_user')

        if user.active:
            user.active = False
            user.save()
            user.add_to_log('Account locked')
            messages.info(request, 'User account %s has been locked.' % user)
        else:
            messages.error(request, 'Cannot lock user account %s, because it is already inactive.' % user)

        return self.redirect('accounts:admin:detail', args=(user.id,))


class UnlockView(_UserView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        user = context.pop('current_user')

        if not user.active:
            user.active = True
            user.save()
            user.add_to_log('Account unlocked')
            messages.info(request, 'User account %s has been unlocked.' % user)
        else:
            messages.error(request, 'Cannot unlock user account %s, because it is not locked.' % user)

        return self.redirect('accounts:admin:detail', args=(user.id,))
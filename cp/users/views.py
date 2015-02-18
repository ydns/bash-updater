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

from accounts.models import User, UserBan, UserType
from accounts.utils.i18n import TranslationContext
from django.contrib.sessions.models import Session
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponseNotFound
from django.shortcuts import get_object_or_404
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _
from ydns.utils import messages
from ydns.utils.mail import EmailMessage
from ydns.views import TemplateView

class BaseView(TemplateView):
    requires_admin = True
    requires_login = True

    def get_context_data(self, **kwargs):
        context = super(BaseView, self).get_context_data(**kwargs)
        context['users'] = User.objects.all()
        return context

class BaseUidView(BaseView):
    def get_context_data(self, **kwargs):
        context = super(BaseUidView, self).get_context_data(**kwargs)
        context['u'] = get_object_or_404(User, id=int(self.kwargs['user_id']))
        return context

class BanView(BaseUidView):
    template_name = 'cp/users/ban.html'

    def ban(self, request, user, reason):
        """
        Ban a user account.
        :param request: HttpRequst
        :param user: User to be banned
        :param reason: Ban reason
        :return: HttpResponse
        """
        ban = UserBan.objects.create(user=user,
                                     banned_by=request.user,
                                     reason=reason)

        with TranslationContext(user):
            msg = EmailMessage(_('Account banned'),
                               tpl='cp/users/banned.mail',
                               context={'reason': reason})
            msg.send(to=[user.email])

        user.is_active = False
        user.save()

        user.add_message(tag='account_banned',
                         reason=reason)

        # Kick of existing sessions with that user account
        for session in Session.objects.all():
            data = session.get_decoded()

            if data.get('_auth_user_id', None) == user.pk:
                session.delete()

        messages.info(request,
                      _("Account <strong>%s</strong> has been banned.") % user.email)

        return self.redirect('cp:users:detail', args=(user.id,))

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)

        if context['u'].get_ban():
            messages.error(request,
                           _("That user account is already banned."))
            self.redirect('cp:users:detail', args=(context['u'].id,))

        return super(BanView, self).get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if context['u'].get_ban():
            messages.error(request,
                           _("That user account is already banned."))
            self.redirect('cp:users:detail', args=(context['u'].id,))

        if not errors:
            return self.ban(request, context['u'], cleaned_data['reason'])
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('reason'):
            errors['reason'] = _("No reason specified")
        else:
            cleaned_data['reason'] = request.POST['reason'].strip()

        if errors:
           cleaned_data.clear()

        return errors, cleaned_data

class DeleteView(BaseUidView):
    template_name = 'cp/users/delete.html'

    def delete_account(self, request, user, cleaned_data):
        email = user.email
        msg = None

        if cleaned_data['notify']:
            with TranslationContext(user):
                msg = EmailMessage(_('Account deletion'),
                                   tpl='cp/users/delete.mail')

        user.delete()

        if msg:
            msg.send(to=[email])

        messages.info(request,
                      mark_safe(_("The account <strong>%s</strong> has been deleted.") % email))

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            self.delete_account(request, context['u'], cleaned_data)
            return self.redirect('home')
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

        cleaned_data['notify'] = request.POST.get('notify') == 'yes'

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class DetailView(BaseUidView):
    template_name = 'cp/users/detail.html'

class DomainsView(BaseUidView):
    template_name = 'cp/users/domains.html'

class HomeView(BaseView):
    template_name = 'cp/users/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        context['account_types'] = [(x.value, x.to_str()) for x in UserType]
        context['results_per_page'] = (10, 25, 50, 100, 250, 500)
        context['filter'] = self.get_filter()
        return context

    def get_filter(self):
        fs = {'query': '',
              'type': '',
              'rpp': '25'}

        for k in fs:
            if self.request.GET.get(k):
                val = self.request.GET[k]

                if k == 'query':
                    fs[k] = val
                elif k == 'type':
                    try:
                        i = UserType(int(val))
                    except:
                        pass
                    else:
                        fs[k] = i.value
                elif k == 'rpp':
                    try:
                        i = int(val)
                    except:
                        pass
                    else:
                        fs[k] = i

        return fs

class HostsView(BaseUidView):
    template_name = 'cp/users/hosts.html'

class JournalView(BaseUidView):
    template_name = 'cp/users/journal.html'

class ResultsView(BaseView):
    template_name = 'cp/users/results.html'

    def get_context_data(self, **kwargs):
        context = super(ResultsView, self).get_context_data(**kwargs)
        context['filter'] = self.get_filter()
        context.update(self.get_results(context['filter']))
        return context

    def get_filter(self):
        fs = {'query': '',
              'type': '',
              'rpp': '25',
              'p': 1}

        for k in fs:
            if self.request.GET.get(k):
                val = self.request.GET[k]

                if k == 'query':
                    fs[k] = val
                elif k == 'type':
                    try:
                        i = UserType(int(val))
                    except:
                        pass
                    else:
                        fs[k] = i.value
                elif k == 'rpp':
                    try:
                        i = int(val)
                    except:
                        pass
                    else:
                        fs[k] = i
                elif k == 'p':
                    try:
                        i = int(val)
                    except:
                        pass
                    else:
                        fs[k] = i

        return fs

    def get_results(self, f):
        users = User.objects.all()

        if f.get('query'):
            users = users.filter(Q(email__iregex=f['query']) | Q(alias__iregex=f['query']))

        if f.get('type'):
            users = users.filter(type=f['type'])

        paginator = Paginator(users, f.get('rpp', 25))
        page_idx = 1

        if f.get('p'):
            if f['p'] in paginator.page_range:
                page_idx = f['p']

        page = paginator.page(page_idx)

        return {'paginator': paginator, 'page': page}

class UnBanView(BaseUidView):
    def get(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        user = context['u']

        ban = user.get_ban()

        if not ban:
            return HttpResponseNotFound()

        ban.delete()

        user.is_active = True
        user.save()

        user.add_message(tag='account_unbanned')

        with TranslationContext(user):
            msg = EmailMessage(_('Account ban removed'),
                               tpl='cp/users/unbanned.mail')
            msg.send(to=[user.email])

        messages.info(request,
                      _("Ban for user account <strong>%s</strong> removed.") % user.email)

        return self.redirect('cp:users:detail', args=(user.id,))


        user.is_active = False
        user.save()
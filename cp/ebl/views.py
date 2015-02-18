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

from accounts.models import User, BlacklistedEmail
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _
from ydns.utils import messages
from ydns.views import TemplateView

import re

class BaseView(TemplateView):
    requires_admin = True
    requires_login = True

    def get_context_data(self, **kwargs):
        context = super(BaseView, self).get_context_data(**kwargs)
        context['users'] = User.objects.all()
        return context

class BaseIdView(BaseView):
    def get_context_data(self, **kwargs):
        context = super(BaseIdView, self).get_context_data(**kwargs)
        context['entry'] = get_object_or_404(BlacklistedEmail, id=int(self.kwargs['entry_id']))
        return context

class CreateView(BaseView):
    template_name = 'cp/ebl/create.html'

    def create_entry(self, request, pattern, reason):
        BlacklistedEmail.objects.create(name=pattern,
                                        user=request.user,
                                        reason=reason)

        messages.info(request,
                      _("Pattern created."))

        return self.redirect('cp:ebl:home')

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request)

        if not errors:
            return self.create_entry(request,
                                     cleaned_data['pattern'],
                                     cleaned_data.get('reason') or None)
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def validate(self, request):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('pattern'):
            errors['pattern'] = _("Pattern not specified")
        else:
            try:
                re.compile(request.POST['pattern'])
            except re.error as exc:
                errors['pattern'] = _("Pattern is invalid: %s") % str(exc)
            else:
                try:
                    BlacklistedEmail.objects.get(name__iexact=request.POST['pattern'])
                except BlacklistedEmail.DoesNotExist:
                    pass
                else:
                    errors['pattern'] = _("Pattern already exists")

                if not errors:
                    cleaned_data['pattern'] = request.POST['pattern']

        if request.POST.get('reason'):
            cleaned_data['reason'] = request.POST['reason'].strip()

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class DeleteView(BaseIdView):
    template_name = 'cp/ebl/delete.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        entry = context['entry']

        entry.delete()
        messages.info(request, _("Email Blacklist Entry deleted."))

        return self.redirect('cp:ebl:home')

class DetailView(BaseIdView):
    template_name = 'cp/ebl/detail.html'

class EditView(BaseIdView):
    template_name = 'cp/ebl/edit.html'

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(**kwargs)
        errors, cleaned_data = self.validate(request, context)

        if not errors:
            return self.update_entry(request,
                                     context['entry'],
                                     cleaned_data['pattern'],
                                     cleaned_data.get('reason') or None)
        else:
            context.update(errors=errors, post=request.POST)

        return self.render_to_response(context)

    def update_entry(self, request, entry, pattern, reason):
        changes = 0

        if entry.name != pattern:
            entry.name = pattern
            changes += 1

        if entry.reason != reason:
            entry.reason = reason
            changes += 1

        if changes > 0:
            entry.save()

            messages.info(request,
                          _("Changes saved."))

        return self.redirect('cp:ebl:detail', args=(entry.id,))

    def validate(self, request, context):
        errors = {}
        cleaned_data = {}

        if not request.POST.get('pattern'):
            errors['pattern'] = _("Pattern not specified")
        else:
            try:
                re.compile(request.POST['pattern'])
            except re.error as exc:
                errors['pattern'] = _("Pattern is invalid: %s") % str(exc)
            else:
                try:
                    BlacklistedEmail.objects.exclude(id=context['entry'].id).get(name__iexact=request.POST['pattern'])
                except BlacklistedEmail.DoesNotExist:
                    pass
                else:
                    errors['pattern'] = _("Pattern already exists")

                if not errors:
                    cleaned_data['pattern'] = request.POST['pattern']

        if request.POST.get('reason'):
            cleaned_data['reason'] = request.POST['reason'].strip()

        if errors:
            cleaned_data.clear()

        return errors, cleaned_data

class HomeView(BaseView):
    template_name = 'cp/ebl/home.html'

    def get_context_data(self, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        context['entries'] = BlacklistedEmail.objects.all()
        return context
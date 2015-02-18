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
from base64 import b64decode
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseNotFound, JsonResponse
from django.utils import timezone
from django.views.generic import View
from netaddr import IPAddress, AddrConversionError, AddrFormatError
from ydns.models import Host, Record
from ydns.views import TemplateView

class CurrentIpAddressView(View):
    """
    The resource for returning the current IP address as seen
    by the YDNS web server.
    """
    def get(self, request, *args, **kwargs):
        return HttpResponse(request.META['REMOTE_ADDR'], content_type='text/plain')

class CurrentIpAddressJsonView(View):
    """
    The resource for returning the current IP address as seen
    by the YDNS web server. (JSON version)
    """
    def get(self, request, *args, **kwargs):
        address_type = None

        try:
            i = IPAddress(request.META['REMOTE_ADDR'])
        except (AddrFormatError, AddrConversionError):
            pass
        else:
            address_type = i.version

        return JsonResponse({'ip': request.META['REMOTE_ADDR'],
                             'address_type': address_type})

class DocumentationPdfView(TemplateView):
    requires_admin = False
    requires_login = False

    def get(self, request, *args, **kwargs):
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename="YDNS_APIv1_Documentation.pdf"'
        return response

class HomeView(TemplateView):
    requires_admin = False
    requires_login = False
    template_name = 'api/v1/home.html'

class UpdateView(View):
    """
    The resource for issuing update calls to API v1.

    Following GET parameters are accepted:
      "host" (required): The YDNS host to be updated
      "ip" (optional): An IP Address to use for update purposes instead of REMOTE_ADDR
      "record_id" (optional): Optional record to force updating a specific record

    Additional improvements apply here compared to YDNS v2.1:
    Records for a specific address type (IPv4 or IPv6 address) are automatically
    created if they don't exist. This doesn't apply to YDNS v2.1 and earlier.

    """
    class AuthorizationError(ValueError):
        pass

    def get(self, request, *args, **kwargs):
        user = None

        try:
            user = self.get_user(request)
        except self.AuthorizationError as exc:
            return HttpResponseBadRequest(str(exc))
        else:
            if user is None:
                return HttpResponse('badauth', status=401)

        # Check parameters
        if 'host' not in request.GET:
            return HttpResponseBadRequest('Missing host parameter')

        host = None
        content = None
        record = None

        if request.GET.get('content'):
            content = request.GET['content']
        elif request.GET.get('ip'):
            content = request.GET['ip']
        else:
            content = request.META['REMOTE_ADDR']

        if len(content) > 65535:
            return HttpResponseBadRequest('ip exceeds max length')

        # Try to find the host
        try:
            host = Host.objects.get(user=user, name=request.GET['host'])
        except Host.DoesNotExist:
            return HttpResponseNotFound('host not found')

        if request.GET.get('record_id'):
            try:
                record_id = int(request.GET['record_id'])
            except (ValueError, TypeError, IndexError):
                return HttpResponseBadRequest('Parameter record_id has invalid value')
            else:
                try:
                    record = host.records.get(id=record_id)
                except Record.DoesNotExist:
                    return HttpResponseNotFound('record not found')
                else:
                    return self.update_record(host, record, content, check=True, user=user)

        # Find appropriate record
        try:
            ip = IPAddress(content)
        except (AddrFormatError, AddrConversionError):
            return HttpResponseBadRequest('invalid ip address (%s)' % (content,))
        else:
            desired_rr_type = 'A' if ip.version == 4 else 'AAAA'
            records = host.records.filter(type=desired_rr_type)

            if records.count() > 0:
                record = records.first()
                return self.update_record(host, record, content, user=user)
            else:
                return self.create_record(host, desired_rr_type, content, user=user)

    def get_user(self, request):
        """
        Check authentication of a user by using HTTP Authorization.

        :param request: HttpRequest
        :return: User or None in case no user can be found
        """
        if 'HTTP_AUTHORIZATION' not in request.META:
            raise self.AuthorizationError('Missing Authorization header')

        authorization = request.META['HTTP_AUTHORIZATION']
        params = authorization.split()
        email = None
        password = None

        if len(params) < 2:
            raise self.AuthorizationError('Erroneous Authorization header')
        elif params[0].lower() != 'basic':
            raise self.AuthorizationError('Erroneous Authorization header: No other auth type '
                                          'than "Basic" is supported')

        try:
            data = b64decode(params[1])
        except Exception:
            raise self.AuthorizationError('Erroneous Authorization header: Invalid encoded')
        else:
            data = data.decode('utf-8').split(':', 2)

            if len(data) != 2:
                raise self.AuthorizationError('Erroneous Authorization header: Invalid param count '
                                              'in authorization header')
            else:
                email, password = data[:2]

        assert(email is not None)
        assert(password is not None)

        # Check user account
        if '@' in email:
            qs = {'email__iexact': email}
        else:
            qs = {'alias': email}

        try:
            user = User.objects.get(**qs)
        except User.DoesNotExist:
            return None
        else:
            if not user.check_password(password) and not user.api_password == password:
                return None
            elif not user.is_active:
                return None  # account is inactive
            elif user.get_ban():
                return None  # user is banned
            else:
                return user

    def create_record(self, host, rr_type, content, user=None):
        """
        Create a record.

        :param host: Host to create record for
        :param rr_type: Resource record type
        :param content: Content
        :param user: User
        :return: HttpResponse
        """
        record = host.records.create(domain=host.domain,
                                     name=host.name,
                                     type=rr_type,
                                     content=content)

        host.add_message('record_created',
                         ip=self.request.META['REMOTE_ADDR'],
                         user=user,
                         user_agent=self.request.META.get('HTTP_USER_AGENT'),
                         rr_type=rr_type,
                         auto=True)

        return HttpResponse('ok')

    def update_record(self, host, record, content, check=False, user=None):
        if check:
            if record.type in ('A', 'AAAA'):
                try:
                    ip = IPAddress(content)
                except (AddrConversionError, AddrFormatError):
                    return HttpResponseBadRequest('type mismatch: record type is %s, but content is not a '
                                                  'valid IP address' % record.type)
                else:
                    if ip.version == 4 and record.type != 'A':
                        return HttpResponseBadRequest('type mismatch: record type is %s, but content is not a '
                                                      'valid IPv6 address' % record.type)
                    elif ip.version == 6 and record.type != 'AAAA':
                        return HttpResponseBadRequest('type mismatch: record type is %s, but content is not a '
                                                      'valid IPv4 address' % record.type)

        record.content = content
        record.date_last_modified = timezone.now()
        record.save()

        host.add_message('record_updated',
                         ip=self.request.META['REMOTE_ADDR'],
                         user=user,
                         user_agent=self.request.META.get('HTTP_USER_AGENT'),
                         content=content)

        return HttpResponse('ok')
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


def activate_timezone(request):
    """
    Set user timezone for the current session.

    This ensures that the timezone is persistent within the session
    in conjunction with an additional middleware that activates the
    timezone on every request.

    :param request: HttpRequest
    """
    if not request.user.is_authenticated():
        raise AttributeError('user must be authenticated')

    user = request.user

    if user.timezone:
        request.session['django_timezone'] = user.timezone
        request.session.modified = True
    elif 'django_timezone' in request.session:
        del request.session['django_timezone']


def deactivate_timezone(request):
    """
    Remove timezone from user session.

    :param request: HttpRequest
    """
    if 'django_timezone' in request.session:
        del request.session['django_timezone']
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

# This is similar to what `django.contrib.messages` does, but much simpler.

__all__ = ['count', 'danger', 'error', 'info', 'success', 'warning']

def _add_message(request, level, message, title=None):
    """
    Add a message to the session.

    :param request: HttpRequest
    :param level: Message level (str)
    :param message: Message content (str)
    :param title: Title (str or None)
    """
    if not request.session.get('_sysmsgs'):
        request.session['_sysmsgs'] = []

    request.session['_sysmsgs'].append({'level': level,
                                        'message': message,
                                        'title': title})
    request.session.modified = True

def count(request):
    """
    Return the number of messages in the current request session.

    :param request: HttpRequest
    :return: int
    """
    if request.session.get('_sysmsgs'):
        return len(request.session['_sysmsgs'])
    return 0

def danger(request, message, title=None):
    """
    Add a danger message.

    :param request: HttpRequest
    :param message: Message content (str)
    :param title: Message title (str or None)
    """
    return _add_message(request, 'danger', message, title)

error = danger

def info(request, message, title=None):
    """
    Add a info message.

    :param request: HttpRequest
    :param message: Message content (str)
    :param title: Message title (str or None)
    """
    return _add_message(request, 'info', message, title)

def success(request, message, title=None):
    """
    Add a success message.

    :param request: HttpRequest
    :param message: Message content (str)
    :param title: Message title (str or None)
    """
    return _add_message(request, 'success', message, title)

def warning(request, message, title=None):
    """
    Add a warning message.

    :param request: HttpRequest
    :param message: Message content (str)
    :param title: Message title (str or None)
    """
    return _add_message(request, 'warning', message, title)
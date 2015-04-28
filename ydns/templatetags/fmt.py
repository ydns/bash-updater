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

from dateutil.relativedelta import relativedelta
from django import template
from django.template.defaultfilters import date as filter_date
from django.utils import timezone

import math

register = template.Library()


@register.filter(expects_localtime=True, is_safe=False)
def fmt_timesince(d):
    """
    Formatter for time since.

    :param d:
    :return: str
    """
    now = timezone.now()
    diff = now - d
    secs = diff.total_seconds()

    if secs < 60:
        return 'moments ago'
    elif secs >= 60 and secs < 3600:
        mins = math.floor(secs / 60)
        return '{} minute{} ago'.format(mins, '' if mins == 1 else 's')
    elif secs >= 3600 and secs < 3600 * 3:
        hours = math.floor(secs / 3600)
        return '{} hour{} ago'.format(hours, '' if hours == 1 else 's')
    elif now.date() == d.date():
        return 'Today, {}'.format(filter_date(d, 'H:i'))
    elif now.date() - relativedelta(days=1) == d.date():
        return 'Yesterday, {}'.format(filter_date(d, 'H:i'))
    else:
        return filter_date(d, 'N j, Y H:i')
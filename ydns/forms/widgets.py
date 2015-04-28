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

from django.conf import settings
from django.core.exceptions import ValidationError
from django.forms import widgets
from django.forms.utils import format_html
from ydns.utils import recaptcha
from ydns.utils.recaptcha import RecaptchaError


class RecaptchaInput(widgets.Widget):
    """
    reCAPTCHA Input widget.
    """
    def clean(self, value):
        super(RecaptchaInput, self).clean(value)

        try:
            recaptcha.verify(value)
        except RecaptchaError as exc:
            raise ValidationError(str(exc))

        return value

    def render(self, name, value, attrs=None):
        return format_html('<div class="g-recaptcha" data-sitekey="{}"></div>'.format(settings.RECAPTCHA_SITE_KEY))

    def value_from_datadict(self, data, files, name):
        return data.get('g-recaptcha-response', None)
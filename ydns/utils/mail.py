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

from django.core.mail import EmailMessage as _EmailMessage
from django.template.loader import render_to_string


class EmailMessage(_EmailMessage):
    """
    Template-based email message.
    """

    def __init__(self, subject, tpl, context=None, from_email=None):
        """
        Initialize a email message instance.

        :param subject: Subject (str)
        :param tpl: Template file path (str)
        :param context: Template context (dict or None)
        :param from_email: Email origin (str or None)
        """
        if context is None:
            context = {}

        body = render_to_string(tpl, context)
        super(EmailMessage, self).__init__(subject,
                                           body,
                                           from_email=from_email)

    def send(self, to=None, bcc=None, cc=None, fail_silently=False):
        """
        Send the email to specific recipients.

        :param to: Direct recipients, FROM header (tuple, list)
        :param bcc: Blind carbon copy recipients, BCC header (tuple, list)
        :param cc: Carbon copy recipients, CC header (tuple, list)
        :param fail_silently: Whether to raise an exception on error (bool)
        """
        if to and isinstance(to, (tuple, list)):
            self.to = list(to)
        if bcc and isinstance(bcc, (tuple, list)):
            self.bcc = list(to)
        if cc and isinstance(cc, (tuple, list)):
            self.cc = list(cc)

        return super(EmailMessage, self).send(fail_silently=fail_silently)
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

from django.core.exceptions import ValidationError
from netaddr import AddrFormatError, IPAddress
from ydns import forms
from .enum import RecordType


class CreateForm(forms.HorizontalForm):
    name = forms.CharField(placeholder='Record name…',
                           label='Name')
    type = forms.ChoiceField(label='Type')
    content = forms.CharField(placeholder='Content (e.g. IP address, etc.)…')
    ttl = forms.IntegerField(label='TTL', required=False)
    prio = forms.IntegerField(label='Priority', required=False)

    field_css = 'col-lg-9 col-md-9'

    def __init__(self, type_choices, **kwargs):
        super(CreateForm, self).__init__(**kwargs)
        self.fields['type'].choices = type_choices

    def clean_name(self):
        return self.cleaned_data['name'].lower()

    def clean_content(self):
        record_type = RecordType(self.cleaned_data['type'])

        if record_type == RecordType.A:
            try:
                ip = IPAddress(self.cleaned_data['content'])
            except AddrFormatError:
                raise ValidationError('Not an IP address')
            else:
                if ip.version != 4:
                    raise ValidationError('Not an IPv4 address')
        elif record_type == RecordType.AAAA:
            try:
                ip = IPAddress(self.cleaned_data['content'])
            except AddrFormatError:
                raise ValidationError('Not an IP address')
            else:
                if ip.version != 6:
                    raise ValidationError('Not an IPv6 address')

        return self.cleaned_data['content']

    def clean_prio(self):
        record_type = RecordType(self.cleaned_data['type'])

        if record_type == RecordType.MX:
            if not self.cleaned_data.get('prio'):
                raise ValidationError('This field is required')
            else:
                try:
                    n = int(self.cleaned_data['prio'])
                except (ValueError, IndexError, TypeError):
                    raise ValidationError('Must be an integer')
                else:
                    if n < 1 or n > 10000000:
                        raise ValidationError('Must be between 1 and 10000000')
                    else:
                        return n

        return None

    def clean_ttl(self):
        record_type = RecordType(self.cleaned_data['type'])

        if record_type == RecordType.MX:
            if not self.cleaned_data.get('ttl'):
                raise ValidationError('This field is required')
            else:
                try:
                    n = int(self.cleaned_data['ttl'])
                except (ValueError, IndexError, TypeError):
                    raise ValidationError('Must be an integer')
                else:
                    if n < 1 or n > 10000000:
                        raise ValidationError('Must be between 1 and 10000000')
                    else:
                        return n

        return None


class EditForm(CreateForm):
    label_css = 'col-lg-2 col-md-3'
    field_css = 'col-lg-5 col-md-5'
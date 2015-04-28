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

from django import forms
from django.forms import widgets
from .widgets import RecaptchaInput

__all__ = ['BooleanField', 'CharField', 'ChoiceField', 'DateField', 'DecimalField', 'EmailField', 'FileField',
           'IntegerField', 'PasswordField', 'RecaptchaField', 'TextField']


class BooleanField(forms.BooleanField):
    widget = widgets.CheckboxInput


class InputMixin(forms.Field):
    """
    Input mixin to support Bootstrap CSS styling and further
    common attributes for form fields.
    """
    def __init__(self, placeholder=None, *args, **kwargs):
        self.placeholder = placeholder
        super(InputMixin, self).__init__(*args, **kwargs)

    def widget_attrs(self, widget):
        attrs = super(InputMixin, self).widget_attrs(widget)

        if self.placeholder:
            attrs.update(placeholder=self.placeholder)
        if self.required:
            attrs.update(required=self.required)

        klass = attrs.get('class') or ''

        if 'form-control' not in klass.split(' '):
            klass += ' form-control'

        attrs['class'] = klass.strip()

        return attrs


class CharField(forms.CharField, InputMixin):
    widget = widgets.TextInput


class ChoiceField(forms.ChoiceField):
    widget = widgets.Select

    def widget_attrs(self, widget):
        attrs = super(ChoiceField, self).widget_attrs(widget)

        if self.required:
            attrs.update(required=self.required)

        klass = attrs.get('class') or ''

        if 'form-control' not in klass.split(' '):
            klass += ' form-control'

        attrs['class'] = klass.strip()

        return attrs


class DateField(forms.DateField, InputMixin):
    widget = widgets.DateInput

    def widget_attrs(self, widget):
        attrs = super(DateField, self).widget_attrs(widget)
        attrs['data-provide'] = 'datepicker'
        return attrs


class DecimalField(forms.DecimalField, InputMixin):
    widget = widgets.NumberInput


class EmailField(forms.EmailField, InputMixin):
    widget = widgets.EmailInput


class FileField(forms.FileField, InputMixin):
    widget = widgets.FileInput


class IntegerField(forms.IntegerField, InputMixin):
    widget = widgets.NumberInput


class PasswordField(CharField):
    widget = widgets.PasswordInput


class RecaptchaField(forms.CharField):
    widget = RecaptchaInput


class TextField(forms.CharField, InputMixin):
    widget = widgets.Textarea

    def __init__(self, rows=3, placeholder=None, *args, **kwargs):
        if not isinstance(rows, int):
            raise TypeError('rows must be an int, got {!r}'.format(rows))

        self.rows = rows
        self.placeholder = placeholder
        super(TextField, self).__init__(*args, **kwargs)

    def widget_attrs(self, widget):
        attrs = super(TextField, self).widget_attrs(widget)

        if self.rows:
            attrs.update(rows=self.rows)
        if self.placeholder:
            attrs.update(placeholder=self.placeholder)

        return attrs
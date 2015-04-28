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
from django.forms.widgets import CheckboxInput
from django.utils.encoding import force_text
from django.utils.html import conditional_escape
from django.utils.safestring import mark_safe

__all__ = ['Form', 'HorizontalForm']


class Form(forms.Form):
    """
    Extension of Django form framework to support Bootstrap
    specific styling.
    """
    def __str__(self):
        s = ''

        for name, field in self.fields.items():
            bf = self[name]

            if isinstance(field.widget, CheckboxInput):
                s += '<div class="checkbox{}">'.format(' has-error' if bf.errors else '')
                s += '<label>'
                s += str(bf)

                if bf.label:
                    s += ' ' + force_text(bf.label)
                if bf.errors:
                    s += '<p class="help-block">{}</p>'.format(
                        ', '.join([conditional_escape(error) for error in bf.errors]))

                s += '</label>'
            else:
                s += '<div class="form-group{}">'.format(' has-error' if bf.errors else '')

                if bf.label:
                    label = conditional_escape(force_text(bf.label))
                    s += force_text(bf.label_tag(label) or '')

                s += str(bf)

                if bf.errors:
                    s += '<p class="help-block">{}</p>'.format(
                        ', '.join([conditional_escape(error) for error in bf.errors]))

                s += '</div>'

        return mark_safe(s)


class HorizontalForm(forms.Form):
    """
    Extension of Django form framework to support Bootstrap
    specific styling for horizontal forms.
    """
    label_css = 'col-lg-3 col-md-3'
    field_css = 'col-lg-4 col-md-4'
    label_offset_css = 'col-lg-offset-3 col-md-offset-3'

    def __str__(self):
        s = ''

        for name, field in self.fields.items():
            bf = self[name]

            if isinstance(field.widget, CheckboxInput):
                s += '<div class="checkbox{}">'.format(' has-error' if bf.errors else '')
                s += '<label class="{}">'.format(self.label_offset_css)
                s += str(bf)

                if bf.label:
                    s += force_text(bf.label)
                if bf.errors:
                    s += '<p class="help-block">{}</p>'.format(
                        ', '.join([conditional_escape(error) for error in bf.errors]))

                s += '</label>'
            else:
                cls_list = ['form-group']

                if bf.errors:
                    cls_list.append('has-error')
                if hasattr(field, 'css_class'):
                    cls_list.append(field.css_class)

                    if 'hidden' in cls_list and (bf.data or bf.errors):
                        cls_list.remove('hidden')

                s += '<div class="{}" data-field-name="{}">'.format(' '.join(cls_list), name)

                if bf.label:
                    label = force_text(bf.label)
                    s += '<label for="id_{0}" class="control-label {1}">{2}</label>'.format(name,
                                                                                            self.label_css,
                                                                                            label)

                s += '<div class="{}">'.format(self.field_css)
                s += str(bf)

                if bf.errors:
                    s += '<p class="help-block">{}</p>'.format(
                        ', '.join([conditional_escape(error) for error in bf.errors]))

                s += '</div>'

            s += '</div>'

        return mark_safe(s)
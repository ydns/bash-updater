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

from ydns import forms


class LoginForm(forms.HorizontalForm):
    email = forms.EmailField(label='Email address')
    password = forms.PasswordField()

    field_css = 'col-lg-9 col-md-9'


class ResetPasswordForm(forms.HorizontalForm):
    email = forms.EmailField(label='Email address')
    recaptcha = forms.RecaptchaField(label=' ')

    field_css = 'col-lg-9 col-md-9'


class SetPasswordForm(forms.HorizontalForm):
    new = forms.PasswordField(label='New password',
                              placeholder='Enter a new password…',
                              min_length=6)
    repeat = forms.PasswordField(label='New password',
                                 placeholder='Repeat the new password…',
                                 min_length=6)

    field_css = 'col-lg-9 col-md-9'


class SignupForm(forms.HorizontalForm):
    email = forms.EmailField(label='Email address',
                             placeholder='Your email address…')
    password = forms.PasswordField(label='Password',
                                   placeholder='Enter a password…',
                                   min_length=6)
    repeat = forms.PasswordField(label='Password',
                                 placeholder='Repeat the password…',
                                 min_length=6)
    recaptcha = forms.RecaptchaField(label=' ')
    terms = forms.BooleanField(label='I have read and accept the {terms_url}')

    field_css = 'col-lg-9 col-md-9'

    def __init__(self, terms_url, **kwargs):
        super(SignupForm, self).__init__(**kwargs)

        terms_url_html = '<a href="{}">Terms and Conditions</a>'.format(terms_url)
        self.fields['terms'].label = self.fields['terms'].label.format(terms_url=terms_url_html)
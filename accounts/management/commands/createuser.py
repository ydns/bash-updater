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
from django.core.management.base import BaseCommand
from django.core.validators import validate_email, ValidationError
from getpass import getpass
from optparse import make_option


class Command(BaseCommand):
    """
    This management command is used to create user accounts
    via command line. Useful if you'd like to create an account
    with administrative privileges.
    """
    args = '<email>'
    help = 'Create user account'
    option_list = BaseCommand.option_list + (
        make_option('-p',
                    action='store_true',
                    dest='password',
                    default=False,
                    help='Assign password to account'),
        make_option('--admin',
                    action='store_true',
                    dest='admin',
                    default=False,
                    help='Assign admin privileges to account'),
    )

    def handle(self, *args, **options):
        if not args:
            return self.stderr.write('Missing required argument: email')
        else:
            try:
                validate_email(args[0])
            except ValidationError:
                return self.stderr.write('{!r} is not a valid email address'.format(args[0]))
            else:
                try:
                    user = User.objects.get(email__iexact=args[0])
                except User.DoesNotExist:
                    pass
                else:
                    return self.stderr.write('Email address {!r} is already '
                                             'taken by user account #{}'.format(user.email, user.id))

            email = args[0]
            password = None

            if options['password']:
                while True:
                    s = getpass()
                    if s:
                        s2 = getpass('Repeat Password: ')
                        if s != s2:
                            self.stderr.write('Passwords do not match')
                        else:
                            password = s
                            break

            # Create the account
            kwargs = {'is_active': True}

            if options['admin']:
                kwargs['is_admin'] = True

            user = User.objects.create_user(email, password, **kwargs)
            self.stdout.write('User account #{} created.'.format(user.id))

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
from django.core.management.base import NoArgsCommand
from django.db.models import Q
from django.utils import timezone
from domains import utils
from ydns.models import Domain
from ydns.utils.mail import EmailMessage

class Command(NoArgsCommand):
    help = 'Periodically check domains'

    def handle_noargs(self, **options):
        """
        Periodically check all domains if their configuration is fine.

        In case the configuration went wrong, issue a mail to our admins
        to inform them about this.

        :param options: Options (dict)
        """
        all_domains = Domain.objects.all()

        for domain in all_domains:
            result, servers, error = utils.validate(domain)

            if result == utils.ValidationResult.domain_not_found:
                message = 'Domain not found'
                msg = EmailMessage('Domain check: Domain not found (%s)' % domain.name,
                                   'domains/check_issue_admins.mail',
                                   {'domain': domain, 'message': message})
                msg.send(to=['support@ydns.eu'])
            elif result == utils.ValidationResult.exception_raised:
                message = 'Exception raised: %s' % (error,)
                msg = EmailMessage('Domain check: Exception raised (%s)' % domain.name,
                                   'domains/check_issue_admins.mail',
                                   {'domain': domain, 'message': message})
                msg.send(to=['support@ydns.eu'])
            elif result == utils.ValidationResult.missing_primary:
                message = 'Missing primary'
                msg = EmailMessage('Domain check: Missing primary (%s)' % domain.name,
                                   'domains/check_issue_admins.mail',
                                   {'domain': domain, 'message': message})
                msg.send(to=['support@ydns.eu'])
            elif result == utils.ValidationResult.missing_secondary:
                message = 'Missing secondary'
                msg = EmailMessage('Domain check: Missing secondary (%s)' % domain.name,
                                   'domains/check_issue_admins.mail',
                                   {'domain': domain, 'message': message})
                msg.send(to=['support@ydns.eu'])

        # Domains, which were inactive for some time are being deleted
        delta = timezone.now() - relativedelta(days=7)
        outdated_qs = all_domains.filter(Q(date_last_validated=None) | Q(date_last_validated__lte=delta))\
            .exclude(is_official=False)  # exclude official ones

        for domain in outdated_qs:
            is_outdated = False

            if domain.date_last_validated is None and domain.date_created <= delta.replace(tzinfo=None):
                is_outdated = True
            elif domain.date_last_validated:
                is_outdated = True

            if is_outdated:
                domain_name = domain.name
                domain.delete()
                self.stdout.write('*** Deleted domain "%s" (outdated)\n' % domain_name)
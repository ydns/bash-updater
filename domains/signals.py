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

from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from .models import Domain
from .utils import create_basic_records


@receiver(post_save, sender=Domain)
def _handle_new_domain(sender, instance, created, **kwargs):
    """
    Signal handler for domain creation.

    :param sender: Model
    :param instance: Instance
    :param created: Whether the instance has been created (bool)
    :param kwargs: Keyword arguments
    """
    if created:
        create_basic_records(instance)


@receiver(pre_delete, sender=Domain)
def _handle_domain_removal(sender, instance, **kwargs):
    """
    Signal handler for domain deletion.

    :param sender: Model
    :param instance: Instance
    :param kwargs: Keyword arguments
    """
    instance.records.all().delete()
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

from django.core.paginator import PageNotAnInteger, Paginator, EmptyPage
from django.utils.safestring import mark_safe
from urllib.parse import urlencode

__all__ = ['Pagination']


class Pagination(object):
    def __init__(self, object_list, objects_per_page, url, page_index=1):
        self.paginator = Paginator(object_list, objects_per_page)
        self.url = url
        self.query = {}

        try:
            page = self.paginator.page(page_index)
        except PageNotAnInteger:
            page = self.paginator.page(1)
        except EmptyPage:
            page = self.paginator.page(self.paginator.num_pages)

        self.page = page

    def __len__(self):
        return self.paginator.num_pages

    def __str__(self):
        return mark_safe(self.render())

    def get_url(self, **kwargs):
        query = self.query
        query.update(**kwargs)
        url = self.url

        if query:
            url += '?' + urlencode(query)

        return url

    def render(self, param='p'):
        """
        Render HTML code for the Pagination object.

        :param param: Page index parameter (str)
        :return: str
        """
        s = '<nav>'
        s += '<ul class="pagination pagination-sm">'

        if self.page.has_previous():
            if self.page.previous_page_number() > 1:
                url = self.get_url(**{param: str(self.page.previous_page_number())})
            else:
                url = self.get_url()

            s += '<li><a href="{}"><i class="fa fa-angle-left"></i></a></li>'.format(url)

        # page range
        page_range = 4

        if self.page.number - page_range <= 1:
            start = 1
            end = 6
        elif self.page.number >= (self.paginator.num_pages - page_range):
            start = self.paginator.num_pages - 5
            end = self.paginator.num_pages
        else:
            start = self.page.number - page_range
            end = self.page.number + page_range

        i = start
        while i < (end + 1):
            if i > 0 and i <= self.paginator.num_pages:
                s += '<li'
                if i == self.page.number:
                    s += ' class="active"'
                s += '>'

                if i > 1:
                    url = self.get_url(**{param: str(i)})
                else:
                    url = self.get_url()
                s += '<a href="{}">{}</a>'.format(url, i)
                s += '</li>'

            i += 1

        if self.page.has_next():
            url = self.get_url(**{param: str(self.page.next_page_number())})
            s += '<li><a href="{}"><i class="fa fa-angle-right"></i></a></li>'.format(url)

        s += '</ul>'
        s += '</nav>'

        return s
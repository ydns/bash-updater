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

from django.utils.safestring import mark_safe


class ContextualNavigationMiddleware(object):
    """
    A middleware for contextual navigation.

    Each class based view can define a static method called "get_navbar_context"
    to provide one or more links to be added to the navigation bar.

    A context processor will grab the generated content to display in the
    templates if appropriately.
    """

    @classmethod
    def process_view(cls, request, view_func, view_args, view_kwargs):
        """
        Process a view.

        :param request: HttpRequest
        :param view_func: Wrapped view function
        :param view_args: View arguments
        :param view_kwargs: View keyword arguments
        :return: None
        """
        if hasattr(view_func, 'cls'):
            instance = view_func.cls(**view_func.cls_kwargs)
            instance.request = request
            instance.args = view_args
            instance.kwargs = view_kwargs

            if hasattr(instance, 'get_navbar_context'):
                nc = instance.get_navbar_context()
                if nc:
                    request.navbar_context = cls.make_html(nc)

        return None

    @classmethod
    def make_html(cls, nc):
        """
        Generate markup code for the navbar content.

        :param nc: Navbar content (iterable)
        :return: safe html
        """
        s = ''

        if nc:
            for element in nc:
                s += element.__html__()

        return mark_safe(s)
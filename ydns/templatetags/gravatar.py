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

from django import template
from hashlib import md5
from urllib.parse import urlencode

register = template.Library()


class GravatarUrlNode(template.Node):
    """
    Template node for generating Gravatar urls.
    """
    def __init__(self, email, size):
        """
        Initialize Gravatar URL node instance.

        :param email: Email address (str)
        :param size: Desired image size in pixels (int)
        """
        self.email = template.Variable(email)
        self.size = template.Variable(size)

    def render(self, context):
        """
        Render node content.

        :param context: Template context
        :return: str
        """
        try:
            email = self.email.resolve(context)
        except template.VariableDoesNotExist:
            return ''
        else:
            size = 40

            try:
                size = self.size.resolve(context)
            except template.VariableDoesNotExist:
                pass
            else:
                if not isinstance(size, int):
                    raise template.TemplateSyntaxError('{!r} must be an integer'.format(size))

            gravatar_url = 'https://www.gravatar.com/avatar/' + md5(email.lower().encode()).hexdigest()
            gravatar_url += '?' + urlencode({'s': str(self.size)})

            return gravatar_url


@register.tag
def gravatar_url(parser, token):
    """
    Gravatar URL tag.

    :param parser: Template parser
    :param token: Token
    :return: URL node instance
    """
    split_token = token.split_contents()

    if len(split_token) < 2:
        raise template.TemplateSyntaxError('{!r} requires arguments'.format(token.contents.split()[0]))

    email = split_token[1]
    size = 40

    if len(split_token) == 3:
        size = split_token[2]
    elif len(split_token) > 3:
        raise template.TemplateSyntaxError('{!r} takes at most two arguments'.format(token.contents.split()[0]))

    return GravatarUrlNode(email, size)
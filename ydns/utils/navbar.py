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


class NavBarNode(object):
    """
    A navbar node.
    """

    def __init__(self):
        self.index = -1

    def __html__(self):
        raise NotImplementedError()


class NavBarDivider(NavBarNode):
    """
    Horizontal divider.
    """

    def __html__(self):
        return '<li role="presentation" class="divider"></li>'


class NavBarHeader(NavBarNode):
    """
    Header item.
    """

    def __init__(self, title):
        super(NavBarHeader, self).__init__()
        self.title = title

    def __html__(self):
        return '<li role="presentation" class="dropdown-header">{!s}</li>'.format(self.title)


class NavBarItem(NavBarNode):
    """
    Actual item with arbitrary children.
    """

    def __init__(self, title, url=None, id=None, children=None):
        super(NavBarItem, self).__init__()
        self.title = title
        self.url = url
        self.id = id
        self.children = children or []

    def add(self, node):
        if not isinstance(node, NavBarNode):
            raise ValueError('node must be a NavBarNode derived item')

        self.children.append(node)

    def __html__(self):
        s = '<li role="presentation"'

        if self.children:
            s += ' class="dropdown"'

            if self.id:
                s += ' data-nav-id="{!s}"'.format(self.id)

            s += '><a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button"' \
                 'aria-expanded="false">{!s}</a>'.format(self.title)
            s += '<ul class="dropdown-menu" role="menu">'

            for child in self.children:
                s += child.__html__()

            s += '</ul>'
        else:
            if self.id:
                s += ' data-nav-id="{!s}"'.format(self.id)

            s += '><a href="{!s}">{!s}</a>'.format(self.url or '#', self.title)

        s += '</li>'

        return s
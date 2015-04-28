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

import re

_re_chrome = re.compile(r'Chrome/(\S+)')
_re_safari = re.compile(r'Safari/(\S+)')
_re_osx_ver = re.compile(r'OS X ([A-Za-z0-9_]+)')


def parse(s):
    """
    Parse user agent string.

    :param s: str
    :return: dict
    """
    ua = {'os': None,
          'os_version': None,
          'browser': None,
          'browser_version': None}

    if 'OS X' in s:
        ua['os'] = 'OS X'

        match = _re_osx_ver.findall(s)
        if match:
            ver_str = match[0].replace('_', '.')
            ua['os_version'] = ver_str
    elif 'X11' in s:
        if 'Linux' in s:
            ua['os'] = 'Linux'
        else:
            ua['os'] = 'X11'
    elif 'Windows' in s:
        ua['os'] = 'Windows'

    if 'Chrome/' in s:
        match = _re_chrome.findall(s)
        if match:
            ua['browser'] = 'Google Chrome'
            ua['browser_version'] = match[0]
    elif 'Safari/' in s:
        match = _re_safari.findall(s)
        if match:
            ua['browser'] = 'Safari'
            ua['browser_version'] = match[0]
    elif 'MSIE' in s:
        ua['browser'] = 'Internet Explorer'

    return ua
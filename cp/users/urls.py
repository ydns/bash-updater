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

from django.conf.urls import patterns, url
from .views import (BanView, DeleteView, DetailView, DomainsView, HomeView, HostsView, JournalView, ResultsView,
                    UnBanView)

urlpatterns = patterns('',
    url(r'^$', HomeView.as_view(), name='home'),
    url(r'^results$', ResultsView.as_view(), name='results'),
    url(r'^(?P<user_id>\d+)/ban/delete$', UnBanView.as_view(), name='unban'),
    url(r'^(?P<user_id>\d+)/ban$', BanView.as_view(), name='ban'),
    url(r'^(?P<user_id>\d+)/delete$', DeleteView.as_view(), name='delete'),
    url(r'^(?P<user_id>\d+)/domains$', DomainsView.as_view(), name='domains'),
    url(r'^(?P<user_id>\d+)/hosts$', HostsView.as_view(), name='hosts'),
    url(r'^(?P<user_id>\d+)/journal$', JournalView.as_view(), name='journal'),
    url(r'^(?P<user_id>\d+)$', DetailView.as_view(), name='detail'),
)
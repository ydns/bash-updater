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

from accounts import views as accounts_views
from django.conf.urls import include, url
from . import views

urlpatterns = (
    url(r'^$', views.HomeView.as_view(), name='home'),
    url(r'^accounts/', include('accounts.urls', namespace='accounts')),
    url(r'^api/', include('api.urls', namespace='api')),
    url(r'^dashboard$', views.DashboardView.as_view(), name='dashboard'),
    url(r'^domains/', include('domains.urls', namespace='domains')),
    url(r'^donate$', views.DonateView.as_view(), name='donate'),
    url(r'^get-started$', views.GetStartedView.as_view(), name='get_started'),
    url(r'^imprint$', views.ImprintView.as_view(), name='imprint'),
    url(r'^terms-and-conditions$', views.TermsView.as_view(), name='terms'),
    url(r'^login$', accounts_views.LoginView.as_view(), name='login'),
    url(r'^signup$', accounts_views.SignupView.as_view(), name='signup'),
)

#!/bin/bash
#
# yDNS Updater, updates your yDNS host.
# Copyright (C) 2013 Christian Jurk <cj@ydns.eu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


##
# Define your yDNS account details and host you'd like to update.
##

YDNS_USER="user@host.xx"
YDNS_PASSWD="secret"
YDNS_HOST="myhost.ydns.eu"

##
# Don't change anything below.
##
if ! hash curl 2>/dev/null; then
	echo "ERROR: cURL is missing."
	exit 1
fi

# if this fails with error 60 your certificate store does not contain the certificate,
# either add it or use -k (disable certificate check
ret=$(curl --basic \
	-u "$YDNS_USER:$YDNS_PASSWD" \
	--silent \
	https://ydns.eu/api/v1/update/?host=$YDNS_HOST)

if [ "$ret" != "ok" ]; then
	echo "Update failed: $ret"
	exit 90
fi

yDNS update API
---------------

To update a yDNS host, you have to do simple HTTP GET requests. Each 
request must use HTTP authorization in order to perform authorization of 
your request:

The URL to perform update calls is:
http://ydns.eu/api/v1/update/?host=myhost.ydns.eu[&ip=ip_address]

where the host parameter is required and the ip parameter is optional. 
If the latter is not specified, the public IP address as seen on the 
Internet is being used (should be fine for most situations). The IP 
address can be either an IPv4 or IPv6 address. You have to use the IP 
parameter if you want to update your IPv6 address, because the yDNS 
server currently does not have a public IPv6 address configured.

When requesting a host update, the server will respond either:

* HTTP status 400 (BAD REQUEST) if something is wrong with your parameters.
* HTTP status 401 (UNAUTHORIZED) if the authentication is invalid.
* HTTP STATUS 404 (NOT FOUND) if the specified host is not found.
* HTTP STATUS 200 (OK) if the update was successful.

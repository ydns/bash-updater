# yDNS - Simple updater script

The full yDNS API documentation can be found at:
https://ydns.eu/api/

This is a simple bash script that can update the IP address at yDNS
by simply cURL'ing the API update resource.

## Requirements

* bash
* [cURL](http://curl.haxx.se)

## Installation

Copy the script to a desired location. To configure the script, you can either edit it by editing `YDNS_USER`, `YDNS_PASSWD` and `YDNS_HOST` within, or you can use the `-u`, `-p` and `-H` command line options respectively. For example:

```
$ ./updater.sh -u myuser -p password -H myhost.ydns.eu
```

## How to use

Simply run the script with - or without command line options, depending on whether you'd like to specify the configuration as command line arguments. You can use the `-V` option to enable verbose output (useful for debugging). The script will exit with code 0 on success, with code 1 on input errors and 90 or 91 on other issues.

You can list all available command line options using the `-h` option.

## Changelog

### 20140824.1

- Added support for command line arguments.
- Added support for detecting IP address changes. The IP address is only updated when it has changed. A temporary file (default `/tmp/ydns_last_ip`) is used to store the "last known" IP address to decide whether it has been changed since last usage.
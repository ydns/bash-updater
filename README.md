# YDNS Bash Updater Script

This repository contains the bash updater script which can be used on *NIX-like environments to update dynamic hosts. It is recommended to use this script with cronjob to run periodically (preferrably every 15 minutes).

The script uses the YDNS API v1 (dyn-compatible).

## Installation

First, ensure that your host has [curl](http://curl.haxx.se) installed.

1. Check out the source code (updater.sh)
2. Place it into desired place and make it executable (`chmod +x updater.sh`)
3. Edit the script and update the user and host information to fit your configuration
4. Run the script (either by single call or set up a cronjob to run it periodically)

## Crontab Setup

To run this script every 15 minutes using `crontab`, add the following line to your crontab list:

```bash
*/15 * * * * /path/to/script/updater.sh > /dev/null
```

Although this works on most all implementations of `crontab`, for more portability use this instead:

```bash
0,15,30,45 * * * * /path/to/script/updater.sh > /dev/null
````

**NOTE:** To gain access to the crontab list to edit and add entries, execute `crontab -e` at the terminal

## Further notes

The code is licensed under the GNU Public License, version 3.

## Contribution

If you like to contribute useful changes to the script, simply fork the project, apply your changes and make a pull request.

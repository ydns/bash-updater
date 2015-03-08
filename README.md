# YDNS Core

This repository contains the backend and front-end code for the development release of YDNS.

## Requirements

* Python 3.4+
* Django 1.7+
* dnspython3
* netaddr
* googler

## Installation

1. Check out the source code
2. Create a virtual environment and install all the dependencies using `pip install -r requirements.txt`
3. Rename `ydns/local_settins.example.py` to `ydns/local_settings.py` and adjust the configuration. If you'd like to use the OAuth2 login features, you may have to obtain appropriate API credentials
4. Setup a database and add the configuration to your local_settings.py
5. Apply database migrations by using `./manage.py migrate` inside your YDNS folder
6. Launch the local server by using `./manage.py runserver`

In production environments, you might like to setup YDNS/Django as application server to serve a WSGI instance. A WSGI-capable web server can be used to distribute requests to the application server then (eg. uWSGI).

## Further notes

The code is licensed under the MIT license.

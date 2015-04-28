##
# Local YDNS configuration
#
# Please put your configuration in this file.
##

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'ydns',
        'USER': 'ydns',
        'PASSWORD': 'secret',
        'HOST': ''
    }
}

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'

# reCAPTCHA site key (reCAPTCHA v2.0)
RECAPTCHA_SITE_KEY = ''
RECAPTCHA_SECRET_KEY = ''

# Google-specific details
GAPI_CLIENT_ID = ''
GAPI_CLIENT_SECRET = ''

# Facebook-specific details
FACEBOOK_APP_ID = ''
FACEBOOK_APP_SECRET = ''

# Github-specific details
GITHUB_CLIENT_ID = ''
GITHUB_CLIENT_SECRET = ''
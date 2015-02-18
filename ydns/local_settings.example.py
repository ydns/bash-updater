##
# Local YDNS configuration
#
# Please put your configuration in this file.
##

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'db_name',
        'USER': 'db_user',
        'PASSWORD': 'db_pass',
        'HOST': ''
    }
}

RECAPTCHA = {
    'private_key': 'Recaptcha_Private_Key_here',
    'public_key': 'Recaptcha_Public_Key_here'
}

DEFAULT_FROM_EMAIL = 'YDNS <noreply@ydns.io>'

_ = lambda s: s
LANGUAGES = (
    ('en-us', _('English')),
    ('de', _('German')),
)

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.static",
    "django.core.context_processors.tz",
    "ydns.context_processors.messages"
)

MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'

# OAuth2: Google-specific details
GAPI_CLIENT_ID = ''
GAPI_CLIENT_SECRET = ''

# OAuth2: Facebook-specific details
FACEBOOK_APP_ID = ''
FACEBOOK_APP_SECRET = ''

# OAuth2: Github-specific details
GITHUB_CLIENT_ID = ''
GITHUB_CLIENT_SECRET = ''
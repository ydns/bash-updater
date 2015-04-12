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

from django.db import models
from enum import Enum

import json

__all__ = ['EnumField', 'JsonField']

class EnumField(models.Field, metaclass=models.SubfieldBase):
    """
    Simple enumeration field type.
    """
    def __init__(self, enum, *args, **kwargs):
        if not issubclass(enum, Enum):
            raise TypeError('%s must be a subclass of Enum' % enum)
        self.enum = enum
        super(EnumField, self).__init__(*args, **kwargs)

    def db_type(self, connection):
        if issubclass(self.enum, str):
            return 'text'
        return 'integer'

    def deconstruct(self):
        name, path, args, kwargs = super(EnumField, self).deconstruct()
        kwargs['enum'] = self.enum
        return name, path, args, kwargs

    def get_db_prep_value(self, value, connection, prepared=False):
        if value is None:
            return value
        elif issubclass(self.enum, str):
            return str(value)
        else:
            return int(value)

    def to_python(self, value):
        if value is None:
            return value
        return self.enum(value)


class JsonField(models.Field, metaclass=models.SubfieldBase):
    """
    Simple JSON field.
    """
    def db_type(self, connection):
        return 'text'

    def get_prep_value(self, value):
        if value is None:
            return value
        return json.dumps(value)

    def to_python(self, value):
        if value is None:
            return None
        elif isinstance(value, str):
            return json.loads(value)
        return value
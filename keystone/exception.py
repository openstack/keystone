# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import re


class Error(StandardError):
    """Base error class.

    Child classes should define an HTTP status code, title, and a doc string.

    """
    code = None
    title = None

    def __init__(self, message=None, **kwargs):
        """Use the doc string as the error message by default."""
        message = message or self.__doc__ % kwargs
        super(Error, self).__init__(message)

    def __str__(self):
        """Cleans up line breaks and indentation from doc strings."""
        string = super(Error, self).__str__()
        string = re.sub('[ \n]+', ' ', string)
        string = string.strip()
        return string


class ValidationError(Error):
    """Expecting to find %(attribute)s in %(target)s.

    The server could not comply with the request since it is either malformed
    or otherwise incorrect.

    The client is assumed to be in error.

    """
    code = 400
    title = 'Bad Request'


class Unauthorized(Error):
    """The request you have made requires authentication."""
    code = 401
    title = 'Not Authorized'


class Forbidden(Error):
    """You are not authorized to perform the requested action."""
    code = 403
    title = 'Not Authorized'


class ForbiddenAction(Forbidden):
    """You are not authorized to perform the requested action: %(action)s"""


class NotFound(Error):
    """Could not find: %(target)s"""
    code = 404
    title = 'Not Found'


class EndpointNotFound(NotFound):
    """Could not find endpoint: %(endpoint_id)s"""


class RoleNotFound(NotFound):
    """Could not find role: %(role_id)s"""


class ServiceNotFound(NotFound):
    """Could not find service: %(service_id)s"""


class TenantNotFound(NotFound):
    """Could not find tenant: %(tenant_id)s"""


class TokenNotFound(NotFound):
    """Could not find token: %(token_id)s"""


class UserNotFound(NotFound):
    """Could not find user: %(user_id)s"""


class Conflict(Error):
    """Conflict occurred attempting to store %(type)s.

    %(details)s

    """
    code = 409
    title = 'Conflict'


class UnexpectedError(Error):
    """An unexpected error prevented the server from fulfilling your request.

    %(exception)s

    """
    code = 500
    title = 'Internal Server Error'


class NotImplemented(Error):
    """The action you have requested has not been implemented."""
    code = 501
    title = 'Not Implemented'

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
    """You are not authorized to perform the requested action: %(action)s"""
    code = 403
    title = 'Not Authorized'


class NotFound(Error):
    """Could not find: %(target)s"""
    code = 404
    title = 'Not Found'

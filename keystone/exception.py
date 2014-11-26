# Copyright 2012 OpenStack Foundation
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

from oslo.utils import encodeutils
import six

from keystone.common import config
from keystone.i18n import _, _LW
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)

# Tests use this to make exception message format errors fatal
_FATAL_EXCEPTION_FORMAT_ERRORS = False


class Error(Exception):
    """Base error class.

    Child classes should define an HTTP status code, title, and a
    message_format.

    """
    code = None
    title = None
    message_format = None

    def __init__(self, message=None, **kwargs):
        try:
            message = self._build_message(message, **kwargs)
        except KeyError:
            # if you see this warning in your logs, please raise a bug report
            if _FATAL_EXCEPTION_FORMAT_ERRORS:
                raise
            else:
                LOG.warning(_LW('missing exception kwargs (programmer error)'))
                message = self.message_format

        super(Error, self).__init__(message)

    def _build_message(self, message, **kwargs):
        """Builds and returns an exception message.

        :raises: KeyError given insufficient kwargs

        """
        if not message:
            try:
                message = self.message_format % kwargs
            except UnicodeDecodeError:
                try:
                    kwargs = dict([(k, encodeutils.safe_decode(v)) for k, v in
                                   six.iteritems(kwargs)])
                except UnicodeDecodeError:
                    # NOTE(jamielennox): This is the complete failure case
                    # at least by showing the template we have some idea
                    # of where the error is coming from
                    message = self.message_format
                else:
                    message = self.message_format % kwargs

        return message


class ValidationError(Error):
    message_format = _("Expecting to find %(attribute)s in %(target)s -"
                       " the server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = 400
    title = 'Bad Request'


class SchemaValidationError(ValidationError):
    # NOTE(lbragstad): For whole OpenStack message consistency, this error
    # message has been written in a format consistent with WSME.
    message_format = _("%(detail)s")


class ValidationTimeStampError(Error):
    message_format = _("Timestamp not in expected format."
                       " The server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = 400
    title = 'Bad Request'


class StringLengthExceeded(ValidationError):
    message_format = _("String length exceeded.The length of"
                       " string '%(string)s' exceeded the limit"
                       " of column %(type)s(CHAR(%(length)d)).")


class ValidationSizeError(Error):
    message_format = _("Request attribute %(attribute)s must be"
                       " less than or equal to %(size)i. The server"
                       " could not comply with the request because"
                       " the attribute size is invalid (too large)."
                       " The client is assumed to be in error.")
    code = 400
    title = 'Bad Request'


class PasswordVerificationError(Error):
    message_format = _("The password length must be less than or equal "
                       "to %(size)i. The server could not comply with the "
                       "request because the password is invalid.")
    code = 403
    title = 'Forbidden'


class RegionDeletionError(Error):
    message_format = _("Unable to delete region %(region_id)s because it or "
                       "its child regions have associated endpoints.")
    code = 403
    title = 'Forbidden'


class PKITokenExpected(Error):
    message_format = _('The certificates you requested are not available. '
                       'It is likely that this server does not use PKI tokens '
                       'otherwise this is the result of misconfiguration.')
    code = 403
    title = 'Cannot retrieve certificates'


class SecurityError(Error):
    """Avoids exposing details of security failures, unless in debug mode."""
    amendment = _('(Disable debug mode to suppress these details.)')

    def _build_message(self, message, **kwargs):
        """Only returns detailed messages in debug mode."""
        if CONF.debug:
            return _('%(message)s %(amendment)s') % {
                'message': message or self.message_format % kwargs,
                'amendment': self.amendment}
        else:
            return self.message_format % kwargs


class Unauthorized(SecurityError):
    message_format = _("The request you have made requires authentication.")
    code = 401
    title = 'Unauthorized'


class AuthPluginException(Unauthorized):
    message_format = _("Authentication plugin error.")

    def __init__(self, *args, **kwargs):
        super(AuthPluginException, self).__init__(*args, **kwargs)
        self.authentication = {}


class MissingGroups(Unauthorized):
    message_format = _("Unable to find valid groups while using "
                       "mapping %(mapping_id)s")


class AuthMethodNotSupported(AuthPluginException):
    message_format = _("Attempted to authenticate with an unsupported method.")

    def __init__(self, *args, **kwargs):
        super(AuthMethodNotSupported, self).__init__(*args, **kwargs)
        self.authentication = {'methods': CONF.auth.methods}


class AdditionalAuthRequired(AuthPluginException):
    message_format = _("Additional authentications steps required.")

    def __init__(self, auth_response=None, **kwargs):
        super(AdditionalAuthRequired, self).__init__(message=None, **kwargs)
        self.authentication = auth_response


class Forbidden(SecurityError):
    message_format = _("You are not authorized to perform the"
                       " requested action.")
    code = 403
    title = 'Forbidden'


class ForbiddenAction(Forbidden):
    message_format = _("You are not authorized to perform the"
                       " requested action: %(action)s")


class ImmutableAttributeError(Forbidden):
    message_format = _("Could not change immutable attribute(s) "
                       "'%(attributes)s' in target %(target)s")


class CrossBackendNotAllowed(Forbidden):
    message_format = _("Group membership across backend boundaries is not "
                       "allowed, group in question is %(group_id)s, "
                       "user is %(user_id)s")


class InvalidPolicyAssociation(Forbidden):
    message_format = _("Invalid mix of entities for policy association - "
                       "only Endpoint, Service or Region+Service allowed. "
                       "Request was - Endpoint: %(endpoint_id)s, "
                       "Service: %(service_id)s, Region: %(region_id)s")


class NotFound(Error):
    message_format = _("Could not find: %(target)s")
    code = 404
    title = 'Not Found'


class EndpointNotFound(NotFound):
    message_format = _("Could not find endpoint: %(endpoint_id)s")


class MetadataNotFound(NotFound):
    """(dolph): metadata is not a user-facing concept,
    so this exception should not be exposed
    """
    message_format = _("An unhandled exception has occurred:"
                       " Could not find metadata.")


class PolicyNotFound(NotFound):
    message_format = _("Could not find policy: %(policy_id)s")


class PolicyAssociationNotFound(NotFound):
    message_format = _("Could not find policy association")


class RoleNotFound(NotFound):
    message_format = _("Could not find role: %(role_id)s")


class RegionNotFound(NotFound):
    message_format = _("Could not find region: %(region_id)s")


class ServiceNotFound(NotFound):
    message_format = _("Could not find service: %(service_id)s")


class DomainNotFound(NotFound):
    message_format = _("Could not find domain: %(domain_id)s")


class ProjectNotFound(NotFound):
    message_format = _("Could not find project: %(project_id)s")


class InvalidParentProject(NotFound):
    message_format = _("Cannot create project with parent: %(project_id)s")


class TokenNotFound(NotFound):
    message_format = _("Could not find token: %(token_id)s")


class UserNotFound(NotFound):
    message_format = _("Could not find user: %(user_id)s")


class GroupNotFound(NotFound):
    message_format = _("Could not find group: %(group_id)s")


class MappingNotFound(NotFound):
    message_format = _("Could not find mapping: %(mapping_id)s")


class TrustNotFound(NotFound):
    message_format = _("Could not find trust: %(trust_id)s")


class TrustUseLimitReached(Forbidden):
    message_format = _("No remaining uses for trust: %(trust_id)s")


class CredentialNotFound(NotFound):
    message_format = _("Could not find credential: %(credential_id)s")


class VersionNotFound(NotFound):
    message_format = _("Could not find version: %(version)s")


class EndpointGroupNotFound(NotFound):
    message_format = _("Could not find Endpoint Group: %(endpoint_group_id)s")


class IdentityProviderNotFound(NotFound):
    message_format = _("Could not find Identity Provider: %(idp_id)s")


class FederatedProtocolNotFound(NotFound):
    message_format = _("Could not find federated protocol %(protocol_id)s for"
                       " Identity Provider: %(idp_id)s")


class PublicIDNotFound(NotFound):
    # This is used internally and mapped to either User/GroupNotFound or,
    # Assertion before the exception leaves Keystone.
    message_format = "%(id)s"


class Conflict(Error):
    message_format = _("Conflict occurred attempting to store %(type)s -"
                       " %(details)s")
    code = 409
    title = 'Conflict'


class RequestTooLarge(Error):
    message_format = _("Request is too large.")
    code = 413
    title = 'Request is too large.'


class UnexpectedError(SecurityError):
    """Avoids exposing details of failures, unless in debug mode."""
    _message_format = _("An unexpected error prevented the server "
                        "from fulfilling your request.")

    debug_message_format = _("An unexpected error prevented the server "
                             "from fulfilling your request: %(exception)s")

    @property
    def message_format(self):
        """Return the generic message format string unless debug is enabled."""
        if CONF.debug:
            return self.debug_message_format
        return self._message_format

    def _build_message(self, message, **kwargs):
        if CONF.debug and 'exception' not in kwargs:
            # Ensure that exception has a value to be extra defensive for
            # substitutions and make sure the exception doesn't raise an
            # exception.
            kwargs['exception'] = ''
        return super(UnexpectedError, self)._build_message(message, **kwargs)

    code = 500
    title = 'Internal Server Error'


class TrustConsumeMaximumAttempt(UnexpectedError):
    debug_message_format = _("Unable to consume trust %(trust_id)s, unable to "
                             "acquire lock.")


class CertificateFilesUnavailable(UnexpectedError):
    debug_message_format = _("Expected signing certificates are not available "
                             "on the server. Please check Keystone "
                             "configuration.")


class MalformedEndpoint(UnexpectedError):
    debug_message_format = _("Malformed endpoint URL (%(endpoint)s),"
                             " see ERROR log for details.")


class MappedGroupNotFound(UnexpectedError):
    debug_message_format = _("Group %(group_id)s returned by mapping "
                             "%(mapping_id)s was not found in the backend.")


class MetadataFileError(UnexpectedError):
    message_format = _("Error while reading metadata file, %(reason)s")


class NotImplemented(Error):
    message_format = _("The action you have requested has not"
                       " been implemented.")
    code = 501
    title = 'Not Implemented'


class Gone(Error):
    message_format = _("The service you have requested is no"
                       " longer available on this server.")
    code = 410
    title = 'Gone'


class ConfigFileNotFound(UnexpectedError):
    debug_message_format = _("The Keystone configuration file %(config_file)s "
                             "could not be found.")


class MultipleSQLDriversInConfig(UnexpectedError):
    message_format = _('The Keystone domain configuration file '
                       '%(config_file)s defines an additional SQL driver - '
                       'only one is permitted.')


class MigrationNotProvided(Exception):
    def __init__(self, mod_name, path):
        super(MigrationNotProvided, self).__init__(_(
            "%(mod_name)s doesn't provide database migrations. The migration"
            " repository path at %(path)s doesn't exist or isn't a directory."
        ) % {'mod_name': mod_name, 'path': path})


class UnsupportedTokenVersionException(Exception):
    """Token version is unrecognizable or unsupported."""
    pass


class SAMLSigningError(UnexpectedError):
    debug_message_format = _('Unable to sign SAML assertion. It is likely '
                             'that this server does not have xmlsec1 '
                             'installed, or this is the result of '
                             'misconfiguration. Reason %(reason)s')
    title = 'Error signing SAML assertion'

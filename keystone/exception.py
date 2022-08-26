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

import http.client
from oslo_log import log
from oslo_utils import encodeutils

import keystone.conf
from keystone.i18n import _


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

KEYSTONE_API_EXCEPTIONS = set([])

# Tests use this to make exception message format errors fatal
_FATAL_EXCEPTION_FORMAT_ERRORS = False


def _format_with_unicode_kwargs(msg_format, kwargs):
    try:
        return msg_format % kwargs
    except UnicodeDecodeError:
        try:
            kwargs = {k: encodeutils.safe_decode(v)
                      for k, v in kwargs.items()}
        except UnicodeDecodeError:
            # NOTE(jamielennox): This is the complete failure case
            # at least by showing the template we have some idea
            # of where the error is coming from
            return msg_format

        return msg_format % kwargs


class _KeystoneExceptionMeta(type):
    """Automatically Register the Exceptions in 'KEYSTONE_API_EXCEPTIONS' list.

    The `KEYSTONE_API_EXCEPTIONS` list is utilized by flask to register a
    handler to emit sane details when the exception occurs.
    """

    def __new__(mcs, name, bases, class_dict):
        """Create a new instance and register with KEYSTONE_API_EXCEPTIONS."""
        cls = type.__new__(mcs, name, bases, class_dict)
        KEYSTONE_API_EXCEPTIONS.add(cls)
        return cls


class Error(Exception, metaclass=_KeystoneExceptionMeta):
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
                LOG.warning('missing exception kwargs (programmer error)')
                message = self.message_format

        super(Error, self).__init__(message)

    def _build_message(self, message, **kwargs):
        """Build and returns an exception message.

        :raises KeyError: given insufficient kwargs

        """
        if message:
            return message
        return _format_with_unicode_kwargs(self.message_format, kwargs)


class ValidationError(Error):
    message_format = _("Expecting to find %(attribute)s in %(target)s."
                       " The server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = int(http.client.BAD_REQUEST)
    title = http.client.responses[http.client.BAD_REQUEST]


class URLValidationError(ValidationError):
    message_format = _("Cannot create an endpoint with an invalid URL:"
                       " %(url)s.")


class PasswordValidationError(ValidationError):
    message_format = _("Password validation error: %(detail)s.")


class PasswordRequirementsValidationError(PasswordValidationError):
    message_format = _("The password does not match the requirements:"
                       " %(detail)s.")


class PasswordHistoryValidationError(PasswordValidationError):
    message_format = _("The new password cannot be identical to a "
                       "previous password. The total number which "
                       "includes the new password must be unique is "
                       "%(unique_count)s.")


class PasswordAgeValidationError(PasswordValidationError):
    message_format = _("You cannot change your password at this time due "
                       "to the minimum password age. Once you change your "
                       "password, it must be used for %(min_age_days)d day(s) "
                       "before it can be changed. Please try again in "
                       "%(days_left)d day(s) or contact your administrator to "
                       "reset your password.")


class PasswordSelfServiceDisabled(PasswordValidationError):
    message_format = _("You cannot change your password at this time due "
                       "to password policy disallowing password changes. "
                       "Please contact your administrator to reset your "
                       "password.")


class SchemaValidationError(ValidationError):
    # NOTE(lbragstad): For whole OpenStack message consistency, this error
    # message has been written in a format consistent with WSME.
    message_format = _("%(detail)s")


class ValidationTimeStampError(Error):
    message_format = _("Timestamp not in expected format."
                       " The server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = int(http.client.BAD_REQUEST)
    title = http.client.responses[http.client.BAD_REQUEST]


class InvalidOperatorError(ValidationError):
    message_format = _("The given operator %(_op)s is not valid."
                       " It must be one of the following:"
                       " 'eq', 'neq', 'lt', 'lte', 'gt', or 'gte'.")


class ValidationExpirationError(Error):
    message_format = _("The 'expires_at' must not be before now."
                       " The server could not comply with the request"
                       " since it is either malformed or otherwise"
                       " incorrect. The client is assumed to be in error.")
    code = int(http.client.BAD_REQUEST)
    title = http.client.responses[http.client.BAD_REQUEST]


class StringLengthExceeded(ValidationError):
    message_format = _("String length exceeded. The length of"
                       " string '%(string)s' exceeds the limit"
                       " of column %(type)s(CHAR(%(length)d)).")


class AmbiguityError(ValidationError):
    message_format = _("There are multiple %(resource)s entities named"
                       " '%(name)s'. Please use ID instead of names to"
                       " resolve the ambiguity.")


class ApplicationCredentialValidationError(ValidationError):
    message_format = _("Invalid application credential: %(detail)s")


class CircularRegionHierarchyError(Error):
    message_format = _("The specified parent region %(parent_region_id)s "
                       "would create a circular region hierarchy.")
    code = int(http.client.BAD_REQUEST)
    title = http.client.responses[http.client.BAD_REQUEST]


class ForbiddenNotSecurity(Error):
    """When you want to return a 403 Forbidden response but not security.

    Use this for errors where the message is always safe to present to the user
    and won't give away extra information.

    """

    code = int(http.client.FORBIDDEN)
    title = http.client.responses[http.client.FORBIDDEN]


class PasswordVerificationError(ForbiddenNotSecurity):
    message_format = _("The password length must be less than or equal "
                       "to %(size)i. The server could not comply with the "
                       "request because the password is invalid.")


class RegionDeletionError(ForbiddenNotSecurity):
    message_format = _("Unable to delete region %(region_id)s because it or "
                       "its child regions have associated endpoints.")


class ApplicationCredentialLimitExceeded(ForbiddenNotSecurity):
    message_format = _("Unable to create additional application credentials, "
                       "maximum of %(limit)d already exceeded for user.")


class CredentialLimitExceeded(ForbiddenNotSecurity):
    message_format = _("Unable to create additional credentials, maximum "
                       "of %(limit)d already exceeded for user.")


class SecurityError(Error):
    """Security error exception.

    Avoids exposing details of security errors, unless in insecure_debug mode.

    """

    amendment = _('(Disable insecure_debug mode to suppress these details.)')

    def __deepcopy__(self):
        """Override the default deepcopy.

        Keystone :class:`keystone.exception.Error` accepts an optional message
        that will be used when rendering the exception object as a string. If
        not provided the object's message_format attribute is used instead.
        :class:`keystone.exception.SecurityError` is a little different in
        that it only uses the message provided to the initializer when
        keystone is in `insecure_debug` mode. Instead it will use its
        `message_format`. This is to ensure that sensitive details are not
        leaked back to the caller in a production deployment.

        This dual mode for string rendering causes some odd behaviour when
        combined with oslo_i18n translation. Any object used as a value for
        formatting a translated string is deep copied.

        The copy causes an issue. The deep copy process actually creates a new
        exception instance with the rendered string. Then when that new
        instance is rendered as a string to use for substitution a warning is
        logged. This is because the code tries to use the `message_format` in
        secure mode, but the required kwargs are not in the deep copy.

        The end result is not an error because when the KeyError is caught the
        instance's ``message`` is used instead and this has the properly
        translated message. The only indication that something is wonky is a
        message in the warning log.
        """
        return self

    def _build_message(self, message, **kwargs):
        """Only returns detailed messages in insecure_debug mode."""
        if message and CONF.insecure_debug:
            if isinstance(message, str):
                # Only do replacement if message is string. The message is
                # sometimes a different exception or bytes, which would raise
                # TypeError.
                message = _format_with_unicode_kwargs(message, kwargs)
            return _('%(message)s %(amendment)s') % {
                'message': message,
                'amendment': self.amendment}

        return _format_with_unicode_kwargs(self.message_format, kwargs)


class Unauthorized(SecurityError):
    message_format = _("The request you have made requires authentication.")
    code = int(http.client.UNAUTHORIZED)
    title = http.client.responses[http.client.UNAUTHORIZED]


class InsufficientAuthMethods(Error):
    # NOTE(adriant): This is an internal only error that is built into
    # an auth receipt response.
    message_format = _("Insufficient auth methods received for %(user_id)s. "
                       "Auth Methods Provided: %(methods)s.")
    code = 401
    title = 'Unauthorized'

    def __init__(self, message=None, user_id=None, methods=None):
        methods_str = '[%s]' % ','.join(methods)
        super(InsufficientAuthMethods, self).__init__(
            message, user_id=user_id, methods=methods_str)

        self.user_id = user_id
        self.methods = methods


class ReceiptNotFound(Unauthorized):
    message_format = _("Could not find auth receipt: %(receipt_id)s.")


class PasswordExpired(Unauthorized):
    message_format = _("The password is expired and needs to be changed for "
                       "user: %(user_id)s.")


class AuthPluginException(Unauthorized):
    message_format = _("Authentication plugin error.")

    def __init__(self, *args, **kwargs):
        super(AuthPluginException, self).__init__(*args, **kwargs)
        self.authentication = {}


class UserDisabled(Unauthorized):
    message_format = _("The account is disabled for user: %(user_id)s.")


class AccountLocked(Unauthorized):
    message_format = _("The account is locked for user: %(user_id)s.")


class AuthMethodNotSupported(AuthPluginException):
    message_format = _("Attempted to authenticate with an unsupported method.")

    def __init__(self, *args, **kwargs):
        super(AuthMethodNotSupported, self).__init__(*args, **kwargs)
        self.authentication = {'methods': CONF.auth.methods}


class ApplicationCredentialAuthError(AuthPluginException):
    message_format = _(
        "Error authenticating with application credential: %(detail)s")


class AdditionalAuthRequired(AuthPluginException):
    message_format = _("Additional authentications steps required.")

    def __init__(self, auth_response=None, **kwargs):
        super(AdditionalAuthRequired, self).__init__(message=None, **kwargs)
        self.authentication = auth_response


class Forbidden(SecurityError):
    message_format = _("You are not authorized to perform the"
                       " requested action.")
    code = int(http.client.FORBIDDEN)
    title = http.client.responses[http.client.FORBIDDEN]


class ForbiddenAction(Forbidden):
    message_format = _("You are not authorized to perform the"
                       " requested action: %(action)s.")


class CrossBackendNotAllowed(Forbidden):
    message_format = _("Group membership across backend boundaries is not "
                       "allowed. Group in question is %(group_id)s, "
                       "user is %(user_id)s.")


class InvalidPolicyAssociation(Forbidden):
    message_format = _("Invalid mix of entities for policy association: "
                       "only Endpoint, Service, or Region+Service allowed. "
                       "Request was - Endpoint: %(endpoint_id)s, "
                       "Service: %(service_id)s, Region: %(region_id)s.")


class InvalidDomainConfig(Forbidden):
    message_format = _("Invalid domain specific configuration: %(reason)s.")


class InvalidLimit(Forbidden):
    message_format = _("Invalid resource limit: %(reason)s.")


class LimitTreeExceedError(Exception):
    def __init__(self, project_id, max_limit_depth):
        super(LimitTreeExceedError, self).__init__(_(
            "Keystone cannot start due to project hierarchical depth in the "
            "current deployment (project_ids: %(project_id)s) exceeds the "
            "enforcement model's maximum limit of %(max_limit_depth)s. Please "
            "use a different enforcement model to correct the issue."
        ) % {'project_id': project_id, 'max_limit_depth': max_limit_depth})


class NotFound(Error):
    message_format = _("Could not find: %(target)s.")
    code = int(http.client.NOT_FOUND)
    title = http.client.responses[http.client.NOT_FOUND]


class EndpointNotFound(NotFound):
    message_format = _("Could not find endpoint: %(endpoint_id)s.")


class PolicyNotFound(NotFound):
    message_format = _("Could not find policy: %(policy_id)s.")


class PolicyAssociationNotFound(NotFound):
    message_format = _("Could not find policy association.")


class RoleNotFound(NotFound):
    message_format = _("Could not find role: %(role_id)s.")


class ImpliedRoleNotFound(NotFound):
    message_format = _("%(prior_role_id)s does not imply %(implied_role_id)s.")


class InvalidImpliedRole(Forbidden):
    message_format = _("%(role_id)s cannot be an implied roles.")


class DomainSpecificRoleMismatch(Forbidden):
    message_format = _("Project %(project_id)s must be in the same domain "
                       "as the role %(role_id)s being assigned.")


class DomainSpecificRoleNotWithinIdPDomain(Forbidden):
    message_format = _("role: %(role_name)s must be within the same domain as "
                       "the identity provider: %(identity_provider)s.")


class DomainIdInvalid(ValidationError):
    message_format = _("Domain ID does not conform to required UUID format.")


class RoleAssignmentNotFound(NotFound):
    message_format = _("Could not find role assignment with role: "
                       "%(role_id)s, user or group: %(actor_id)s, "
                       "project, domain, or system: %(target_id)s.")


class RegionNotFound(NotFound):
    message_format = _("Could not find region: %(region_id)s.")


class ServiceNotFound(NotFound):
    message_format = _("Could not find service: %(service_id)s.")


class DomainNotFound(NotFound):
    message_format = _("Could not find domain: %(domain_id)s.")


class ProjectNotFound(NotFound):
    message_format = _("Could not find project: %(project_id)s.")


class ProjectTagNotFound(NotFound):
    message_format = _("Could not find project tag: %(project_tag)s.")


class TokenNotFound(NotFound):
    message_format = _("Could not find token: %(token_id)s.")


class UserNotFound(NotFound):
    message_format = _("Could not find user: %(user_id)s.")


class GroupNotFound(NotFound):
    message_format = _("Could not find group: %(group_id)s.")


class MappingNotFound(NotFound):
    message_format = _("Could not find mapping: %(mapping_id)s.")


class TrustNotFound(NotFound):
    message_format = _("Could not find trust: %(trust_id)s.")


class TrustUseLimitReached(Forbidden):
    message_format = _("No remaining uses for trust: %(trust_id)s.")


class CredentialNotFound(NotFound):
    message_format = _("Could not find credential: %(credential_id)s.")


class VersionNotFound(NotFound):
    message_format = _("Could not find version: %(version)s.")


class EndpointGroupNotFound(NotFound):
    message_format = _("Could not find Endpoint Group: %(endpoint_group_id)s.")


class IdentityProviderNotFound(NotFound):
    message_format = _("Could not find Identity Provider: %(idp_id)s.")


class ServiceProviderNotFound(NotFound):
    message_format = _("Could not find Service Provider: %(sp_id)s.")


class FederatedProtocolNotFound(NotFound):
    message_format = _("Could not find federated protocol %(protocol_id)s for"
                       " Identity Provider: %(idp_id)s.")


class PublicIDNotFound(NotFound):
    # This is used internally and mapped to either User/GroupNotFound or,
    # Assertion before the exception leaves Keystone.
    message_format = "%(id)s"


class RegisteredLimitNotFound(NotFound):
    message_format = _("Could not find registered limit for %(id)s.")


class LimitNotFound(NotFound):
    message_format = _("Could not find limit for %(id)s.")


class NoLimitReference(Forbidden):
    message_format = _("Unable to create a limit that has no corresponding "
                       "registered limit.")


class RegisteredLimitError(ForbiddenNotSecurity):
    message_format = _("Unable to update or delete registered limit %(id)s "
                       "because there are project limits associated with it.")


class DomainConfigNotFound(NotFound):
    message_format = _('Could not find %(group_or_option)s in domain '
                       'configuration for domain %(domain_id)s.')


class ConfigRegistrationNotFound(Exception):
    # This is used internally between the domain config backend and the
    # manager, so should not escape to the client.  If it did, it is a coding
    # error on our part, and would end up, appropriately, as a 500 error.
    pass


class ApplicationCredentialNotFound(NotFound):
    message_format = _("Could not find Application Credential: "
                       "%(application_credential_id)s.")


class AccessRuleNotFound(NotFound):
    message_format = _("Could not find Access Rule: %(access_rule_id)s.")


class Conflict(Error):
    message_format = _("Conflict occurred attempting to store %(type)s -"
                       " %(details)s.")
    code = int(http.client.CONFLICT)
    title = http.client.responses[http.client.CONFLICT]


class UnexpectedError(SecurityError):
    """Avoids exposing details of failures, unless in insecure_debug mode."""

    message_format = _("An unexpected error prevented the server "
                       "from fulfilling your request.")

    debug_message_format = _("An unexpected error prevented the server "
                             "from fulfilling your request: %(exception)s.")

    def _build_message(self, message, **kwargs):

        # Ensure that exception has a value to be extra defensive for
        # substitutions and make sure the exception doesn't raise an
        # exception.
        kwargs.setdefault('exception', '')

        return super(UnexpectedError, self)._build_message(
            message or self.debug_message_format, **kwargs)

    code = int(http.client.INTERNAL_SERVER_ERROR)
    title = http.client.responses[http.client.INTERNAL_SERVER_ERROR]


class TrustConsumeMaximumAttempt(UnexpectedError):
    debug_message_format = _("Unable to consume trust %(trust_id)s. Unable to "
                             "acquire lock.")


class MalformedEndpoint(UnexpectedError):
    debug_message_format = _("Malformed endpoint URL (%(endpoint)s),"
                             " see ERROR log for details.")


class MappedGroupNotFound(UnexpectedError):
    debug_message_format = _("Group %(group_id)s returned by mapping "
                             "%(mapping_id)s was not found in the backend.")


class MetadataFileError(UnexpectedError):
    debug_message_format = _("Error while reading metadata file: %(reason)s.")


class DirectMappingError(UnexpectedError):
    debug_message_format = _("Local section in mapping %(mapping_id)s refers "
                             "to a remote match that doesn't exist "
                             "(e.g. {0} in a local section).")


class AssignmentTypeCalculationError(UnexpectedError):
    debug_message_format = _(
        'Unexpected combination of grant attributes - '
        'User: %(user_id)s, Group: %(group_id)s, Project: %(project_id)s, '
        'Domain: %(domain_id)s.')


class NotImplemented(Error):
    message_format = _("The action you have requested has not"
                       " been implemented.")
    code = int(http.client.NOT_IMPLEMENTED)
    title = http.client.responses[http.client.NOT_IMPLEMENTED]


class Gone(Error):
    message_format = _("The service you have requested is no"
                       " longer available on this server.")
    code = int(http.client.GONE)
    title = http.client.responses[http.client.GONE]


class ConfigFileNotFound(UnexpectedError):
    debug_message_format = _("The Keystone configuration file %(config_file)s "
                             "could not be found.")


class KeysNotFound(UnexpectedError):
    debug_message_format = _('No encryption keys found; run keystone-manage '
                             'fernet_setup to bootstrap one.')


class MultipleSQLDriversInConfig(UnexpectedError):
    debug_message_format = _('The Keystone domain-specific configuration has '
                             'specified more than one SQL driver (only one is '
                             'permitted): %(source)s.')


class MigrationNotProvided(Exception):
    def __init__(self, mod_name, path):
        super(MigrationNotProvided, self).__init__(_(
            "%(mod_name)s doesn't provide database migrations. The migration"
            " repository path at %(path)s doesn't exist or isn't a directory."
        ) % {'mod_name': mod_name, 'path': path})


class UnsupportedTokenVersionException(UnexpectedError):
    debug_message_format = _('Token version is unrecognizable or '
                             'unsupported.')


class SAMLSigningError(UnexpectedError):
    debug_message_format = _('Unable to sign SAML assertion. It is likely '
                             'that this server does not have xmlsec1 '
                             'installed or this is the result of '
                             'misconfiguration. Reason %(reason)s.')


class OAuthHeadersMissingError(UnexpectedError):
    debug_message_format = _('No Authorization headers found, cannot proceed '
                             'with OAuth related calls. If running under '
                             'HTTPd or Apache, ensure WSGIPassAuthorization '
                             'is set to On.')


class TokenlessAuthConfigError(ValidationError):
    message_format = _('Could not determine Identity Provider ID. The '
                       'configuration option %(issuer_attribute)s '
                       'was not found in the request environment.')


class CredentialEncryptionError(Exception):
    message_format = _("An unexpected error prevented the server "
                       "from accessing encrypted credentials.")


class LDAPServerConnectionError(UnexpectedError):
    debug_message_format = _('Unable to establish a connection to '
                             'LDAP Server (%(url)s).')


class LDAPInvalidCredentialsError(UnexpectedError):
    message_format = _('Unable to authenticate against Identity backend - '
                       'Invalid username or password')


class LDAPSizeLimitExceeded(UnexpectedError):
    message_format = _('Number of User/Group entities returned by LDAP '
                       'exceeded size limit. Contact your LDAP '
                       'administrator.')


class CacheDeserializationError(Exception):

    def __init__(self, obj, data):
        super(CacheDeserializationError, self).__init__(
            _('Failed to deserialize %(obj)s. Data is %(data)s') % {
                'obj': obj, 'data': data
            }
        )


class ResourceUpdateForbidden(ForbiddenNotSecurity):
    message_format = _('Unable to update immutable %(type)s resource: '
                       '`%(resource_id)s. Set resource option "immutable" '
                       'to false first.')


class ResourceDeleteForbidden(ForbiddenNotSecurity):
    message_format = _('Unable to delete immutable %(type)s resource: '
                       '`%(resource_id)s. Set resource option "immutable" '
                       'to false first.')


class OAuth2Error(Error):

    def __init__(self, code, title, error_title, message):
        self.code = code
        self.title = title
        self.error_title = error_title
        self.message_format = message


class OAuth2InvalidClient(OAuth2Error):
    def __init__(self, code, title, message):
        error_title = 'invalid_client'
        super().__init__(code, title, error_title, message)


class OAuth2InvalidRequest(OAuth2Error):
    def __init__(self, code, title, message):
        error_title = 'invalid_request'
        super().__init__(code, title, error_title, message)


class OAuth2UnsupportedGrantType(OAuth2Error):
    def __init__(self, code, title, message):
        error_title = 'unsupported_grant_type'
        super().__init__(code, title, error_title, message)


class OAuth2OtherError(OAuth2Error):
    def __init__(self, code, title, message):
        error_title = 'other_error'
        super().__init__(code, title, error_title, message)

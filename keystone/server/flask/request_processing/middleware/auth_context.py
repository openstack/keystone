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


import functools
import itertools
import re
import wsgiref.util

import http.client
from keystonemiddleware import auth_token
import oslo_i18n
from oslo_log import log
from oslo_serialization import jsonutils
import webob.dec
import webob.exc

from keystone.common import authorization
from keystone.common import context
from keystone.common import provider_api
from keystone.common import render_token
from keystone.common import tokenless_auth
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils as federation_utils
from keystone.i18n import _
from keystone.models import token_model

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)
PROVIDERS = provider_api.ProviderAPIs

# Environment variable used to pass the request context
CONTEXT_ENV = 'openstack.context'

__all__ = ('AuthContextMiddleware',)


CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)


JSON_ENCODE_CONTENT_TYPES = set(['application/json',
                                 'application/json-home'])

# minimum access rules support
ACCESS_RULES_MIN_VERSION = token_model.ACCESS_RULES_MIN_VERSION


def best_match_language(req):
    """Determine the best available locale.

    This returns best available locale based on the Accept-Language HTTP
    header passed in the request.
    """
    if not req.accept_language:
        return None
    return req.accept_language.best_match(
        oslo_i18n.get_available_languages('keystone'))


def base_url(context):
    url = CONF['public_endpoint']

    if url:
        substitutions = dict(
            itertools.chain(CONF.items(), CONF.eventlet_server.items()))

        url = url % substitutions
    elif 'environment' in context:
        url = wsgiref.util.application_uri(context['environment'])
        # remove version from the URL as it may be part of SCRIPT_NAME but
        # it should not be part of base URL
        url = re.sub(r'/v(3|(2\.0))/*$', '', url)

        # now remove the standard port
        url = utils.remove_standard_port(url)
    else:
        # if we don't have enough information to come up with a base URL,
        # then fall back to localhost. This should never happen in
        # production environment.
        url = 'http://localhost:%d' % CONF.eventlet_server.public_port

    return url.rstrip('/')


def middleware_exceptions(method):

    @functools.wraps(method)
    def _inner(self, request):
        try:
            return method(self, request)
        except exception.Error as e:
            LOG.warning(e)
            return render_exception(e, request=request,
                                    user_locale=best_match_language(request))
        except TypeError as e:
            LOG.exception(e)
            return render_exception(exception.ValidationError(e),
                                    request=request,
                                    user_locale=best_match_language(request))
        except Exception as e:
            LOG.exception(e)
            return render_exception(exception.UnexpectedError(exception=e),
                                    request=request,
                                    user_locale=best_match_language(request))

    return _inner


def render_response(body=None, status=None, headers=None, method=None):
    """Form a WSGI response."""
    if headers is None:
        headers = []
    else:
        headers = list(headers)
    headers.append(('Vary', 'X-Auth-Token'))

    if body is None:
        body = b''
        status = status or (http.client.NO_CONTENT,
                            http.client.responses[http.client.NO_CONTENT])
    else:
        content_types = [v for h, v in headers if h == 'Content-Type']
        if content_types:
            content_type = content_types[0]
        else:
            content_type = None

        if content_type is None or content_type in JSON_ENCODE_CONTENT_TYPES:
            body = jsonutils.dump_as_bytes(body, cls=utils.SmarterEncoder)
            if content_type is None:
                headers.append(('Content-Type', 'application/json'))
        status = status or (http.client.OK,
                            http.client.responses[http.client.OK])

    # NOTE(davechen): `mod_wsgi` follows the standards from pep-3333 and
    # requires the value in response header to be binary type(str) on python2,
    # unicode based string(str) on python3, or else keystone will not work
    # under apache with `mod_wsgi`.
    # keystone needs to check the data type of each header and convert the
    # type if needed.
    # see bug:
    # https://bugs.launchpad.net/keystone/+bug/1528981
    # see pep-3333:
    # https://www.python.org/dev/peps/pep-3333/#a-note-on-string-types
    # see source from mod_wsgi:
    # https://github.com/GrahamDumpleton/mod_wsgi(methods:
    # wsgi_convert_headers_to_bytes(...), wsgi_convert_string_to_bytes(...)
    # and wsgi_validate_header_value(...)).
    def _convert_to_str(headers):
        str_headers = []
        for header in headers:
            str_header = []
            for value in header:
                if not isinstance(value, str):
                    str_header.append(str(value))
                else:
                    str_header.append(value)
            # convert the list to the immutable tuple to build the headers.
            # header's key/value will be guaranteed to be str type.
            str_headers.append(tuple(str_header))
        return str_headers

    headers = _convert_to_str(headers)

    resp = webob.Response(body=body,
                          status='%d %s' % status,
                          headerlist=headers,
                          charset='utf-8')

    if method and method.upper() == 'HEAD':
        # NOTE(morganfainberg): HEAD requests should return the same status
        # as a GET request and same headers (including content-type and
        # content-length). The webob.Response object automatically changes
        # content-length (and other headers) if the body is set to b''. Capture
        # all headers and reset them on the response object after clearing the
        # body. The body can only be set to a binary-type (not TextType or
        # NoneType), so b'' is used here and should be compatible with
        # both py2x and py3x.
        stored_headers = resp.headers.copy()
        resp.body = b''
        for header, value in stored_headers.items():
            resp.headers[header] = value

    return resp


def render_exception(error, context=None, request=None, user_locale=None):
    """Form a WSGI response based on the current error."""
    error_message = error.args[0]
    message = oslo_i18n.translate(error_message, desired_locale=user_locale)
    if message is error_message:
        # translate() didn't do anything because it wasn't a Message,
        # convert to a string.
        message = str(message)

    body = {'error': {
        'code': error.code,
        'title': error.title,
        'message': message,
    }}
    headers = []
    if isinstance(error, exception.AuthPluginException):
        body['error']['identity'] = error.authentication
    elif isinstance(error, exception.Unauthorized):
        # NOTE(gyee): we only care about the request environment in the
        # context. Also, its OK to pass the environment as it is read-only in
        # base_url()
        local_context = {}
        if request:
            local_context = {'environment': request.environ}
        elif context and 'environment' in context:
            local_context = {'environment': context['environment']}
        url = base_url(local_context)

        headers.append(('WWW-Authenticate', 'Keystone uri="%s"' % url))
    return render_response(status=(error.code, error.title),
                           body=body,
                           headers=headers)


class AuthContextMiddleware(provider_api.ProviderAPIMixin,
                            auth_token.BaseAuthProtocol):
    """Build the authentication context from the request auth token."""

    kwargs_to_fetch_token = True

    def __init__(self, app):
        super(AuthContextMiddleware, self).__init__(app, log=LOG,
                                                    service_type='identity')
        self.token = None

    def fetch_token(self, token, **kwargs):
        try:
            self.token = self.token_provider_api.validate_token(
                token, access_rules_support=ACCESS_RULES_MIN_VERSION)
            return render_token.render_token_response_from_model(self.token)
        except exception.TokenNotFound:
            raise auth_token.InvalidToken(_('Could not find token'))

    def _build_tokenless_auth_context(self, request):
        """Build the authentication context.

        The context is built from the attributes provided in the env,
        such as certificate and scope attributes.
        """
        tokenless_helper = tokenless_auth.TokenlessAuthHelper(request.environ)

        (domain_id, project_id, trust_ref, unscoped, system) = (
            tokenless_helper.get_scope())
        user_ref = tokenless_helper.get_mapped_user(
            project_id,
            domain_id)

        # NOTE(gyee): if it is an ephemeral user, the
        # given X.509 SSL client cert does not need to map to
        # an existing user.
        if user_ref['type'] == federation_utils.UserType.EPHEMERAL:
            auth_context = {}
            auth_context['group_ids'] = user_ref['group_ids']
            auth_context[federation_constants.IDENTITY_PROVIDER] = (
                user_ref[federation_constants.IDENTITY_PROVIDER])
            auth_context[federation_constants.PROTOCOL] = (
                user_ref[federation_constants.PROTOCOL])
            if domain_id and project_id:
                msg = _('Scoping to both domain and project is not allowed')
                raise ValueError(msg)
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = user_ref['roles']
        else:
            # it's the local user, so token data is needed.
            token = token_model.TokenModel()
            token.user_id = user_ref['id']
            token.methods = [CONF.tokenless_auth.protocol]
            token.domain_id = domain_id
            token.project_id = project_id

            auth_context = {'user_id': user_ref['id']}
            auth_context['is_delegated_auth'] = False
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = [role['name'] for role in token.roles]
        return auth_context

    def _validate_trusted_issuer(self, request):
        """To further filter the certificates that are trusted.

        If the config option 'trusted_issuer' is absent or does
        not contain the trusted issuer DN, no certificates
        will be allowed in tokenless authorization.

        :param env: The env contains the client issuer's attributes
        :type env: dict
        :returns: True if client_issuer is trusted; otherwise False
        """
        if not CONF.tokenless_auth.trusted_issuer:
            return False

        issuer = request.environ.get(CONF.tokenless_auth.issuer_attribute)
        if not issuer:
            msg = ('Cannot find client issuer in env by the '
                   'issuer attribute - %s.')
            LOG.info(msg, CONF.tokenless_auth.issuer_attribute)
            return False

        if issuer in CONF.tokenless_auth.trusted_issuer:
            return True

        msg = ('The client issuer %(client_issuer)s does not match with '
               'the trusted issuer %(trusted_issuer)s')
        LOG.info(
            msg, {'client_issuer': issuer,
                  'trusted_issuer': CONF.tokenless_auth.trusted_issuer})

        return False

    @middleware_exceptions
    def process_request(self, request):
        context_env = request.environ.get(CONTEXT_ENV, {})

        # NOTE(notmorgan): This code is merged over from the admin token
        # middleware and now emits the security warning when the
        # conf.admin_token value is set.
        token = request.headers.get(authorization.AUTH_TOKEN_HEADER)
        if CONF.admin_token and (token == CONF.admin_token):
            context_env['is_admin'] = True
            LOG.warning(
                "The use of the '[DEFAULT] admin_token' configuration"
                "option presents a significant security risk and should "
                "not be set. This option is deprecated in favor of using "
                "'keystone-manage bootstrap' and will be removed in a "
                "future release.")
            request.environ[CONTEXT_ENV] = context_env

        if not context_env.get('is_admin', False):
            resp = super(AuthContextMiddleware, self).process_request(request)

            if resp:
                return resp
            if request.token_auth.user is not None:
                request.set_user_headers(request.token_auth.user)

        # NOTE(jamielennox): function is split so testing can check errors from
        # fill_context. There is no actual reason for fill_context to raise
        # errors rather than return a resp, simply that this is what happened
        # before refactoring and it was easier to port. This can be fixed up
        # and the middleware_exceptions helper removed.
        self.fill_context(request)

    def _keystone_specific_values(self, token, request_context):
        request_context.token_reference = (
            render_token.render_token_response_from_model(token)
        )
        if token.domain_scoped:
            # Domain scoped tokens should never have is_admin_project set
            # Even if KSA defaults it otherwise.  The two mechanisms are
            # parallel; only one or the other should be used for access.
            request_context.is_admin_project = False
            request_context.domain_id = token.domain_id
            request_context.domain_name = token.domain['name']
        if token.oauth_scoped:
            request_context.is_delegated_auth = True
            request_context.oauth_consumer_id = (
                token.access_token['consumer_id']
            )
            request_context.oauth_access_token_id = token.access_token_id
        if token.trust_scoped:
            request_context.is_delegated_auth = True
            request_context.trust_id = token.trust_id
        if token.is_federated:
            request_context.group_ids = []
            for group in token.federated_groups:
                request_context.group_ids.append(group['id'])
        else:
            request_context.group_ids = []

    def fill_context(self, request):
        # The request context stores itself in thread-local memory for logging.

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = ('Auth context already exists in the request '
                   'environment; it will be used for authorization '
                   'instead of creating a new one.')
            LOG.warning(msg)
            return

        kwargs = {
            'authenticated': False,
            'overwrite': True}
        request_context = context.RequestContext.from_environ(
            request.environ, **kwargs)
        request.environ[context.REQUEST_CONTEXT_ENV] = request_context

        # NOTE(gyee): token takes precedence over SSL client certificates.
        # This will preserve backward compatibility with the existing
        # behavior. Tokenless authorization with X.509 SSL client
        # certificate is effectively disabled if no trusted issuers are
        # provided.

        if request.environ.get(CONTEXT_ENV, {}).get('is_admin', False):
            request_context.is_admin = True
            auth_context = {}

        elif request.token_auth.has_user_token:
            # Keystone enforces policy on some values that other services
            # do not, and should not, use.  This adds them in to the context.
            if not self.token:
                self.token = PROVIDERS.token_provider_api.validate_token(
                    request.user_token,
                    access_rules_support=request.headers.get(
                        authorization.ACCESS_RULES_HEADER)
                )
            self._keystone_specific_values(self.token, request_context)
            request_context.auth_token = request.user_token
            auth_context = request_context.to_policy_values()
            additional = {
                'trust_id': request_context.trust_id,
                'trustor_id': request_context.trustor_id,
                'trustee_id': request_context.trustee_id,
                'domain_id': request_context._domain_id,
                'domain_name': request_context.domain_name,
                'group_ids': request_context.group_ids,
                'token': self.token
            }
            auth_context.update(additional)

        elif self._validate_trusted_issuer(request):
            auth_context = self._build_tokenless_auth_context(request)
            # NOTE(gyee): we are no longer using auth_context when formulating
            # the credentials for RBAC. Instead, we are using the (Oslo)
            # request context. So we'll need to set all the necessary
            # credential attributes in the request context here.
            token_attributes = frozenset((
                'user_id', 'project_id',
                'domain_id', 'user_domain_id',
                'project_domain_id', 'user_domain_name',
                'project_domain_name', 'roles', 'is_admin',
                'project_name', 'domain_name', 'system_scope',
                'is_admin_project', 'service_user_id',
                'service_user_name', 'service_project_id',
                'service_project_name', 'service_user_domain_id'
                'service_user_domain_name', 'service_project_domain_id',
                'service_project_domain_name', 'service_roles'))
            for attr in token_attributes:
                if attr in auth_context:
                    setattr(request_context, attr, auth_context[attr])
            # NOTE(gyee): request_context.token_reference is always
            # expecting a 'token' key regardless. But in the case of X.509
            # tokenless auth, we don't need a token. So setting it to None
            # should be suffice.
            request_context.token_reference = {'token': None}
        else:
            # There is either no auth token in the request or the certificate
            # issuer is not trusted. No auth context will be set. This
            # typically happens on an initial token request.
            return

        # set authenticated to flag to keystone that a token has been validated
        request_context.authenticated = True

        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for loading in middleware (holdover from paste.deploy)."""
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory

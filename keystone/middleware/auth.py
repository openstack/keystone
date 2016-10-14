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

from keystonemiddleware import auth_token
from oslo_log import log

from keystone.common import authorization
from keystone.common import context
from keystone.common import dependency
from keystone.common import tokenless_auth
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.federation import constants as federation_constants
from keystone.federation import utils
from keystone.i18n import _, _LI, _LW
from keystone.middleware import core
from keystone.models import token_model
from keystone.token.providers import common

CONF = keystone.conf.CONF
LOG = log.getLogger(__name__)

__all__ = ('AuthContextMiddleware',)


@dependency.requires('token_provider_api')
class AuthContextMiddleware(auth_token.BaseAuthProtocol):
    """Build the authentication context from the request auth token."""

    kwargs_to_fetch_token = True

    def __init__(self, app):
        bind = CONF.token.enforce_token_bind
        super(AuthContextMiddleware, self).__init__(app,
                                                    log=LOG,
                                                    enforce_token_bind=bind)

    def fetch_token(self, token, **kwargs):
        try:
            return self.token_provider_api.validate_token(token)
        except exception.TokenNotFound:
            raise auth_token.InvalidToken(_('Could not find token'))

    def _build_tokenless_auth_context(self, request):
        """Build the authentication context.

        The context is built from the attributes provided in the env,
        such as certificate and scope attributes.
        """
        tokenless_helper = tokenless_auth.TokenlessAuthHelper(request.environ)

        (domain_id, project_id, trust_ref, unscoped) = (
            tokenless_helper.get_scope())
        user_ref = tokenless_helper.get_mapped_user(
            project_id,
            domain_id)

        # NOTE(gyee): if it is an ephemeral user, the
        # given X.509 SSL client cert does not need to map to
        # an existing user.
        if user_ref['type'] == utils.UserType.EPHEMERAL:
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
            token_helper = common.V3TokenDataHelper()
            token_data = token_helper.get_token_data(
                user_id=user_ref['id'],
                method_names=[CONF.tokenless_auth.protocol],
                domain_id=domain_id,
                project_id=project_id)

            auth_context = {'user_id': user_ref['id']}
            auth_context['is_delegated_auth'] = False
            if domain_id:
                auth_context['domain_id'] = domain_id
            if project_id:
                auth_context['project_id'] = project_id
            auth_context['roles'] = [role['name'] for role
                                     in token_data['token']['roles']]
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
            msg = _LI('Cannot find client issuer in env by the '
                      'issuer attribute - %s.')
            LOG.info(msg, CONF.tokenless_auth.issuer_attribute)
            return False

        if issuer in CONF.tokenless_auth.trusted_issuer:
            return True

        msg = _LI('The client issuer %(client_issuer)s does not match with '
                  'the trusted issuer %(trusted_issuer)s')
        LOG.info(
            msg, {'client_issuer': issuer,
                  'trusted_issuer': CONF.tokenless_auth.trusted_issuer})

        return False

    @wsgi.middleware_exceptions
    def process_request(self, request):
        context_env = request.environ.get(core.CONTEXT_ENV, {})
        if not context_env.get('is_admin', False):
            resp = super(AuthContextMiddleware, self).process_request(request)

            if resp:
                return resp

        # NOTE(jamielennox): function is split so testing can check errors from
        # fill_context. There is no actual reason for fill_context to raise
        # errors rather than return a resp, simply that this is what happened
        # before refactoring and it was easier to port. This can be fixed up
        # and the middleware_exceptions helper removed.
        self.fill_context(request)

    def fill_context(self, request):
        # The request context stores itself in thread-local memory for logging.
        request_context = context.RequestContext(
            request_id=request.environ.get('openstack.request_id'),
            authenticated=False,
            overwrite=True)
        request.environ[context.REQUEST_CONTEXT_ENV] = request_context

        if authorization.AUTH_CONTEXT_ENV in request.environ:
            msg = _LW('Auth context already exists in the request '
                      'environment; it will be used for authorization '
                      'instead of creating a new one.')
            LOG.warning(msg)
            return

        # NOTE(gyee): token takes precedence over SSL client certificates.
        # This will preserve backward compatibility with the existing
        # behavior. Tokenless authorization with X.509 SSL client
        # certificate is effectively disabled if no trusted issuers are
        # provided.

        if request.environ.get(core.CONTEXT_ENV, {}).get('is_admin', False):
            request_context.is_admin = True
            auth_context = {}

        elif request.token_auth.has_user_token:
            request_context.auth_token = request.user_token
            ref = token_model.KeystoneToken(token_id=request.user_token,
                                            token_data=request.token_info)
            auth_context = authorization.token_to_auth_context(ref)

        elif self._validate_trusted_issuer(request):
            auth_context = self._build_tokenless_auth_context(request)

        else:
            LOG.debug('There is either no auth token in the request or '
                      'the certificate issuer is not trusted. No auth '
                      'context will be set.')
            return

        # set authenticated to flag to keystone that a token has been validated
        request_context.authenticated = True

        # The attributes of request_context are put into the logs. This is a
        # common pattern for all the OpenStack services. In all the other
        # projects these are IDs, so set the attributes to IDs here rather than
        # the name.
        request_context.user_id = auth_context.get('user_id')
        request_context.project_id = auth_context.get('project_id')
        request_context.domain_id = auth_context.get('domain_id')
        request_context.domain_name = auth_context.get('domain_name')
        request_context.user_domain_id = auth_context.get('user_domain_id')
        request_context.roles = auth_context.get('roles')

        is_admin_project = auth_context.get('is_admin_project', True)
        request_context.is_admin_project = is_admin_project

        project_domain_id = auth_context.get('project_domain_id')
        request_context.project_domain_id = project_domain_id

        is_delegated_auth = auth_context.get('is_delegated_auth', False)
        request_context.is_delegated_auth = is_delegated_auth

        request_context.trust_id = auth_context.get('trust_id')
        request_context.trustor_id = auth_context.get('trustor_id')
        request_context.trustee_id = auth_context.get('trustee_id')

        access_token_id = auth_context.get('access_token_id')
        request_context.oauth_consumer_id = auth_context.get('consumer_id')
        request_context.oauth_acess_token_id = access_token_id

        LOG.debug('RBAC: auth_context: %s', auth_context)
        request.environ[authorization.AUTH_CONTEXT_ENV] = auth_context

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = keystone.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import keystone.analytics
            keystone.analytics.Analytics(app, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            conf = global_config.copy()
            conf.update(local_config)
            return cls(app, **local_config)
        return _factory

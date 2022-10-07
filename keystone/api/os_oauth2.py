# Copyright 2022 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import flask
from flask import make_response
import http.client
from oslo_log import log
from oslo_serialization import jsonutils

from keystone.api._shared import authentication
from keystone.api._shared import json_home_relations
from keystone.common import provider_api
from keystone.common import utils
from keystone.conf import CONF
from keystone import exception
from keystone.federation import utils as federation_utils
from keystone.i18n import _
from keystone.server import flask as ks_flask

LOG = log.getLogger(__name__)

PROVIDERS = provider_api.ProviderAPIs

_build_resource_relation = json_home_relations.os_oauth2_resource_rel_func


class AccessTokenResource(ks_flask.ResourceBase):

    def _method_not_allowed(self):
        """Raise a method not allowed error."""
        raise exception.OAuth2OtherError(
            int(http.client.METHOD_NOT_ALLOWED),
            http.client.responses[http.client.METHOD_NOT_ALLOWED],
            _('The method is not allowed for the requested URL.'))

    @ks_flask.unenforced_api
    def get(self):
        """The method is not allowed."""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def head(self):
        """The method is not allowed."""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def put(self):
        """The method is not allowed."""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def patch(self):
        """The method is not allowed."""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def delete(self):
        """The method is not allowed."""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def post(self):
        """Get an OAuth2.0 Access Token.

        POST /v3/OS-OAUTH2/token
        """
        grant_type = flask.request.form.get('grant_type')
        if grant_type is None:
            error = exception.OAuth2InvalidRequest(
                int(http.client.BAD_REQUEST),
                http.client.responses[http.client.BAD_REQUEST],
                _('The parameter grant_type is required.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     f'{error.message_format}')
            raise error
        if grant_type != 'client_credentials':
            error = exception.OAuth2UnsupportedGrantType(
                int(http.client.BAD_REQUEST),
                http.client.responses[http.client.BAD_REQUEST],
                _('The parameter grant_type %s is not supported.'
                  ) % grant_type)
            LOG.info('Get OAuth2.0 Access Token API: '
                     f'{error.message_format}')
            raise error

        auth_method = ''
        client_id = flask.request.form.get('client_id')
        client_secret = flask.request.form.get('client_secret')
        client_cert = flask.request.environ.get("SSL_CLIENT_CERT")
        client_auth = flask.request.authorization
        if not client_cert and client_auth and client_auth.type == 'basic':
            client_id = client_auth.username
            client_secret = client_auth.password

        if not client_id:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'failed to get a client_id from the request.')
            raise error
        if client_cert:
            auth_method = 'tls_client_auth'
        elif client_secret:
            auth_method = 'client_secret_basic'

        if auth_method in CONF.oauth2.oauth2_authn_methods:
            if auth_method == 'tls_client_auth':
                return self._tls_client_auth(client_id, client_cert)
            if auth_method == 'client_secret_basic':
                return self._client_secret_basic(client_id, client_secret)

        error = exception.OAuth2InvalidClient(
            int(http.client.UNAUTHORIZED),
            http.client.responses[http.client.UNAUTHORIZED],
            _('Client authentication failed.'))
        LOG.info('Get OAuth2.0 Access Token API: '
                 'failed to get client credentials from the request.')
        raise error

    def _client_secret_basic(self, client_id, client_secret):
        """Get an OAuth2.0 basic Access Token."""
        auth_data = {
            'identity': {
                'methods': ['application_credential'],
                'application_credential': {
                    'id': client_id,
                    'secret': client_secret
                }
            }
        }
        try:
            token = authentication.authenticate_for_token(auth_data)
        except exception.Error as error:
            if error.code == 401:
                error = exception.OAuth2InvalidClient(
                    error.code, error.title,
                    str(error))
            elif error.code == 400:
                error = exception.OAuth2InvalidRequest(
                    error.code, error.title,
                    str(error))
            else:
                error = exception.OAuth2OtherError(
                    error.code, error.title,
                    'An unknown error occurred and failed to get an OAuth2.0 '
                    'access token.')
            LOG.exception(error)
            raise error
        except Exception as error:
            error = exception.OAuth2OtherError(
                int(http.client.INTERNAL_SERVER_ERROR),
                http.client.responses[http.client.INTERNAL_SERVER_ERROR],
                str(error))
            LOG.exception(error)
            raise error

        resp = make_response({
            'access_token': token.id,
            'token_type': 'Bearer',
            'expires_in': CONF.token.expiration
        })
        resp.status = '200 OK'
        return resp

    def _check_mapped_properties(self, cert_dn, user, user_domain):
        mapping_id = CONF.oauth2.get('oauth2_cert_dn_mapping_id')
        try:
            mapping = PROVIDERS.federation_api.get_mapping(mapping_id)
        except exception.MappingNotFound:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'mapping id %s is not found. ',
                     mapping_id)
            raise error

        rule_processor = federation_utils.RuleProcessor(
            mapping.get('id'), mapping.get('rules'))
        try:
            mapped_properties = rule_processor.process(cert_dn)
        except exception.Error as error:
            LOG.exception(error)
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'mapping rule process failed. '
                     'mapping_id: %s, rules: %s, data: %s.',
                     mapping_id, mapping.get('rules'),
                     jsonutils.dumps(cert_dn))
            raise error
        except Exception as error:
            LOG.exception(error)
            error = exception.OAuth2OtherError(
                int(http.client.INTERNAL_SERVER_ERROR),
                http.client.responses[http.client.INTERNAL_SERVER_ERROR],
                str(error))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'mapping rule process failed. '
                     'mapping_id: %s, rules: %s, data: %s.',
                     mapping_id, mapping.get('rules'),
                     jsonutils.dumps(cert_dn))
            raise error

        mapping_user = mapped_properties.get('user', {})
        mapping_user_name = mapping_user.get('name')
        mapping_user_id = mapping_user.get('id')
        mapping_user_email = mapping_user.get('email')
        mapping_domain = mapping_user.get('domain', {})
        mapping_user_domain_id = mapping_domain.get('id')
        mapping_user_domain_name = mapping_domain.get('name')
        if mapping_user_name and mapping_user_name != user.get('name'):
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: %s check failed. '
                     'DN value: %s, DB value: %s.',
                     'user name', mapping_user_name, user.get('name'))
            raise error
        if mapping_user_id and mapping_user_id != user.get('id'):
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: %s check failed. '
                     'DN value: %s, DB value: %s.',
                     'user id', mapping_user_id, user.get('id'))
            raise error
        if mapping_user_email and mapping_user_email != user.get('email'):
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: %s check failed. '
                     'DN value: %s, DB value: %s.',
                     'user email', mapping_user_email, user.get('email'))
            raise error
        if (mapping_user_domain_id and
                mapping_user_domain_id != user_domain.get('id')):
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: %s check failed. '
                     'DN value: %s, DB value: %s.',
                     'user domain id', mapping_user_domain_id,
                     user_domain.get('id'))
            raise error
        if (mapping_user_domain_name and
                mapping_user_domain_name != user_domain.get('name')):
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: %s check failed. '
                     'DN value: %s, DB value: %s.',
                     'user domain name', mapping_user_domain_name,
                     user_domain.get('name'))
            raise error

    def _tls_client_auth(self, client_id, client_cert):
        """Get an OAuth2.0 certificate-bound Access Token."""
        try:
            cert_subject_dn = utils.get_certificate_subject_dn(client_cert)
        except exception.ValidationError:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'failed to get the subject DN from the certificate.')
            raise error
        try:
            cert_issuer_dn = utils.get_certificate_issuer_dn(client_cert)
        except exception.ValidationError:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'failed to get the issuer DN from the certificate.')
            raise error
        client_cert_dn = {}
        for key in cert_subject_dn:
            client_cert_dn['SSL_CLIENT_SUBJECT_DN_%s' %
                           key.upper()] = cert_subject_dn.get(key)
        for key in cert_issuer_dn:
            client_cert_dn['SSL_CLIENT_ISSUER_DN_%s' %
                           key.upper()] = cert_issuer_dn.get(key)

        try:
            user = PROVIDERS.identity_api.get_user(client_id)
        except exception.UserNotFound:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'the user does not exist. user id: %s.',
                     client_id)
            raise error
        project_id = user.get('default_project_id')
        if not project_id:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('Client authentication failed.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'the user does not have default project. user id: %s.',
                     client_id)
            raise error

        user_domain = PROVIDERS.resource_api.get_domain(
            user.get('domain_id'))
        self._check_mapped_properties(client_cert_dn, user, user_domain)
        thumbprint = utils.get_certificate_thumbprint(client_cert)
        LOG.debug(f'The mTLS certificate thumbprint: {thumbprint}')
        try:
            token = PROVIDERS.token_provider_api.issue_token(
                user_id=client_id,
                method_names=['oauth2_credential'],
                project_id=project_id,
                thumbprint=thumbprint
            )
        except exception.Error as error:
            if error.code == 401:
                error = exception.OAuth2InvalidClient(
                    error.code, error.title,
                    str(error))
            elif error.code == 400:
                error = exception.OAuth2InvalidRequest(
                    error.code, error.title,
                    str(error))
            else:
                error = exception.OAuth2OtherError(
                    error.code, error.title,
                    'An unknown error occurred and failed to get an OAuth2.0 '
                    'access token.')
            LOG.exception(error)
            raise error
        except Exception as error:
            error = exception.OAuth2OtherError(
                int(http.client.INTERNAL_SERVER_ERROR),
                http.client.responses[http.client.INTERNAL_SERVER_ERROR],
                str(error))
            LOG.exception(error)
            raise error

        resp = make_response({
            'access_token': token.id,
            'token_type': 'Bearer',
            'expires_in': CONF.token.expiration
        })
        resp.status = '200 OK'
        return resp


class OSAuth2API(ks_flask.APIBase):
    _name = 'OS-OAUTH2'
    _import_name = __name__
    _api_url_prefix = '/OS-OAUTH2'

    resource_mapping = [
        ks_flask.construct_resource_map(
            resource=AccessTokenResource,
            url='/token',
            rel='token',
            resource_kwargs={},
            resource_relation_func=_build_resource_relation
        )]


APIs = (OSAuth2API,)

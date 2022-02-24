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

from keystone.api._shared import authentication
from keystone.api._shared import json_home_relations
from keystone.conf import CONF
from keystone import exception
from keystone.i18n import _
from keystone.server import flask as ks_flask

LOG = log.getLogger(__name__)

_build_resource_relation = json_home_relations.os_oauth2_resource_rel_func


class AccessTokenResource(ks_flask.ResourceBase):

    def _method_not_allowed(self):
        """Raise a method not allowed error"""
        raise exception.OAuth2OtherError(
            int(http.client.METHOD_NOT_ALLOWED),
            http.client.responses[http.client.METHOD_NOT_ALLOWED],
            _('The method is not allowed for the requested URL.'))

    @ks_flask.unenforced_api
    def get(self):
        """The method is not allowed"""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def head(self):
        """The method is not allowed"""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def put(self):
        """The method is not allowed"""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def patch(self):
        """The method is not allowed"""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def delete(self):
        """The method is not allowed"""
        self._method_not_allowed()

    @ks_flask.unenforced_api
    def post(self):
        """Get an OAuth2.0 Access Token.

        POST /v3/OS-OAUTH2/token
        """

        client_auth = flask.request.authorization
        if not client_auth:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('OAuth2.0 client authorization is required.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'field \'authorization\' is not found in HTTP Headers.')
            raise error
        if client_auth.type != 'basic':
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('OAuth2.0 client authorization type %s is not supported.')
                % client_auth.type)
            LOG.info('Get OAuth2.0 Access Token API: '
                     f'{error.message_format}')
            raise error
        client_id = client_auth.username
        client_secret = client_auth.password

        if not client_id:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('OAuth2.0 client authorization is invalid.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'client_id is not found in authorization.')
            raise error
        if not client_secret:
            error = exception.OAuth2InvalidClient(
                int(http.client.UNAUTHORIZED),
                http.client.responses[http.client.UNAUTHORIZED],
                _('OAuth2.0 client authorization is invalid.'))
            LOG.info('Get OAuth2.0 Access Token API: '
                     'client_secret is not found in authorization.')
            raise error

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

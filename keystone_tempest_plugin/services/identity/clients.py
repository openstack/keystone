# Copyright 2016 Red Hat, Inc.
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

import json

import six
from six.moves import http_client
from tempest import config
from tempest.lib.common import rest_client


CONF = config.CONF

# We only use the identity catalog type
SERVICE_TYPE = 'identity'


class Identity(rest_client.RestClient):
    """Tempest REST client for keystone."""

    # Used by the superclass to build the correct URL paths
    api_version = 'v3'

    def __init__(self, auth_provider):
        super(Identity, self).__init__(
            auth_provider,
            SERVICE_TYPE,
            CONF.identity.region,
            endpoint_type='adminURL')


class Federation(Identity):
    """Tempest REST client for keystone's Federated Identity API."""

    subpath_prefix = 'OS-FEDERATION'
    subpath_suffix = None

    def _build_path(self, entity_id=None):
        subpath = '%s/%s' % (self.subpath_prefix, self.subpath_suffix)
        return '%s/%s' % (subpath, entity_id) if entity_id else subpath

    def _delete(self, entity_id, **kwargs):
        url = self._build_path(entity_id)
        resp, body = super(Federation, self).delete(url, **kwargs)
        self.expected_success(http_client.NO_CONTENT, resp.status)
        return rest_client.ResponseBody(resp, body)

    def _get(self, entity_id=None, **kwargs):
        url = self._build_path(entity_id)
        resp, body = super(Federation, self).get(url, **kwargs)
        self.expected_success(http_client.OK, resp.status)
        body = json.loads(body if six.PY2 else body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def _patch(self, entity_id, body, **kwargs):
        url = self._build_path(entity_id)
        resp, body = super(Federation, self).patch(url, body, **kwargs)
        self.expected_success(http_client.OK, resp.status)
        body = json.loads(body if six.PY2 else body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

    def _put(self, entity_id, body, **kwargs):
        url = self._build_path(entity_id)
        resp, body = super(Federation, self).put(url, body, **kwargs)
        self.expected_success(http_client.CREATED, resp.status)
        body = json.loads(body if six.PY2 else body.decode('utf-8'))
        return rest_client.ResponseBody(resp, body)

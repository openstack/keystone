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

from tempest.lib.common import rest_client

from keystone_tempest_plugin.services.identity import clients


class IdentityProvidersClient(clients.Federation):

    subpath_suffix = 'identity_providers'

    def create_identity_provider(self, idp_id, **kwargs):
        """Create an identity provider.

        :param str idp_id: The ID to be used to create the Identity Provider.
        :param kwargs: All optional attributes: description (str), enabled
                       (boolean) and remote_ids (list).
        """
        put_body = json.dumps({'identity_provider': kwargs})
        resp, body = self._put(idp_id, put_body)
        self.expected_success(201, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

    def list_identity_providers(self):
        """List the identity providers."""
        resp, body = self._get()
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

    def show_identity_provider(self, idp_id):
        """Get an identity provider."""
        resp, body = self._get(idp_id)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

    def delete_identity_provider(self, idp_id):
        """Delete an identity provider."""
        resp, body = self._delete(idp_id)
        self.expected_success(204, resp.status)
        return rest_client.ResponseBody(resp, body)

    def update_identity_provider(self, idp_id, **kwargs):
        """Update an identity provider.

        :param str idp_id: The ID from the Identity Provider to be updated.
        :param kwargs: All optional attributes to update: description (str),
                       enabled (boolean) and remote_ids (list).
        """
        patch_body = json.dumps({'identity_provider': kwargs})
        resp, body = self._patch(idp_id, patch_body)
        self.expected_success(200, resp.status)
        body = json.loads(body)
        return rest_client.ResponseBody(resp, body)

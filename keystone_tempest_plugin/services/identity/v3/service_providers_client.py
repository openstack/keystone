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

from keystone_tempest_plugin.services.identity import clients


class ServiceProvidersClient(clients.Federation):

    subpath_suffix = 'service_providers'

    def create_service_provider(self, sp_id, **kwargs):
        """Create a service provider.

        :param str sp_id: The ID to be used to create the Service Provider.
        :param kwargs: Extra attributes. Mandatory: auth_url (str) and sp_url
                       (str). Optional: description (str), enabled (boolean)
                       and relay_state_prefix (str).
        """
        put_body = json.dumps({'service_provider': kwargs})
        return self._put(sp_id, put_body)

    def list_service_providers(self):
        """List the service providers."""
        return self._get()

    def show_service_provider(self, sp_id):
        """Get a service provider."""
        return self._get(sp_id)

    def delete_service_provider(self, sp_id):
        """Delete a service provider."""
        return self._delete(sp_id)

    def update_service_provider(self, sp_id, **kwargs):
        """Update a service provider.

        :param str sp_id: The ID of the Service Provider to be updated.
        :param kwargs: All attributes to be updated: auth_url (str) and sp_url
                       (str), description (str), enabled (boolean) and
                       relay_state_prefix (str).
        """
        patch_body = json.dumps({'service_provider': kwargs})
        return self._patch(sp_id, patch_body)

    def get_service_providers_in_token(self):
        """Get the service providers list present in the token.

        Only enabled service providers are displayed in the token.
        """
        # First we force the auth_data update via the set_auth() command
        # in the auth_provider
        self.auth_provider.set_auth()

        # Now we can retrieve the updated auth_data
        auth_data = self.auth_provider.get_auth()[1]
        try:
            return auth_data['service_providers']
        except KeyError:
            # no service providers in token
            return []

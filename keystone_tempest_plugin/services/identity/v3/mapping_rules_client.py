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


class MappingRulesClient(clients.Federation):

    subpath_suffix = 'mappings'

    def create_mapping_rule(self, mapping_id, rules):
        """Create a mapping rule."""
        put_body = json.dumps({'mapping': rules})
        return self._put(mapping_id, put_body)

    def list_mapping_rules(self):
        """List the mapping rules."""
        return self._get()

    def show_mapping_rule(self, mapping_id):
        """Get a mapping rule."""
        return self._get(mapping_id)

    def delete_mapping_rule(self, mapping_id):
        """Delete a mapping rule."""
        return self._delete(mapping_id)

    def update_mapping_rule(self, mapping_id, rules):
        """Update a mapping rule."""
        patch_body = json.dumps({'mapping': rules})
        return self._patch(mapping_id, patch_body)

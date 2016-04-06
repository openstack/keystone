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

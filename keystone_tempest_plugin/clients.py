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

from keystone_tempest_plugin.services.identity.v3 import (
    identity_providers_client)

from tempest import clients


class Manager(clients.Manager):

    def __init__(self, credentials, service=None):
        super(Manager, self).__init__(credentials, service)

        self.identity_providers_client = (
            identity_providers_client.IdentityProvidersClient(
                self.auth_provider))

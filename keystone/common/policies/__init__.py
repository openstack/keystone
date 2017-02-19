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

import itertools

from keystone.common.policies import base
from keystone.common.policies import credential
from keystone.common.policies import domain
from keystone.common.policies import ec2_credential
from keystone.common.policies import endpoint
from keystone.common.policies import group
from keystone.common.policies import project
from keystone.common.policies import region
from keystone.common.policies import service
from keystone.common.policies import user


def list_rules():
    return itertools.chain(
        base.list_rules(),
        credential.list_rules(),
        domain.list_rules(),
        ec2_credential.list_rules(),
        endpoint.list_rules(),
        group.list_rules(),
        project.list_rules(),
        region.list_rules(),
        service.list_rules(),
        user.list_rules(),
    )

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

# NOTE(morgan): This module contains json_home partial functions for
# what were called "extensions" before. As keystone does not have extensions
# any longer, once Keystone is converted to flask fully, there should be no
# reason to add more elements to this module.

import functools

from keystone.common import json_home

# OS-EC2 "extension"
os_ec2_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-EC2', extension_version='1.0')

# s3token "extension"
s3_token_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='s3tokens', extension_version='1.0')

# OS-EP-FILTER "extension"
os_ep_filter_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-EP-FILTER', extension_version='1.0')
os_ep_filter_parameter_rel_func = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-EP-FILTER', extension_version='1.0')

# OS-OAUTH1 "extension"
os_oauth1_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-OAUTH1', extension_version='1.0')
os_oauth1_parameter_rel_func = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-OAUTH1', extension_version='1.0')

# OS-OAUTH2 "extension"
os_oauth2_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-OAUTH2', extension_version='1.0')
os_oauth2_parameter_rel_func = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-OAUTH2', extension_version='1.0')

# OS-REVOKE "extension"
os_revoke_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-REVOKE', extension_version='1.0')

# OS-SIMPLE-CERT "extension"
os_simple_cert_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-SIMPLE-CERT', extension_version='1.0')

# OS-TRUST "extension"
os_trust_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation, extension_name='OS-TRUST',
    extension_version='1.0')
os_trust_parameter_rel_func = functools.partial(
    json_home.build_v3_extension_parameter_relation, extension_name='OS-TRUST',
    extension_version='1.0')

# OS-ENDPOINT-POLICY "extension"
os_endpoint_policy_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-ENDPOINT-POLICY', extension_version='1.0')

# OS-FEDERATION "extension"
os_federation_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')
os_federation_parameter_rel_func = functools.partial(
    json_home.build_v3_extension_parameter_relation,
    extension_name='OS-FEDERATION', extension_version='1.0')

# OS-INHERIT "extension"
os_inherit_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-INHERIT', extension_version='1.0')

# OS-PKI (revoked) "extension"
os_pki_resource_rel_func = functools.partial(
    json_home.build_v3_extension_resource_relation,
    extension_name='OS-PKI', extension_version='1.0')

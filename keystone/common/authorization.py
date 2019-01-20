# Copyright 2012 OpenStack Foundation
# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 - 2012 Justin Santa Barbara
# All Rights Reserved.
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

# A couple common constants for Auth data

# Header used to transmit the auth token
AUTH_TOKEN_HEADER = 'X-Auth-Token'  # nosec


# Header used to transmit the auth receipt
AUTH_RECEIPT_HEADER = 'Openstack-Auth-Receipt'


# Header used to transmit the subject token
SUBJECT_TOKEN_HEADER = 'X-Subject-Token'  # nosec

# Environment variable used to convey the Keystone auth context,
# the user credential used for policy enforcement.
AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'

# Header set by versions of keystonemiddleware that understand application
# credential access rules
ACCESS_RULES_HEADER = 'OpenStack-Identity-Access-Rules'

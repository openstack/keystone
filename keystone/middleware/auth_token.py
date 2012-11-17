# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010-2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
The actual code for auth_token has now been moved python-keystoneclient.  It is
imported back here to ensure backward combatibility for old paste.ini files
that might still refer to here as opposed to keystoneclient
"""

from keystoneclient.middleware import auth_token as client_auth_token

will_expire_soon = client_auth_token.will_expire_soon
InvalidUserToken = client_auth_token.InvalidUserToken
ServiceError = client_auth_token.ServiceError
ConfigurationError = client_auth_token.ConfigurationError
AuthProtocol = client_auth_token.AuthProtocol

filter_factory = client_auth_token.filter_factory
app_factory = client_auth_token.app_factory

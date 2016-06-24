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
"""Constants for use in the keystone.conf package.

These constants are shared by more than one module in the keystone.conf
package.

"""

from keystone.conf import utils


_DEFAULT_AUTH_METHODS = ['external', 'password', 'token', 'oauth1']

_CERTFILE = '/etc/keystone/ssl/certs/signing_cert.pem'
_KEYFILE = '/etc/keystone/ssl/private/signing_key.pem'

_DEPRECATE_PKI_MSG = utils.fmt("""
PKI token support has been deprecated in the M release and will be removed in
the O release. Fernet or UUID tokens are recommended.
""")

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

# Shared primary-vs-delegated auth method classification, used by
# keystone.api.trusts, keystone.api.os_oauth1, keystone.api.users,
# keystone.api.credentials, and keystone.auth.plugins.token to guard
# sensitive actions (managing trusts, OAuth1 access tokens, application
# credentials, or another user's credentials; exchanging a token for
# another token) against delegated-token abuse. See LP#2153453,
# LP#2158538, LP#2159643.

import keystone.conf

CONF = keystone.conf.CONF

# Auth methods that authenticate a user directly. Anything else --
# a delegated credential (application_credential, oauth1, ec2credential,
# oauth2_credential) or a future, not-yet-reviewed delegated method -- is
# treated as delegated by default and rejected from the sensitive actions
# this module's callers guard. This is a deny-by-default allowlist, not a
# denylist of specific known-bad methods: a new delegated method nobody
# has reviewed yet must be blocked automatically, not silently allowed
# through until someone remembers to add it to a denylist.
_BUILTIN_PRIMARY_AUTH_METHODS = frozenset(
    {
        'external',
        'kerberos',
        'mapped',
        'openid',
        'password',
        'saml2',
        'token',
        'totp',
        'x509',
    }
)


def primary_auth_methods():
    """The effective set of primary (non-delegated) auth methods.

    Operators running a custom, third-party auth plugin (e.g. a
    site-specific SSO integration) can list its method name in
    [auth] additional_primary_auth_methods so tokens issued through it
    are not mistaken for a delegated credential by the guards in this
    module's callers.
    """
    return _BUILTIN_PRIMARY_AUTH_METHODS | frozenset(
        CONF.auth.additional_primary_auth_methods
    )


def is_delegated_method(token):
    """Return True if token.methods indicates a delegated credential.

    An empty methods list is treated as delegated, not allowed: a token
    whose methods were lost on a fernet round-trip (e.g.
    ec2credential/oauth2_credential decoding to []) must not be treated
    as if it had no delegated methods at all -- issuperset([]) is True.
    """
    return bool(token) and (
        not token.methods
        or not primary_auth_methods().issuperset(token.methods)
    )

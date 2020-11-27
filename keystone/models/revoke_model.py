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

from oslo_log import log
from oslo_serialization import msgpackutils
from oslo_utils import timeutils

from keystone.common import cache
from keystone.common import utils


LOG = log.getLogger(__name__)

# The set of attributes common between the RevokeEvent
# and the dictionaries created from the token Data.
_NAMES = ['trust_id',
          'consumer_id',
          'access_token_id',
          'audit_id',
          'audit_chain_id',
          'expires_at',
          'domain_id',
          'project_id',
          'user_id',
          'role_id']


# Additional arguments for creating a RevokeEvent
_EVENT_ARGS = ['issued_before', 'revoked_at']

# Names of attributes in the RevocationEvent, including "virtual" attributes.
# Virtual attributes are those added based on other values.
_EVENT_NAMES = _NAMES + ['domain_scope_id']

# Values that will be in the token data but not in the event.
# These will compared with event values that have different names.
# For example: both trustor_id and trustee_id are compared against user_id
_TOKEN_KEYS = ['identity_domain_id',
               'assignment_domain_id',
               'issued_at',
               'trustor_id',
               'trustee_id']

# Alternative names to be checked in token for every field in
# revoke tree.
ALTERNATIVES = {
    'user_id': ['user_id', 'trustor_id', 'trustee_id'],
    'domain_id': ['identity_domain_id', 'assignment_domain_id'],
    # For a domain-scoped token, the domain is in assignment_domain_id.
    'domain_scope_id': ['assignment_domain_id', ],
}


REVOKE_KEYS = _NAMES + _EVENT_ARGS


def blank_token_data(issued_at):
    token_data = dict()
    for name in _NAMES:
        token_data[name] = None
    for name in _TOKEN_KEYS:
        token_data[name] = None
    # required field
    token_data['issued_at'] = issued_at
    return token_data


class RevokeEvent(object):
    def __init__(self, **kwargs):
        for k in REVOKE_KEYS:
            v = kwargs.get(k)
            setattr(self, k, v)

        if self.domain_id and self.expires_at:
            # This is revoking a domain-scoped token.
            self.domain_scope_id = self.domain_id
            self.domain_id = None
        else:
            # This is revoking all tokens for a domain.
            self.domain_scope_id = None

        if self.expires_at is not None:
            # Trim off the expiration time because MySQL timestamps are only
            # accurate to the second.
            self.expires_at = self.expires_at.replace(microsecond=0)

        if self.revoked_at is None:
            self.revoked_at = timeutils.utcnow().replace(microsecond=0)
        if self.issued_before is None:
            self.issued_before = self.revoked_at

    def to_dict(self):
        keys = ['user_id',
                'role_id',
                'domain_id',
                'domain_scope_id',
                'project_id',
                'audit_id',
                'audit_chain_id',
                ]
        event = {key: self.__dict__[key] for key in keys
                 if self.__dict__[key] is not None}
        if self.trust_id is not None:
            event['OS-TRUST:trust_id'] = self.trust_id
        if self.consumer_id is not None:
            event['OS-OAUTH1:consumer_id'] = self.consumer_id
        if self.access_token_id is not None:
            event['OS-OAUTH1:access_token_id'] = self.access_token_id
        if self.expires_at is not None:
            event['expires_at'] = utils.isotime(self.expires_at)
        if self.issued_before is not None:
            event['issued_before'] = utils.isotime(self.issued_before,
                                                   subsecond=True)
        if self.revoked_at is not None:
            event['revoked_at'] = utils.isotime(self.revoked_at,
                                                subsecond=True)
        return event


def is_revoked(events, token_data):
    """Check if a token matches a revocation event.

    Compare a token against every revocation event. If the token matches an
    event in the `events` list, the token is revoked. If the token is compared
    against every item in the list without a match, it is not considered
    revoked from the `revoke_api`.

    :param events: a list of RevokeEvent instances
    :param token_data: map based on a flattened view of the token. The required
                       fields are `expires_at`,`user_id`, `project_id`,
                       `identity_domain_id`, `assignment_domain_id`,
                       `trust_id`, `trustor_id`, `trustee_id` `consumer_id` and
                       `access_token_id`
    :returns: True if the token matches an existing revocation event, meaning
              the token is revoked. False is returned if the token does not
              match any revocation events, meaning the token is considered
              valid by the revocation API.
    """
    return any([matches(e, token_data) for e in events])


def matches(event, token_values):
    """See if the token matches the revocation event.

    A brute force approach to checking.
    Compare each attribute from the event with the corresponding
    value from the token.  If the event does not have a value for
    the attribute, a match is still possible.  If the event has a
    value for the attribute, and it does not match the token, no match
    is possible, so skip the remaining checks.

    :param event: a RevokeEvent instance
    :param token_values: dictionary with set of values taken from the
                         token
    :returns: True if the token matches the revocation event, indicating the
              token has been revoked
    """
    # If any one check does not match, the whole token does
    # not match the event. The numerous return False indicate
    # that the token is still valid and short-circuits the
    # rest of the logic.

    # The token has two attributes that can match the domain_id.
    if event.domain_id is not None and event.domain_id not in (
            token_values['identity_domain_id'],
            token_values['assignment_domain_id'],):
        return False

    if event.domain_scope_id is not None and event.domain_scope_id not in (
            token_values['assignment_domain_id'],):
        return False

    # If an event specifies an attribute name, but it does not match, the token
    # is not revoked.
    if event.expires_at is not None and event.expires_at not in (
            token_values['expires_at'],):
        return False

    if event.trust_id is not None and event.trust_id not in (
            token_values['trust_id'],):
        return False

    if event.consumer_id is not None and event.consumer_id not in (
            token_values['consumer_id'],):
        return False

    if event.audit_chain_id is not None and event.audit_chain_id not in (
            token_values['audit_chain_id'],):
        return False

    if event.role_id is not None and event.role_id not in (
            token_values['roles']):
        return False

    return True


def build_token_values(token):

    token_expires_at = timeutils.parse_isotime(token.expires_at)

    # Trim off the microseconds because the revocation event only has
    # expirations accurate to the second.
    token_expires_at = token_expires_at.replace(microsecond=0)

    token_values = {
        'expires_at': timeutils.normalize_time(token_expires_at),
        'issued_at': timeutils.normalize_time(
            timeutils.parse_isotime(token.issued_at)),
        'audit_id': token.audit_id,
        'audit_chain_id': token.parent_audit_id,
    }

    if token.user_id is not None:
        token_values['user_id'] = token.user_id
        # Federated users do not have a domain, be defensive and get the user
        # domain set to None in the federated user case.
        token_values['identity_domain_id'] = token.user_domain['id']
    else:
        token_values['user_id'] = None
        token_values['identity_domain_id'] = None

    if token.project_id is not None:
        token_values['project_id'] = token.project_id
        # The domain_id of projects acting as domains is None
        token_values['assignment_domain_id'] = token.project_domain['id']
    else:
        token_values['project_id'] = None

    if token.domain_id is not None:
        token_values['assignment_domain_id'] = token.domain_id
    else:
        token_values['assignment_domain_id'] = None

    role_list = []
    if token.roles is not None:
        for role in token.roles:
            role_list.append(role['id'])
    token_values['roles'] = role_list

    if token.trust_scoped:
        token_values['trust_id'] = token.trust['id']
        token_values['trustor_id'] = token.trustor['id']
        token_values['trustee_id'] = token.trustee['id']
    else:
        token_values['trust_id'] = None
        token_values['trustor_id'] = None
        token_values['trustee_id'] = None

    if token.oauth_scoped:
        token_values['consumer_id'] = token.access_token['consumer_id']
        token_values['access_token_id'] = token.access_token['id']
    else:
        token_values['consumer_id'] = None
        token_values['access_token_id'] = None

    return token_values


class _RevokeEventHandler(object):
    # NOTE(morganfainberg): There needs to be reserved "registry" entries set
    # in oslo_serialization for application-specific handlers. We picked 127
    # here since it's waaaaaay far out before oslo_serialization will use it.
    identity = 127
    handles = (RevokeEvent,)

    def __init__(self, registry):
        self._registry = registry

    def serialize(self, obj):
        return msgpackutils.dumps(obj.__dict__, registry=self._registry)

    def deserialize(self, data):
        revoke_event_data = msgpackutils.loads(data, registry=self._registry)
        try:
            revoke_event = RevokeEvent(**revoke_event_data)
        except Exception:
            LOG.debug("Failed to deserialize RevokeEvent. Data is %s",
                      revoke_event_data)
            raise
        return revoke_event


cache.register_model_handler(_RevokeEventHandler)

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

from oslo_utils import timeutils
from six.moves import map

from keystone.common import utils


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
            v = kwargs.get(k, None)
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
            self.revoked_at = timeutils.utcnow()
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
        if self.consumer_id is not None:
            event['OS-OAUTH1:access_token_id'] = self.access_token_id
        if self.expires_at is not None:
            event['expires_at'] = utils.isotime(self.expires_at)
        if self.issued_before is not None:
            event['issued_before'] = utils.isotime(self.issued_before,
                                                   subsecond=True)
        return event

    def key_for_name(self, name):
        return "%s=%s" % (name, getattr(self, name) or '*')


def attr_keys(event):
    return list(map(event.key_for_name, _EVENT_NAMES))


class RevokeTree(object):
    """Fast Revocation Checking Tree Structure

    The Tree is an index to quickly match tokens against events.
    Each node is a hashtable of key=value combinations from revocation events.
    The

    """

    def __init__(self, revoke_events=None):
        self.revoke_map = dict()
        self.add_events(revoke_events)

    def add_event(self, event):
        """Updates the tree based on a revocation event.

        Creates any necessary internal nodes in the tree corresponding to the
        fields of the revocation event.  The leaf node will always be set to
        the latest 'issued_before' for events that are otherwise identical.

        :param:  Event to add to the tree

        :returns:  the event that was passed in.

        """
        revoke_map = self.revoke_map
        for key in attr_keys(event):
            revoke_map = revoke_map.setdefault(key, {})
        revoke_map['issued_before'] = max(
            event.issued_before, revoke_map.get(
                'issued_before', event.issued_before))
        return event

    def remove_event(self, event):
        """Update the tree based on the removal of a Revocation Event

        Removes empty nodes from the tree from the leaf back to the root.

        If multiple events trace the same path, but have different
        'issued_before' values, only the last is ever stored in the tree.
        So only an exact match on 'issued_before' ever triggers a removal

        :param: Event to remove from the tree

        """
        stack = []
        revoke_map = self.revoke_map
        for name in _EVENT_NAMES:
            key = event.key_for_name(name)
            nxt = revoke_map.get(key)
            if nxt is None:
                break
            stack.append((revoke_map, key, nxt))
            revoke_map = nxt
        else:
            if event.issued_before == revoke_map['issued_before']:
                revoke_map.pop('issued_before')
        for parent, key, child in reversed(stack):
            if not any(child):
                del parent[key]

    def add_events(self, revoke_events):
        return list(map(self.add_event, revoke_events or []))

    @staticmethod
    def _next_level_keys(name, token_data):
        """Generate keys based on current field name and token data

        Generate all keys to look for in the next iteration of revocation
        event tree traversal.
        """
        yield '*'
        if name == 'role_id':
            # Roles are very special since a token has a list of them.
            # If the revocation event matches any one of them,
            # revoke the token.
            for role_id in token_data.get('roles', []):
                yield role_id
        else:
            # For other fields we try to get any branch that concur
            # with any alternative field in the token.
            for alt_name in ALTERNATIVES.get(name, [name]):
                yield token_data[alt_name]

    def _search(self, revoke_map, names, token_data):
        """Search for revocation event by token_data

        Traverse the revocation events tree looking for event matching token
        data issued after the token.
        """
        if not names:
            # The last (leaf) level is checked in a special way because we
            # verify issued_at field differently.
            try:
                return revoke_map['issued_before'] >= token_data['issued_at']
            except KeyError:
                return False

        name, remaining_names = names[0], names[1:]

        for key in self._next_level_keys(name, token_data):
            subtree = revoke_map.get('%s=%s' % (name, key))
            if subtree and self._search(subtree, remaining_names, token_data):
                return True

        # If we made it out of the loop then no element in revocation tree
        # corresponds to our token and it is good.
        return False

    def is_revoked(self, token_data):
        """Check if a token matches the revocation event

        Compare the values for each level of the tree with the values from
        the token, accounting for attributes that have alternative
        keys, and for wildcard matches.
        if there is a match, continue down the tree.
        if there is no match, exit early.

        token_data is a map based on a flattened view of token.
        The required fields are:

           'expires_at','user_id', 'project_id', 'identity_domain_id',
           'assignment_domain_id', 'trust_id', 'trustor_id', 'trustee_id'
           'consumer_id', 'access_token_id'

        """
        return self._search(self.revoke_map, _EVENT_NAMES, token_data)


def build_token_values_v2(access, default_domain_id):
    token_data = access['token']

    token_expires_at = timeutils.parse_isotime(token_data['expires'])

    # Trim off the microseconds because the revocation event only has
    # expirations accurate to the second.
    token_expires_at = token_expires_at.replace(microsecond=0)

    token_values = {
        'expires_at': timeutils.normalize_time(token_expires_at),
        'issued_at': timeutils.normalize_time(
            timeutils.parse_isotime(token_data['issued_at'])),
        'audit_id': token_data.get('audit_ids', [None])[0],
        'audit_chain_id': token_data.get('audit_ids', [None])[-1],
    }

    token_values['user_id'] = access.get('user', {}).get('id')

    project = token_data.get('tenant')
    if project is not None:
        token_values['project_id'] = project['id']
    else:
        token_values['project_id'] = None

    token_values['identity_domain_id'] = default_domain_id
    token_values['assignment_domain_id'] = default_domain_id

    trust = token_data.get('trust')
    if trust is None:
        token_values['trust_id'] = None
        token_values['trustor_id'] = None
        token_values['trustee_id'] = None
    else:
        token_values['trust_id'] = trust['id']
        token_values['trustor_id'] = trust['trustor_id']
        token_values['trustee_id'] = trust['trustee_id']

    token_values['consumer_id'] = None
    token_values['access_token_id'] = None

    role_list = []
    # Roles are by ID in metadata and by name in the user section
    roles = access.get('metadata', {}).get('roles', [])
    for role in roles:
        role_list.append(role)
    token_values['roles'] = role_list
    return token_values


def build_token_values(token_data):

    token_expires_at = timeutils.parse_isotime(token_data['expires_at'])

    # Trim off the microseconds because the revocation event only has
    # expirations accurate to the second.
    token_expires_at = token_expires_at.replace(microsecond=0)

    token_values = {
        'expires_at': timeutils.normalize_time(token_expires_at),
        'issued_at': timeutils.normalize_time(
            timeutils.parse_isotime(token_data['issued_at'])),
        'audit_id': token_data.get('audit_ids', [None])[0],
        'audit_chain_id': token_data.get('audit_ids', [None])[-1],
    }

    user = token_data.get('user')
    if user is not None:
        token_values['user_id'] = user['id']
        # Federated users do not have a domain, be defensive and get the user
        # domain set to None in the federated user case.
        token_values['identity_domain_id'] = user.get('domain', {}).get('id')
    else:
        token_values['user_id'] = None
        token_values['identity_domain_id'] = None

    project = token_data.get('project', token_data.get('tenant'))
    if project is not None:
        token_values['project_id'] = project['id']
        token_values['assignment_domain_id'] = project['domain']['id']
    else:
        token_values['project_id'] = None

        domain = token_data.get('domain')
        if domain is not None:
            token_values['assignment_domain_id'] = domain['id']
        else:
            token_values['assignment_domain_id'] = None

    role_list = []
    roles = token_data.get('roles')
    if roles is not None:
        for role in roles:
            role_list.append(role['id'])
    token_values['roles'] = role_list

    trust = token_data.get('OS-TRUST:trust')
    if trust is None:
        token_values['trust_id'] = None
        token_values['trustor_id'] = None
        token_values['trustee_id'] = None
    else:
        token_values['trust_id'] = trust['id']
        token_values['trustor_id'] = trust['trustor_user']['id']
        token_values['trustee_id'] = trust['trustee_user']['id']

    oauth1 = token_data.get('OS-OAUTH1')
    if oauth1 is None:
        token_values['consumer_id'] = None
        token_values['access_token_id'] = None
    else:
        token_values['consumer_id'] = oauth1['consumer_id']
        token_values['access_token_id'] = oauth1['access_token_id']
    return token_values

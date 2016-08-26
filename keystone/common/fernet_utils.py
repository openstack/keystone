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

import os
import stat

from cryptography import fernet
from oslo_log import log

import keystone.conf
from keystone.i18n import _LE, _LW, _LI


LOG = log.getLogger(__name__)

CONF = keystone.conf.CONF


class FernetUtils(object):

    def __init__(self, key_repository=None, max_active_keys=None):
        self.key_repository = key_repository
        self.max_active_keys = max_active_keys

    def validate_key_repository(self, requires_write=False):
        """Validate permissions on the key repository directory."""
        # NOTE(lbragstad): We shouldn't need to check if the directory was
        # passed in as None because we don't set allow_no_values to True.

        # ensure current user has sufficient access to the key repository
        is_valid = (os.access(self.key_repository, os.R_OK) and
                    os.access(self.key_repository, os.X_OK))
        if requires_write:
            is_valid = (is_valid and
                        os.access(self.key_repository, os.W_OK))

        if not is_valid:
            LOG.error(
                _LE('Either [fernet_tokens] key_repository does not exist or '
                    'Keystone does not have sufficient permission to access '
                    'it: %s'), self.key_repository)
        else:
            # ensure the key repository isn't world-readable
            stat_info = os.stat(self.key_repository)
            if(stat_info.st_mode & stat.S_IROTH or
               stat_info.st_mode & stat.S_IXOTH):
                LOG.warning(_LW(
                    'key_repository is world readable: %s'),
                    self.key_repository)

        return is_valid

    def _convert_to_integers(self, id_value):
        """Cast user and group system identifiers to integers."""
        # NOTE(lbragstad) os.chown() will raise a TypeError here if
        # keystone_user_id and keystone_group_id are not integers. Let's cast
        # them to integers if we can because it's possible to pass non-integer
        # values into the fernet_setup utility.
        try:
            id_int = int(id_value)
        except ValueError as e:
            msg = _LE('Unable to convert Keystone user or group ID. Error: %s')
            LOG.error(msg, e)
            raise

        return id_int

    def create_key_directory(self, keystone_user_id=None,
                             keystone_group_id=None):
        """Attempt to create the key directory if it doesn't exist."""
        if not os.access(self.key_repository, os.F_OK):
            LOG.info(_LI(
                'key_repository does not appear to exist; attempting to '
                'create it'))

            try:
                os.makedirs(self.key_repository, 0o700)
            except OSError:
                LOG.error(_LE(
                    'Failed to create key_repository: either it already '
                    'exists or you don\'t have sufficient permissions to '
                    'create it'))

            if keystone_user_id and keystone_group_id:
                os.chown(
                    self.key_repository,
                    keystone_user_id,
                    keystone_group_id)
            elif keystone_user_id or keystone_group_id:
                LOG.warning(_LW(
                    'Unable to change the ownership of key_repository without '
                    'a keystone user ID and keystone group ID both being '
                    'provided: %s') % self.key_repository)

    def _create_new_key(self, keystone_user_id, keystone_group_id):
        """Securely create a new encryption key.

        Create a new key that is readable by the Keystone group and Keystone
        user.
        """
        key = fernet.Fernet.generate_key()  # key is bytes

        # This ensures the key created is not world-readable
        old_umask = os.umask(0o177)
        if keystone_user_id and keystone_group_id:
            old_egid = os.getegid()
            old_euid = os.geteuid()
            os.setegid(keystone_group_id)
            os.seteuid(keystone_user_id)
        elif keystone_user_id or keystone_group_id:
            LOG.warning(_LW(
                'Unable to change the ownership of the new key without a '
                'keystone user ID and keystone group ID both being provided: '
                '%s') %
                self.key_repository)
        # Determine the file name of the new key
        key_file = os.path.join(self.key_repository, '0')
        try:
            with open(key_file, 'w') as f:
                # convert key to str for the file.
                f.write(key.decode('utf-8'))
        finally:
            # After writing the key, set the umask back to it's original value.
            # Do the same with group and user identifiers if a Keystone group
            # or user was supplied.
            os.umask(old_umask)
            if keystone_user_id and keystone_group_id:
                os.seteuid(old_euid)
                os.setegid(old_egid)

        LOG.info(_LI('Created a new key: %s'), key_file)

    def initialize_key_repository(self, keystone_user_id=None,
                                  keystone_group_id=None):
        """Create a key repository and bootstrap it with a key.

        :param keystone_user_id: User ID of the Keystone user.
        :param keystone_group_id: Group ID of the Keystone user.

        """
        # make sure we have work to do before proceeding
        if os.access(os.path.join(self.key_repository, '0'),
                     os.F_OK):
            LOG.info(_LI('Key repository is already initialized; aborting.'))
            return

        # bootstrap an existing key
        self._create_new_key(keystone_user_id, keystone_group_id)

        # ensure that we end up with a primary and secondary key
        self.rotate_keys(keystone_user_id, keystone_group_id)

    def rotate_keys(self, keystone_user_id=None, keystone_group_id=None):
        """Create a new primary key and revoke excess active keys.

        :param keystone_user_id: User ID of the Keystone user.
        :param keystone_group_id: Group ID of the Keystone user.

        Key rotation utilizes the following behaviors:

        - The highest key number is used as the primary key (used for
          encryption).
        - All keys can be used for decryption.
        - New keys are always created as key "0," which serves as a placeholder
          before promoting it to be the primary key.

        This strategy allows you to safely perform rotation on one node in a
        cluster, before syncing the results of the rotation to all other nodes
        (during both key rotation and synchronization, all nodes must recognize
        all primary keys).

        """
        # read the list of key files
        key_files = dict()
        for filename in os.listdir(self.key_repository):
            path = os.path.join(self.key_repository, str(filename))
            if os.path.isfile(path):
                try:
                    key_id = int(filename)
                except ValueError:  # nosec : name isn't a number
                    pass
                else:
                    key_files[key_id] = path

        LOG.info(_LI('Starting key rotation with %(count)s key files: '
                     '%(list)s'), {
            'count': len(key_files),
            'list': list(key_files.values())})

        # determine the number of the new primary key
        current_primary_key = max(key_files.keys())
        LOG.info(_LI('Current primary key is: %s'), current_primary_key)
        new_primary_key = current_primary_key + 1
        LOG.info(_LI('Next primary key will be: %s'), new_primary_key)

        # promote the next primary key to be the primary
        os.rename(
            os.path.join(self.key_repository, '0'),
            os.path.join(self.key_repository, str(new_primary_key))
        )
        key_files.pop(0)
        key_files[new_primary_key] = os.path.join(
            self.key_repository,
            str(new_primary_key))
        LOG.info(_LI('Promoted key 0 to be the primary: %s'), new_primary_key)

        # add a new key to the rotation, which will be the *next* primary
        self._create_new_key(keystone_user_id, keystone_group_id)

        max_active_keys = self.max_active_keys

        # purge excess keys

        # Note that key_files doesn't contain the new active key that was
        # created, only the old active keys.
        keys = sorted(key_files.keys(), reverse=True)
        while len(keys) > (max_active_keys - 1):
            index_to_purge = keys.pop()
            key_to_purge = key_files[index_to_purge]
            LOG.info(_LI('Excess key to purge: %s'), key_to_purge)
            os.remove(key_to_purge)

    def load_keys(self):
        """Load keys from disk into a list.

        The first key in the list is the primary key used for encryption. All
        other keys are active secondary keys that can be used for decrypting
        tokens.

        """
        if not self.validate_key_repository():
            return []

        # build a dictionary of key_number:encryption_key pairs
        keys = dict()
        for filename in os.listdir(self.key_repository):
            path = os.path.join(self.key_repository, str(filename))
            if os.path.isfile(path):
                with open(path, 'r') as key_file:
                    try:
                        key_id = int(filename)
                    except ValueError:  # nosec : filename isn't a number,
                        # ignore this file since it's not a key.
                        pass
                    else:
                        keys[key_id] = key_file.read()

        if len(keys) != self.max_active_keys:
            # Once the number of keys matches max_active_keys, this log entry
            # is too repetitive to be useful.
            LOG.debug(
                'Loaded %(count)d Fernet keys from %(dir)s, but '
                '`[fernet_tokens] max_active_keys = %(max)d`; perhaps there '
                'have not been enough key rotations to reach '
                '`max_active_keys` yet?', {
                    'count': len(keys),
                    'max': self.max_active_keys,
                    'dir': self.key_repository})

        # return the encryption_keys, sorted by key number, descending
        return [keys[x] for x in sorted(keys.keys(), reverse=True)]

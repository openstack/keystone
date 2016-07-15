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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_LDAP_user_enabled_emulation_dn_ignored():
    """`[ldap] user_enabled_emulation_dn` is being ignored.

    There is no reason to set this value unless `keystone.conf [ldap]
    user_enabled_emulation` is also enabled.
    """
    return (
        not CONF.ldap.user_enabled_emulation
        and CONF.ldap.user_enabled_emulation_dn is not None)


def symptom_LDAP_user_enabled_emulation_use_group_config_ignored():
    """`[ldap] user_enabled_emulation_use_group_config` is being ignored.

    There is no reason to set this value unless `keystone.conf [ldap]
    user_enabled_emulation` is also enabled.
    """
    return (
        not CONF.ldap.user_enabled_emulation
        and CONF.ldap.user_enabled_emulation_use_group_config)


def symptom_LDAP_group_members_are_ids_disabled():
    """`[ldap] group_members_are_ids` is not enabled.

    Because you've set `keystone.conf [ldap] group_objectclass = posixGroup`,
    we would have also expected you to enable set `keystone.conf [ldap]
    group_members_are_ids` because we suspect you're using Open Directory,
    which would contain user ID's in a `posixGroup` rather than LDAP DNs, as
    other object classes typically would.
    """
    return (
        CONF.ldap.group_objectclass == 'posixGroup'
        and not CONF.ldap.group_members_are_ids)

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
import re

import configparser

import keystone.conf


CONF = keystone.conf.CONF
CONFIG_REGEX = r'^keystone\..*?\.conf$'


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


def symptom_LDAP_file_based_domain_specific_configs():
    """Domain specific driver directory is invalid or contains invalid files.

    If `keystone.conf [identity] domain_specific_drivers_enabled` is set
    to `true`, then support is enabled for individual domains to have their
    own identity drivers. The configurations for these can either be stored
    in a config file or in the database. The case we handle in this symptom
    is when they are stored in config files, which is indicated by
    `keystone.conf [identity] domain_configurations_from_database`
    being set to `false`.
    """
    if (not CONF.identity.domain_specific_drivers_enabled or
            CONF.identity.domain_configurations_from_database):
        return False

    invalid_files = []
    filedir = CONF.identity.domain_config_dir
    if os.path.isdir(filedir):
        for filename in os.listdir(filedir):
            if not re.match(CONFIG_REGEX, filename):
                invalid_files.append(filename)
        if invalid_files:
            invalid_str = ', '.join(invalid_files)
            print('Warning: The following non-config files were found: %s\n'
                  'If they are intended to be config files then rename them '
                  'to the form of `keystone.<domain_name>.conf`. '
                  'Otherwise, ignore this warning' % invalid_str)
            return True
    else:
        print('Could not find directory ', filedir)
        return True

    return False


def symptom_LDAP_file_based_domain_specific_configs_formatted_correctly():
    """LDAP domain specific configuration files are not formatted correctly.

    If `keystone.conf [identity] domain_specific_drivers_enabled` is set
    to `true`, then support is enabled for individual domains to have their
    own identity drivers. The configurations for these can either be stored
    in a config file or in the database. The case we handle in this symptom
    is when they are stored in config files, which is indicated by
    `keystone.conf [identity] domain_configurations_from_database`
    being set to false. The config files located in the directory specified
    by `keystone.conf [identity] domain_config_dir` should be in the
    form of `keystone.<domain_name>.conf` and their contents should look
    something like this:

    [ldap]
    url = ldap://ldapservice.thecustomer.com
    query_scope = sub

    user_tree_dn = ou=Users,dc=openstack,dc=org
    user_objectclass = MyOrgPerson
    user_id_attribute = uid
    ...
    """
    filedir = CONF.identity.domain_config_dir
    # NOTE(gagehugo): If domain_specific_drivers_enabled = false or
    # the value set in domain_config_dir is nonexistent/invalid, then
    # there is no point in continuing with this check.
    # symptom_LDAP_file_based_domain_specific_config will catch and
    # report this issue.
    if (not CONF.identity.domain_specific_drivers_enabled or
            CONF.identity.domain_configurations_from_database or
            not os.path.isdir(filedir)):
        return False

    invalid_files = []
    for filename in os.listdir(filedir):
        if re.match(CONFIG_REGEX, filename):
            try:
                parser = configparser.ConfigParser()
                parser.read(os.path.join(filedir, filename))
            except configparser.Error:
                invalid_files.append(filename)

    if invalid_files:
        invalid_str = ', '.join(invalid_files)
        print('Error: The following config files are formatted incorrectly: ',
              invalid_str)
        return True

    return False

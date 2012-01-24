#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 OpenStack LLC.
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

"""
Keystone Identity Server - CLI Management Interface
"""

import logging
import optparse  # deprecated in 2.7, in favor of argparse
import os
import sys
import tempfile

from keystone import version
import keystone.backends as db
from keystone.backends.sqlalchemy import migration
# Need to give it a different alias
from keystone import config as new_config
from keystone.common import config
from keystone.logic.types import fault
from keystone.manage import api
from keystone import utils

logger = logging.getLogger(__name__)  # pylint: disable=C0103

# We're using two config systems here, so we need to be clear
# which one we're working with.
CONF = new_config.CONF


# CLI feature set
OBJECTS = ['user', 'tenant', 'role', 'service',
    'endpointTemplates', 'token', 'endpoint', 'credentials', 'database']
ACTIONS = ['add', 'list', 'disable', 'delete', 'grant', 'revoke',
    'sync', 'downgrade', 'upgrade', 'version_control', 'version',
    'goto']


# Messages
OBJECT_NOT_SPECIFIED = 'No object type specified for first argument'
ACTION_NOT_SPECIFIED = 'No action specified for second argument'
ID_NOT_SPECIFIED = 'No ID specified for third argument'
SUPPORTED_OBJECTS = "Supported objects: %s" % (", ".join(OBJECTS))
SUPPORTED_ACTIONS = "Supported actions: %s" % (", ".join(ACTIONS))
ACTION_NOT_SUPPORTED = 'Action not supported for %s'


class RaisingOptionParser(optparse.OptionParser):
    def error(self, msg):
        self.print_usage(sys.stderr)
        raise optparse.OptParseError(msg)


def parse_args(args=None):
    usage = """
    Usage: keystone-manage [options] type action [id [attributes]]
      type       : %s
      action     : %s
      id         : name or id
      attributes : depending on type...
        users    : password, tenant
        tokens   : user, tenant, expiration

      role list [tenant] will list roles granted on that tenant
      database [sync | downgrade | upgrade | version_control | version]

    options
      -c | --config-file : config file to use
      -d | --debug : debug mode

    Example: keystone-manage user add Admin P@ssw0rd
    """ % (", ".join(OBJECTS), ", ".join(ACTIONS))

    # Initialize a parser for our configuration paramaters
    parser = RaisingOptionParser(usage, version='%%prog %s'
        % version.version())
    config.add_common_options(parser)
    config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = config.parse_options(parser, args)

    if not args or args[0] != 'database':
        # Use the legacy code to find the config file
        config_file = config.find_config_file(options, sys.argv[1:])
        # Now init the CONF for the backends
        CONF(config_files=[config_file])

        db.configure_backends()
    return args


def get_options(args=None):
    # Initialize a parser for our configuration paramaters
    parser = RaisingOptionParser()
    config.add_common_options(parser)
    config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = config.parse_options(parser, list(args))

    _config_file, conf = config.load_paste_config('admin', options, args)
    conf.global_conf.update(conf.local_conf)

    return conf.global_conf


# pylint: disable=R0912,R0915
def process(*args):
    # Check arguments
    if len(args) == 0:
        raise optparse.OptParseError(OBJECT_NOT_SPECIFIED)
    else:
        object_type = args[0]
        if object_type not in OBJECTS:
            raise optparse.OptParseError(SUPPORTED_OBJECTS)

    if len(args) == 1:
        raise optparse.OptParseError(ACTION_NOT_SPECIFIED)
    else:
        action = args[1]
        if action not in ACTIONS:
            raise optparse.OptParseError(SUPPORTED_ACTIONS)

    if action not in ['list', 'sync', 'version_control', 'version']:
        if len(args) == 2:
            raise optparse.OptParseError(ID_NOT_SPECIFIED)
        else:
            object_id = args[2]

    # Helper functions
    def require_args(args, min, msg):
        """Ensure there are at least `min` arguments"""
        if len(args) < min:
            raise optparse.OptParseError(msg)

    def optional_arg(args, index):
        return ((len(args) > index) and str(args[index]).strip()) or None

    if object_type == 'database':
        options = get_options(args)

    # Execute command
    if (object_type, action) == ('user', 'add'):
        require_args(args, 4, 'No password specified for fourth argument')
        if api.add_user(name=object_id, password=args[3],
                tenant=optional_arg(args, 4)):
            print ("SUCCESS: User %s created." % object_id)

    elif (object_type, action) == ('user', 'list'):
        print (Table('Users', ['id', 'name', 'enabled', 'tenant'],
                     api.list_users()))

    elif (object_type, action) == ('user', 'disable'):
        if api.disable_user(name=object_id):
            print ("SUCCESS: User %s disabled." % object_id)

    elif object_type == 'user':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('users'))

    elif (object_type, action) == ('tenant', 'add'):
        if api.add_tenant(name=object_id):
            print ("SUCCESS: Tenant %s created." % object_id)

    elif (object_type, action) == ('tenant', 'list'):
        print Table('Tenants', ['id', 'name', 'enabled'], api.list_tenants())

    elif (object_type, action) == ('tenant', 'disable'):
        if api.disable_tenant(name=object_id):
            print ("SUCCESS: Tenant %s disabled." % object_id)

    elif object_type == 'tenant':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('tenants'))

    elif (object_type, action) == ('role', 'add'):
        if api.add_role(name=object_id, service_name=optional_arg(args, 3)):
            print ("SUCCESS: Role %s created successfully." % object_id)

    elif (object_type, action) == ('role', 'list'):
        tenant = optional_arg(args, 2)
        if tenant:
            # print with users
            print (Table('Role assignments for tenant %s' %
                         tenant, ['User', 'Role'],
                         api.list_roles(tenant=tenant)))
        else:
            # print without tenants
            print (Table('Roles', ['id', 'name', 'service_id', 'description'],
                         api.list_roles()))

    elif (object_type, action) == ('role', 'grant'):
        require_args(args, 4, "Missing arguments: role grant 'role' 'user' "
            "'tenant (optional)'")
        tenant = optional_arg(args, 4)
        if api.grant_role(object_id, args[3], tenant):
            print ("SUCCESS: Granted %s the %s role on %s." %
                (args[3], object_id, tenant))

    elif object_type == 'role':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('roles'))

    elif (object_type, action) == ('endpointTemplates', 'add'):
        require_args(args, 9, "Missing arguments: endpointTemplates add "
            "'region' 'service_name' 'publicURL' 'adminURL' 'internalURL' "
            "'enabled' 'global'")
        version_id = optional_arg(args, 9)
        version_list = optional_arg(args, 10)
        version_info = optional_arg(args, 11)
        if api.add_endpoint_template(region=args[2], service=args[3],
                public_url=args[4], admin_url=args[5], internal_url=args[6],
                enabled=args[7], is_global=args[8],
                version_id=version_id, version_list=version_list,
                version_info=version_info):
            print ("SUCCESS: Created EndpointTemplates for %s "
                                   "pointing to %s." % (args[3], args[4]))

    elif (object_type, action) == ('endpointTemplates', 'list'):
        tenant = optional_arg(args, 2)
        if tenant:
            print Table('Endpoints for tenant %s' % tenant,
                        ['id', 'service', 'region', 'Public URL'],
                        api.list_tenant_endpoints(tenant))
        else:
            print Table('All EndpointTemplates', ['id', 'service', 'type',
                        'region', 'enabled', 'is_global', 'Public URL',
                        'Admin URL'],
                api.list_endpoint_templates())

    elif (object_type, action) == ('endpoint', 'add'):
        require_args(args, 4, "Missing arguments: endPoint add tenant "
            "endPointTemplate")
        if api.add_endpoint(tenant=args[2], endpoint_template=args[3]):
            print ("SUCCESS: Endpoint %s added to tenant %s." %
                (args[3], args[2]))

    elif object_type == 'endpoint':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('endpoints'))

    elif (object_type, action) == ('token', 'add'):
        require_args(args, 6, 'Creating a token requires a token id, user, '
            'tenant, and expiration')
        if api.add_token(token=object_id, user=args[3], tenant=args[4],
                expires=args[5]):
            print ("SUCCESS: Token %s created." % object_id)

    elif (object_type, action) == ('token', 'list'):
        print Table('Tokens', ('token', 'user', 'expiration', 'tenant'),
            api.list_tokens())

    elif (object_type, action) == ('token', 'delete'):
        if api.delete_token(token=object_id):
            print ('SUCCESS: Token %s deleted.' % (object_id,))

    elif object_type == 'token':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('tokens'))

    elif (object_type, action) == ('service', 'add'):
        require_args(args, 4, "Missing arguments: service add <name> " \
                     "[type] [desc] [owner_id]"
            "type")
        type = optional_arg(args, 3)
        desc = optional_arg(args, 4)
        owner_id = optional_arg(args, 5)

        if api.add_service(name=object_id, type=type, desc=desc,
                           owner_id=owner_id):
            print ("SUCCESS: Service %s created successfully."
                                   % (object_id,))

    elif (object_type, action) == ('service', 'list'):
        print (Table('Services', ('id', 'name', 'type', 'owner_id',
                                  'description'), api.list_services()))

    elif object_type == 'service':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('services'))

    elif (object_type, action) == ('credentials', 'add'):
        require_args(args, 6, 'Creating a credentials requires a type, key, '
            'secret, and tenant_id (id is user_id)')
        if api.add_credentials(user=object_id, type=args[3], key=args[4],
                secrete=args[5], tenant=optional_arg(args, 6)):
            print ("SUCCESS: Credentials %s created." %
                                   (object_id,))

    elif object_type == 'credentials':
        raise optparse.OptParseError(ACTION_NOT_SUPPORTED % ('credentials'))

    elif (object_type, action) == ('database', 'sync'):
        require_args(args, 1, 'Syncing database requires a version #')
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_sync(options['keystone.backends.sqlalchemy'],
                                 args)
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    elif (object_type, action) == ('database', 'upgrade'):
        require_args(args, 1, 'Upgrading database requires a version #')
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_upgrade(options['keystone.backends.sqlalchemy'],
                                 args)
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    elif (object_type, action) == ('database', 'downgrade'):
        require_args(args, 1, 'Downgrading database requires a version #')
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_downgrade(options['keystone.backends.sqlalchemy'],
                                 args)
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    elif (object_type, action) == ('database', 'version_control'):
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_version_control(options['keystone.backends.sqlalchemy'])
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    elif (object_type, action) == ('database', 'version'):
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_version(options['keystone.backends.sqlalchemy'])
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    elif (object_type, action) == ('database', 'goto'):
        require_args(args, 1, 'Jumping database versions requires a '
            'version #')
        backend_names = options.get('backends', None)
        if backend_names:
            if 'keystone.backends.sqlalchemy' in backend_names.split(','):
                do_db_goto_version(options['keystone.backends.sqlalchemy'],
                    target_version=args[2])
            else:
                raise optparse.OptParseError(
                    'SQL alchemy backend not specified in config')

    else:
        # Command recognized but not handled: should never reach this
        raise NotImplementedError()


#
#   Database Migration commands (from Glance-manage)
#
def do_db_version(options):
    """Print database's current migration level"""
    print (migration.db_version(options['sql_connection']))


def do_db_goto_version(options, target_version):
    """Override the database's current migration level"""
    if migration.db_goto_version(options['sql_connection'], target_version):
        msg = ('Jumped to version=%s (without performing intermediate '
            'migrations)') % target_version
        print (msg)


def do_db_upgrade(options, args):
    """Upgrade the database's migration level"""
    try:
        db_version = args[2]
    except IndexError:
        db_version = None

    print ("Upgrading database to version %s" % db_version)
    migration.upgrade(options['sql_connection'], version=db_version)


def do_db_downgrade(options, args):
    """Downgrade the database's migration level"""
    try:
        db_version = args[2]
    except IndexError:
        raise Exception("downgrade requires a version argument")

    migration.downgrade(options['sql_connection'], version=db_version)


def do_db_version_control(options):
    """Place a database under migration control"""
    migration.version_control(options['sql_connection'])
    print ("Database now under version control")


def do_db_sync(options, args):
    """Place a database under migration control and upgrade"""
    try:
        db_version = args[2]
    except IndexError:
        db_version = None
    migration.db_sync(options['sql_connection'], version=db_version)


class Table:
    """Prints data in table for console output

    Syntax print Table("This is the title",
            ["Header1","Header2","H3"],
            [[1,2,3],["Hi","everybody","How are you??"],[None,True,[1,2]]])

    """
    def __init__(self, title=None, headers=None, rows=None):
        self.title = title
        self.headers = headers if headers is not None else []
        self.rows = rows if rows is not None else []
        self.nrows = len(self.rows)
        self.fieldlen = []

        ncols = len(headers)

        for h in range(ncols):
            max = 0
            for row in rows:
                if len(str(row[h])) > max:
                    max = len(str(row[h]))
            self.fieldlen.append(max)

        for i in range(len(headers)):
            if len(str(headers[i])) > self.fieldlen[i]:
                self.fieldlen[i] = len(str(headers[i]))

        self.width = sum(self.fieldlen) + (ncols - 1) * 3 + 4

    def __str__(self):
        hbar = "-" * self.width
        if self.title:
            title = "| " + self.title + " " * \
                    (self.width - 3 - (len(self.title))) + "|"
            out = [hbar, title, hbar]
        else:
            out = []
        header = ""
        for i in range(len(self.headers)):
            header += "| %s" % (str(self.headers[i])) + " " * \
                (self.fieldlen[i] - len(str(self.headers[i]))) + " "
        header += "|"
        out.append(header)
        out.append(hbar)
        for i in self.rows:
            line = ""
            for j in range(len(i)):
                line += "| %s" % (str(i[j])) + " " * \
                (self.fieldlen[j] - len(str(i[j]))) + " "
            out.append(line + "|")

        out.append(hbar)
        return "\r\n".join(out)


def main(args=None):
    try:
        process(*parse_args(args))
    except (optparse.OptParseError, fault.DatabaseMigrationError) as exc:
        print >> sys.stderr, exc
        sys.exit(2)
    except Exception as exc:
        logstr = str(exc)
        loginfo = None
        if len(exc.args) > 1:
            logstr = exc.args[0]
            loginfo = exc.args[1]

        errmsg = "ERROR: %s" % logstr
        if loginfo:
            errmsg += ": %s" % loginfo

        print errmsg
        logger.error(logstr, exc_info=loginfo)
        raise


if __name__ == '__main__':
    try:
        main()
    except StandardError:
        sys.exit(1)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
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

import gettext
import sys
import os

from keystone.common import logging
from keystone.openstack.common import cfg


gettext.install('keystone', unicode=1)


class ConfigMixin(object):
    def __call__(self, config_files=None, *args, **kw):
        if config_files is not None:
            self._opts['config_file']['opt'].default = config_files
        kw.setdefault('args', [])
        return super(ConfigMixin, self).__call__(*args, **kw)

    def set_usage(self, usage):
        self.usage = usage
        self._oparser.usage = usage


class Config(ConfigMixin, cfg.ConfigOpts):
    pass


class CommonConfig(ConfigMixin, cfg.CommonConfigOpts):
    pass


def setup_logging(conf):
    """
    Sets up the logging options for a log with supplied name

    :param conf: a cfg.ConfOpts object
    """

    if conf.log_config:
        # Use a logging configuration file for all settings...
        if os.path.exists(conf.log_config):
            logging.config.fileConfig(conf.log_config)
            return
        else:
            raise RuntimeError('Unable to locate specified logging '
                               'config file: %s' % conf.log_config)

    root_logger = logging.root
    if conf.debug:
        root_logger.setLevel(logging.DEBUG)
    elif conf.verbose:
        root_logger.setLevel(logging.INFO)
    else:
        root_logger.setLevel(logging.WARNING)

    formatter = logging.Formatter(conf.log_format, conf.log_date_format)

    if conf.use_syslog:
        try:
            facility = getattr(logging.SysLogHandler,
                               conf.syslog_log_facility)
        except AttributeError:
            raise ValueError(_('Invalid syslog facility'))

        handler = logging.SysLogHandler(address='/dev/log',
                                        facility=facility)
    elif conf.log_file:
        logfile = conf.log_file
        if conf.log_dir:
            logfile = os.path.join(conf.log_dir, logfile)
        handler = logging.WatchedFileHandler(logfile)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def register_str(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_opt(cfg.StrOpt(*args, **kw), group=group)


def register_cli_str(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_cli_opt(cfg.StrOpt(*args, **kw), group=group)


def register_bool(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_opt(cfg.BoolOpt(*args, **kw), group=group)


def register_cli_bool(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_cli_opt(cfg.BoolOpt(*args, **kw), group=group)


def register_int(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_opt(cfg.IntOpt(*args, **kw), group=group)


def register_cli_int(*args, **kw):
    conf = kw.pop('conf', CONF)
    group = kw.pop('group', None)
    return conf.register_cli_opt(cfg.IntOpt(*args, **kw), group=group)


CONF = CommonConfig(project='keystone')


register_str('admin_token', default='ADMIN')
register_str('bind_host', default='0.0.0.0')
register_str('compute_port', default=8774)
register_str('admin_port', default=35357)
register_str('public_port', default=5000)
register_str('onready')

#ssl options
register_bool('enable', group='ssl', default=False)
register_str('certfile', group='ssl', default=None)
register_str('keyfile', group='ssl', default=None)
register_str('ca_certs', group='ssl', default=None)
register_bool('cert_required', group='ssl', default=False)

# sql options
register_str('connection', group='sql', default='sqlite:///keystone.db')
register_int('idle_timeout', group='sql', default=200)


register_str('driver', group='catalog',
             default='keystone.catalog.backends.sql.Catalog')
register_str('driver', group='identity',
             default='keystone.identity.backends.sql.Identity')
register_str('driver', group='policy',
             default='keystone.policy.backends.rules.Policy')
register_str('driver', group='token',
             default='keystone.token.backends.kvs.Token')
register_str('driver', group='ec2',
             default='keystone.contrib.ec2.backends.kvs.Ec2')


#ldap
register_str('url', group='ldap', default='ldap://localhost')
register_str('user', group='ldap', default='dc=Manager,dc=example,dc=com')
register_str('password', group='ldap', default='freeipa4all')
register_str('suffix', group='ldap', default='cn=example,cn=com')
register_bool('use_dumb_member', group='ldap', default=False)

register_str('user_tree_dn', group='ldap',
             default='ou=Users,dc=example,dc=com')
register_str('user_objectclass', group='ldap', default='inetOrgPerson')
register_str('user_id_attribute', group='ldap', default='cn')

register_str('tenant_tree_dn', group='ldap',
             default='ou=Groups,dc=example,dc=com')
register_str('tenant_objectclass', group='ldap', default='groupOfNames')
register_str('tenant_id_attribute', group='ldap', default='cn')
register_str('tenant_member_attribute', group='ldap', default='member')


register_str('role_tree_dn', group='ldap',
             default='ou=Roles,dc=example,dc=com')
register_str('role_objectclass', group='ldap', default='organizationalRole')
register_str('role_id_attribute', group='ldap', default='cn')
register_str('role_member_attribute', group='ldap', default='roleOccupant')

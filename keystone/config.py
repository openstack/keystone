#!/usr/bin/env python

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
Routines for configuring OpenStack Service
"""
import gettext
import logging
import logging.config
import logging.handlers
import sys
import os

from keystone import cfg


gettext.install("keystone", unicode=1)


class Config(cfg.CommonConfigOpts):
    def __call__(self, config_files=None):
        if config_files is not None:
            self._opts["config_file"]["opt"].default = config_files
        return super(Config, self).__call__()

    def __getitem__(self, key, default=None):
        return getattr(self, key, default)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def iteritems(self):
        for key in self._opts:
            yield (key, getattr(self, key))

    def to_dict(self):
        """ Returns a representation of the CONF settings as a dict."""
        ret = {}
        for key, val in self.iteritems():
            if val is not None:
                ret[key] = val
        for grp_name in self._groups:
            ret[grp_name] = grp_dict = {}
            grp = self._get_group(grp_name)
            for opt in grp._opts:  # pylint: disable=W0212
                grp_dict[opt] = self._get(opt, grp_name)
        return ret


def setup_logging(conf):
    """
    Sets up the logging options for a log with supplied name

    :param conf: a cfg.ConfOpts object
    """
    if conf.log_config:
        # Use a logging configuration file for all settings...
        for location in (sys.argv[0], "."):
            pth = os.path.join(location, "etc", conf.log_config)
            if os.path.exists(pth):
                logging.config.fileConfig(pth)
                return
        raise RuntimeError("Unable to locate specified logging "
                           "config file: %s" % conf.log_config)
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
            facility = getattr(logging.handlers.SysLogHandler,
                               conf.syslog_log_facility)
        except AttributeError:
            raise ValueError(_("Invalid syslog facility"))

        handler = logging.handlers.SysLogHandler(address="/dev/log",
                                        facility=facility)
    elif conf.log_file:
        logfile = conf.log_file
        if conf.log_dir:
            logfile = os.path.join(conf.log_dir, logfile)
        handler = logging.handlers.WatchedFileHandler(logfile)
    else:
        handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def register_str(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.StrOpt(*args, **kw), group=group)


def register_cli_str(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.StrOpt(*args, **kw), group=group)


def register_bool(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.BoolOpt(*args, **kw), group=group)


def register_cli_bool(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_cli_opt(cfg.BoolOpt(*args, **kw), group=group)


def register_list(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.ListOpt(*args, **kw), group=group)


def register_multi_string(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.MultiStrOpt(*args, **kw), group=group)


def _ensure_group(kw):
    group = kw.pop("group", None)
    if group:
        CONF.register_group(cfg.OptGroup(name=group))
    return group


CONF = Config(project="keystone")

register_str("default_store")
register_str("service_header_mappings")
register_list("extensions")
register_str("service_host")
register_str("service_port")
register_bool("service_ssl")
register_str("admin_host")
register_str("admin_port")
register_bool("admin_ssl")
register_str("bind_host")
register_str("bind_port")
register_str("certfile")
register_str("keyfile")
register_str("ca_certs")
register_bool("cert_required")
register_str("keystone_admin_role")
register_str("keystone_service_admin_role")
register_bool("hash_password")
register_str("backends")
register_str("global_service_id")
register_bool("disable_tokens_in_url")

register_str("sql_connection", group="keystone.backends.sqlalchemy")
register_str("backend_entities", group="keystone.backends.sqlalchemy")
register_str("sql_idle_timeout", group="keystone.backends.sqlalchemy")
# May need to initialize other backends, too.
register_str("ldap_url", group="keystone.backends.ldap")
register_str("ldap_user", group="keystone.backends.ldap")
register_str("ldap_password", group="keystone.backends.ldap")
register_list("backend_entities", group="kkeystone.backends.ldap")

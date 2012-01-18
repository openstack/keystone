# vim: tabstop=4 shiftwidth=4 softtabstop=4

import gettext
import logging
import sys
import os

from keystone import cfg


gettext.install('keystone', unicode=1)


class Config(cfg.CommonConfigOpts):
    def __call__(self, config_files=None, *args, **kw):
        if config_files is not None:
            self._opts['config_file']['opt'].default = config_files
        return super(Config, self).__call__(*args, **kw)

    def __getitem__(self, key, default=None):
        return getattr(self, key, default)

    def __setitem__(self, key, value):
        return setattr(self, key, value)

    def iteritems(self):
        for k in self._opts:
            yield (k, getattr(self, k))


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
            facility = getattr(logging.SysLogHandler,
                               conf.syslog_log_facility)
        except AttributeError:
            raise ValueError(_("Invalid syslog facility"))

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
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.StrOpt(*args, **kw), group=group)


def register_cli_str(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_cli_opt(cfg.StrOpt(*args, **kw), group=group)


def register_bool(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_opt(cfg.BoolOpt(*args, **kw), group=group)


def register_cli_bool(*args, **kw):
    group = _ensure_group(kw)
    return CONF.register_cli_opt(cfg.BoolOpt(*args, **kw), group=group)


def _ensure_group(kw):
    group = kw.pop('group', None)
    if group:
        CONF.register_group(cfg.OptGroup(name=group))
    return group


CONF = Config(project='keystone')


register_str('admin_token', default='ADMIN')
register_str('compute_port')
register_str('admin_port')
register_str('public_port')


# sql options
register_str('connection', group='sql')
register_str('idle_timeout', group='sql')
register_str('min_pool_size', group='sql')
register_str('maz_pool_size', group='sql')
register_str('pool_timeout', group='sql')


register_str('driver', group='catalog')
register_str('driver', group='identity')
register_str('driver', group='policy')
register_str('driver', group='token')
register_str('driver', group='ec2')

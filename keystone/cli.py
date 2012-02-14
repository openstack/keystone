from __future__ import absolute_import

import json
import logging
import sys
import StringIO
import textwrap

import cli.app
import cli.log

from keystone import config
from keystone.common import utils


CONF = config.CONF
CONF.set_usage('%prog COMMAND [key1=value1 key2=value2 ...]')


class BaseApp(cli.log.LoggingApp):
    def __init__(self, *args, **kw):
        kw.setdefault('name', self.__class__.__name__.lower())
        super(BaseApp, self).__init__(*args, **kw)

    def add_default_params(self):
        for args, kw in DEFAULT_PARAMS:
            self.add_param(*args, **kw)

    def _parse_keyvalues(self, args):
        kv = {}
        for x in args:
            key, value = x.split('=', 1)
            # make lists if there are multiple values
            if key.endswith('[]'):
                key = key[:-2]
                existing = kv.get(key, [])
                existing.append(value)
                kv[key] = existing
            else:
                kv[key] = value
        return kv


class DbSync(BaseApp):
    """Sync the database."""

    name = 'db_sync'

    def __init__(self, *args, **kw):
        super(DbSync, self).__init__(*args, **kw)

    def main(self):
        for k in ['identity', 'catalog', 'policy', 'token']:
            driver = utils.import_object(getattr(CONF, k).driver)
            if hasattr(driver, 'db_sync'):
                driver.db_sync()


CMDS = {'db_sync': DbSync,
        }


def print_commands(cmds):
    print
    print 'Available commands:'
    o = []
    max_length = max([len(k) for k in cmds]) + 2
    for k, cmd in sorted(cmds.iteritems()):
        initial_indent = '%s%s: ' % (' ' * (max_length - len(k)), k)
        tw = textwrap.TextWrapper(initial_indent=initial_indent,
                                  subsequent_indent=' ' * (max_length + 2),
                                  width=80)
        o.extend(tw.wrap(
            (cmd.__doc__ and cmd.__doc__ or 'no docs').strip().split('\n')[0]))
    print '\n'.join(o)


def run(cmd, args):
    return CMDS[cmd](argv=args).run()


def main(argv=None, config_files=None):
    CONF.reset()
    args = CONF(config_files=config_files, args=argv)

    if len(args) < 2:
        CONF.print_help()
        print_commands(CMDS)
        sys.exit(1)

    cmd = args[1]
    if cmd in CMDS:
        return run(cmd, (args[:1] + args[2:]))

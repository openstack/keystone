from __future__ import absolute_import

import json
import logging
import sys
import StringIO
import textwrap

import cli.app
import cli.log
from keystoneclient.v2_0 import client as kc

from keystone import config
from keystone.common import utils


CONF = config.CONF
CONF.set_usage('%prog COMMAND [key1=value1 key2=value2 ...]')
config.register_cli_str('endpoint',
                        default='http://localhost:$admin_port/v2.0',
                        #group='ks',
                        conf=CONF)
config.register_cli_str('auth-token',
                        default='$admin_token',
                        #group='ks',
                        help='authorization token',
                        conf=CONF)
config.register_cli_bool('id-only',
                         default=False,
                         #group='ks',
                         conf=CONF)


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


class ClientCommand(BaseApp):
    ACTION_MAP = None

    def _attr_name(self):
        return '%ss' % self.__class__.__name__.lower()

    def _cmd_name(self):
        return self.__class__.__name__.lower()

    def __init__(self, *args, **kw):
        super(ClientCommand, self).__init__(*args, **kw)
        if not self.ACTION_MAP:
            self.ACTION_MAP = {'help': 'help'}
        self.add_param('action', nargs='?', default='help')
        self.add_param('keyvalues', nargs='*')
        self.client = kc.Client(CONF.endpoint, token=CONF.auth_token)
        self.handle = getattr(self.client, self._attr_name())
        self._build_action_map()

    def _build_action_map(self):
        actions = {}
        for k in dir(self.handle):
            if not k.startswith('_'):
                actions[k] = k
        self.ACTION_MAP.update(actions)

    def main(self):
        """Given some keyvalues create the appropriate data in Keystone."""
        action_name = self.ACTION_MAP[self.params.action]
        if action_name == 'help':
            self.print_help()
            sys.exit(1)

        kv = self._parse_keyvalues(self.params.keyvalues)
        try:
            f = getattr(self.handle, action_name)
            resp = f(**kv)
        except Exception:
            logging.exception('')
            raise

        if CONF.id_only and getattr(resp, 'id'):
            print resp.id
            return

        if resp is None:
            return

        # NOTE(termie): this is ugly but it is mostly because the
        #               keystoneclient code doesn't give us very
        #               serializable instance objects
        if type(resp) in [type(list()), type(tuple())]:
            o = []
            for r in resp:
                d = {}
                for k, v in sorted(r.__dict__.iteritems()):
                    if k[0] == '_' or k == 'manager':
                        continue
                    d[k] = v
                o.append(d)
        else:
            o = {}
            for k, v in sorted(resp.__dict__.iteritems()):
                if k[0] == '_' or k == 'manager':
                    continue
                o[k] = v

        print json.dumps(o)

    def print_help(self):
        CONF.set_usage(CONF.usage.replace(
                'COMMAND', '%s SUBCOMMAND' % self._cmd_name()))
        CONF.print_help()

        methods = self._get_methods()
        print_commands(methods)

    def _get_methods(self):
        o = {}
        for k in dir(self.handle):
            if k.startswith('_'):
                continue
            if k in ('find', 'findall', 'api', 'resource_class'):
                continue
            o[k] = getattr(self.handle, k)
        return o


class Role(ClientCommand):
    """Role CRUD functions."""
    pass


class Service(ClientCommand):
    """Service CRUD functions."""
    pass


class Token(ClientCommand):
    """Token CRUD functions."""
    pass


class Tenant(ClientCommand):
    """Tenant CRUD functions."""
    pass


class User(ClientCommand):
    """User CRUD functions."""

    pass


class Ec2(ClientCommand):
    def _attr_name(self):
        return self.__class__.__name__.lower()


CMDS = {'db_sync': DbSync,
                'role': Role,
                'service': Service,
                'token': Token,
                'tenant': Tenant,
                'user': User,
                'ec2': Ec2,
                }


class CommandLineGenerator(object):
    """A keystoneclient lookalike to generate keystone-manage commands.

    One would use it like so:

    >>> gen = CommandLineGenerator(id_only=None)
    >>> cl = gen.ec2.create(user_id='foo', tenant_id='foo')
    >>> cl.to_argv()
    ... ['keystone-manage',
             '--id-only',
             'ec2',
             'create',
             'user_id=foo',
             'tenant_id=foo']

    """

    cmd = 'keystone-manage'

    def __init__(self, cmd=None, execute=False, **kw):
        if cmd:
            self.cmd = cmd
        self.flags = kw
        self.execute = execute

    def __getattr__(self, key):
        return _Manager(self, key)


class _Manager(object):
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name

    def __getattr__(self, key):
        return _CommandLine(cmd=self.parent.cmd,
                                                flags=self.parent.flags,
                                                manager=self.name,
                                                method=key,
                                                execute=self.parent.execute)


class _CommandLine(object):
    def __init__(self, cmd, flags, manager, method, execute=False):
        self.cmd = cmd
        self.flags = flags
        self.manager = manager
        self.method = method
        self.execute = execute
        self.kw = {}

    def __call__(self, **kw):
        self.kw = kw
        if self.execute:
            logging.debug('generated cli: %s', str(self))
            out = StringIO.StringIO()
            old_out = sys.stdout
            sys.stdout = out
            try:
                main(self.to_argv())
            except SystemExit as e:
                pass
            finally:
                sys.stdout = old_out
            rv = out.getvalue().strip().split('\n')[-1]
            try:
                loaded = json.loads(rv)
                if type(loaded) in [type(list()), type(tuple())]:
                    return [DictWrapper(**x) for x in loaded]
                elif type(loaded) is type(dict()):
                    return DictWrapper(**loaded)
            except Exception:
                logging.exception('Could not parse JSON: %s', rv)
                return rv
        return self

    def __flags(self):
        o = []
        for k, v in self.flags.iteritems():
            k = k.replace('_', '-')
            if v is None:
                o.append('--%s' % k)
            else:
                o.append('--%s=%s' % (k, str(v)))
        return o

    def __manager(self):
        if self.manager.endswith('s'):
            return self.manager[:-1]
        return self.manager

    def __kw(self):
        o = []
        for k, v in self.kw.iteritems():
            o.append('%s=%s' % (k, str(v)))
        return o

    def to_argv(self):
        return ([self.cmd]
                        + self.__flags()
                        + [self.__manager(), self.method]
                        + self.__kw())

    def __str__(self):
        args = self.to_argv()
        return ' '.join(args[:1] + ['"%s"' % x for x in args[1:]])


class DictWrapper(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


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

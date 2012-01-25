from __future__ import absolute_import

import logging
import os
import sys
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
config.register_cli_str('auth_token',
                        default='$admin_token',
                        #group='ks',
                        help='asdasd',
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
    print resp

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


def print_commands(cmds):
  print
  print "Available commands:"
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
  args = CONF(config_files=config_files, args=argv)
  if len(args) < 2:
    CONF.print_help()
    print_commands(CMDS)
    sys.exit(1)

  cmd = args[1]
  if cmd in CMDS:
    return run(cmd, (args[:1] + args[2:]))

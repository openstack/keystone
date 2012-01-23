"""OpenStack Identity (Keystone) Management"""


import argparse
import optparse
import os
import pkgutil
import sys

from keystone.common import config as legacy_config
from keystone import config
from keystone.manage2 import commands

CONF = config.CONF

# builds a complete path to the commands package
PACKAGE_PATH = os.path.dirname(commands.__file__)

# builds a list of modules in the commands package
MODULES = [tupl for tupl in pkgutil.iter_modules([PACKAGE_PATH])]


def load_module(module_name):
    """Imports a module given the module name"""
    try:
        module_loader, name, _is_package = [md for md in MODULES
                if md[1] == module_name][0]
    except IndexError:
        raise ValueError("No module found named '%s'" % module_name)

    loader = module_loader.find_module(name)
    module = loader.load_module(name)
    return module


# pylint: disable=W0612
def init_config():
    """Uses legacy config module to parse out legacy settings and provide
    them to the new cfg.py parser.

    This is a hack until we find a better way to have cfg.py ignore
    unknown arguments
    """

    class SilentOptParser(optparse.OptionParser):
        """ Class used to prevent OptionParser from exiting when it detects
        invalid options coming in """
        def exit(self, status=0, msg=None):
            pass

        def error(self, msg):
            pass

    # Initialize a parser for our configuration paramaters
    parser = SilentOptParser()
    legacy_config.add_common_options(parser)
    legacy_config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = legacy_config.parse_options(parser)
    (legacy_args, unknown_args) = parser.parse_args()

    cfgfile = getattr(legacy_args, 'config_file', None)
    if cfgfile:
        known_args = ['--config-file', cfgfile]
    else:
        known_args = []

    # Use the legacy code to find the config file
    config_file = legacy_config.find_config_file(options, known_args)

    # Now init the CONF for the backends using only known args
    old_args = sys.argv[:]
    sys.argv = known_args
    try:
        CONF(config_files=[config_file])
    except StandardError:
        raise
    finally:
        sys.argv = old_args


def main():
    # discover command modules
    module_names = [name for _, name, _ in MODULES]

    # build an argparser for keystone manage itself
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='command',
            help='Management commands')

    # append each command as a subparser
    for module_name in module_names:
        module = load_module(module_name)
        subparser = subparsers.add_parser(module_name,
                help=module.Command.__doc__)

        module.Command.append_parser(subparser)

    # actually parse the command line args or print help
    args = parser.parse_args()

    # configure and run command
    init_config()
    module = load_module(args.command)
    cmd = module.Command()
    exit(cmd.run(args))

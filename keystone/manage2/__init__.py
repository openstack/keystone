"""OpenStack Identity (Keystone) Management"""


import argparse
import os
import pkgutil

from keystone.manage2 import commands
from keystone.manage2 import common


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

        cmd = module.Command(options=common.get_options())
        cmd.append_parser(subparser)

    # actually parse the command line args or print help
    args = parser.parse_args()

    # configure and run command
    module = load_module(args.command)
    cmd = module.Command(options=common.get_options())
    exit(cmd.run(args))

import optparse
import sys

from keystone import backends
from keystone import config as new_config
from keystone import version
from keystone.common import config
from keystone.managers.credential import Manager as CredentialManager
from keystone.managers.endpoint import Manager as EndpointManager
from keystone.managers.endpoint_template import Manager as \
        EndpointTemplateManager
from keystone.managers.grant import Manager as GrantManager
from keystone.managers.role import Manager as RoleManager
from keystone.managers.service import Manager as ServiceManager
from keystone.managers.tenant import Manager as TenantManager
from keystone.managers.token import Manager as TokenManager
from keystone.managers.user import Manager as UserManager


def arg(name, **kwargs):
    """Decorate the command class with an argparse argument"""
    def _decorator(cls):
        if not hasattr(cls, '_args'):
            setattr(cls, '_args', {})
        args = getattr(cls, '_args')
        args[name] = kwargs
        return cls
    return _decorator


def get_options():
    # Initialize a parser for our configuration paramaters
    parser = optparse.OptionParser("Usage", version='%%prog %s'
        % version.version())
    config.add_common_options(parser)
    config.add_log_options(parser)

    # Parse command-line and load config
    (options, args) = config.parse_options(parser, [])  # pylint: disable=W0612

    return options


def init_managers():
    """Initializes backend storage and return managers"""
    if new_config.CONF.backends is None:
        # Get merged config and CLI options and admin-specific settings
        options = get_options()
        config_file = config.find_config_file(options, sys.argv[1:])
        new_config.CONF(config_files=[config_file])

    backends.configure_backends()

    managers = {}
    managers['credential_manager'] = CredentialManager()
    managers['token_manager'] = TokenManager()
    managers['tenant_manager'] = TenantManager()
    managers['endpoint_manager'] = EndpointManager()
    managers['endpoint_template_manager'] = EndpointTemplateManager()
    managers['user_manager'] = UserManager()
    managers['role_manager'] = RoleManager()
    managers['grant_manager'] = GrantManager()
    managers['service_manager'] = ServiceManager()
    return managers

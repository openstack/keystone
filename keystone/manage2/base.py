import argparse

from keystone import config
from keystone.manage2 import common


class BaseCommand(object):
    """Provides a common pattern for keystone-manage commands"""

    # pylint: disable=W0613
    def __init__(self, *args, **kwargs):
        self.parser = argparse.ArgumentParser(prog=self.__module__,
            description=self.__doc__)
        self.append_parser(self.parser)

    def true_or_false(self, args, positive, negative):
        """Evaluates a complementary pair of args to determine True/False.

        Fails if both args were provided.

        """

        if getattr(args, positive) and getattr(args, negative):
            self.parser.error("Unable to apply both: --%s and --%s" % (
                tuple([x.replace('_', '-') for x in (positive, negative)])))

        return getattr(args, positive) and not getattr(args, negative)

    @classmethod
    def append_parser(cls, parser):
        """Appends this command's arguments to an argparser

        :param parser: argparse.ArgumentParser
        """
        args = getattr(cls, '_args', {})

        for name in args.keys():
            try:
                parser.add_argument(name, **args[name])
            except TypeError:
                print "Unable to add argument (%s) %s" % (name, args[name])
                raise

    def run(self, args):
        """Handles argparse args and prints command results to stdout

        :param args: argparse Namespace
        """
        raise NotImplementedError()


# pylint: disable=W0223
class BaseSqlalchemyCommand(BaseCommand):
    """Common functionality for database management commands"""

    def __init__(self, *args, **kwargs):
        super(BaseSqlalchemyCommand, self).__init__(*args, **kwargs)

    @staticmethod
    def _get_connection_string():
        sqla = config.CONF['keystone.backends.sqlalchemy']
        return sqla.sql_connection


# pylint: disable=E1101,W0223
class BaseBackendCommand(BaseCommand):
    """Common functionality for commands requiring backend access"""

    def __init__(self, managers=None, *args, **kwargs):
        super(BaseBackendCommand, self).__init__(*args, **kwargs)

        # we may need to initialize our own managers
        managers = managers or common.init_managers()

        # managers become available as self.attributes
        for name, manager in managers.iteritems():
            setattr(self, name, manager)

    @staticmethod
    def _get(obj_name, manager, id=None):
        """Get an object from a manager, or fail if not found"""
        if id is not None:
            obj = manager.get(id)

            if obj is None:
                raise KeyError("%s ID not found: %s" % (obj_name, id))

            return obj

    def get_user(self, id):
        return BaseBackendCommand._get("User", self.user_manager, id)

    def get_tenant(self, id):
        return BaseBackendCommand._get("Tenant", self.tenant_manager, id)

    def get_token(self, id):
        return BaseBackendCommand._get("Token", self.token_manager, id)

    def get_credential(self, id):
        return BaseBackendCommand._get("Credential", self.credential_manager,
                id)

    def get_role(self, id):
        return BaseBackendCommand._get("Role", self.role_manager, id)

    def get_service(self, id):
        return BaseBackendCommand._get("Service", self.service_manager, id)

    def get_endpoint_template(self, id):
        return BaseBackendCommand._get("Endpoint Template",
                self.endpoint_template_manager, id)

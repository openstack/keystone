from keystone.backends.sqlalchemy import migration
from keystone import version
from keystone.manage2 import base
from keystone.manage2 import common
from keystone.logic.types import fault


@common.arg('--api', action='store_true',
    default=False,
    help='only print the API version')
@common.arg('--implementation', action='store_true',
    default=False,
    help='only print the implementation version')
@common.arg('--database', action='store_true',
    default=False,
    help='only print the database version')
class Command(base.BaseSqlalchemyCommand):
    """Returns keystone version data.

    Provides the latest API version, implementation version, database version,
    or all of the above, if none is specified.
    """

    @staticmethod
    def get_api_version():
        """Returns a complete API version string"""
        return ' '.join([version.API_VERSION, version.API_VERSION_STATUS])

    @staticmethod
    def get_implementation_version():
        """Returns a complete implementation version string"""
        return version.version()

    @staticmethod
    def get_database_version():
        """Returns database's current migration level"""
        return migration.db_version(Command._get_connection_string())

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        show_all = not (args.api or args.implementation or args.database)

        if args.api or show_all:
            print 'API v%s' % Command.get_api_version()
        if args.implementation or show_all:
            print 'Implementation v%s' % Command.get_implementation_version()
        if args.database or show_all:
            try:
                version_str = 'v%s' % (self.get_database_version())
            except fault.DatabaseMigrationError:
                version_str = 'not under version control'

            print 'Database %s' % (version_str)

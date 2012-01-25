from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--version',
    required=False,
    help='specify the desired database version')
class Command(base.BaseSqlalchemyCommand):
    """Upgrades the database to the latest schema."""

    @staticmethod
    def sync_database(version=None):
        """Place database under migration control & automatically upgrade"""
        migration.db_sync(Command._get_connection_string(), version=version)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.sync_database(version=args.version)

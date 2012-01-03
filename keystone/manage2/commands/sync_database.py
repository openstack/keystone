from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--version',
    required=False,
    help='specify the desired database version')
class Command(base.BaseSqlalchemyCommand):
    """Upgrades the database to the latest schema."""

    def sync_database(self, version=None):
        """Place database under migration control & automatically upgrade"""
        migration.db_sync(self.options, version=version)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.sync_database(version=args.version)

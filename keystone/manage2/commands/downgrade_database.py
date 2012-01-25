from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--version',
    required=True,
    help='specify the desired database version')
class Command(base.BaseSqlalchemyCommand):
    """Downgrades the database to the specified version"""

    @staticmethod
    def downgrade_database(version):
        """Downgrade database to the specified version"""
        migration.downgrade(Command._get_connection_string(), version=version)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.downgrade_database(version=args.version)

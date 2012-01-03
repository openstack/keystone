from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--version',
    required=True,
    help='specify the desired database version')
class Command(base.BaseSqlalchemyCommand):
    """Downgrades the database to the specified version"""

    def downgrade_database(self, version):
        """Downgrade database to the specified version"""
        migration.downgrade(self.options, version=version)

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.downgrade_database(version=args.version)

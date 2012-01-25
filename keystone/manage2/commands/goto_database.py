from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base
from keystone.manage2 import common


@common.arg('--version',
    required=True,
    help='specify the desired database version')
class Command(base.BaseSqlalchemyCommand):
    """Jumps to the specified database version without running migrations.

    Useful for initializing your version control at a version other than zero
    (e.g. you have an existing post-diablo database).

    """

    @staticmethod
    def goto_database_version(version):
        """Override database's current migration level"""
        if not migration.db_goto_version(Command._get_connection_string(),
                                         version):
            raise Exception("Unable to jump to specified version")

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.goto_database_version(version=args.version)

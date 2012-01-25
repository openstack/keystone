from keystone.backends.sqlalchemy import migration
from keystone.manage2 import base


class Command(base.BaseSqlalchemyCommand):
    """Places an existing database under version control."""

    @staticmethod
    def version_control_database():
        """Place database under migration control"""
        migration.version_control(Command._get_connection_string())

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.version_control_database()

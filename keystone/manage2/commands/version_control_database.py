from keystone.backends.sqlalchemy import migration
from keystone import config
from keystone.manage2 import base


class Command(base.BaseSqlalchemyCommand):
    """Places an existing database under version control."""

    @staticmethod
    def _get_connection_string():
        sqla = config.CONF['keystone.backends.sqlalchemy']
        return sqla.sql_connection

    @staticmethod
    def version_control_database():
        """Place database under migration control"""
        migration.version_control(Command._get_connection_string())

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        self.version_control_database()

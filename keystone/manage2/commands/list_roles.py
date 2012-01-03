from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all roles in the system."""

    # pylint: disable=E1101
    def get_roles(self):
        return self.role_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["ID", "Name", "Service ID", "Description"])

        for obj in self.get_roles():
            row = [obj.id, obj.name, obj.service_id, obj.desc]
            table.add_row(row)

        self.print_table(table)

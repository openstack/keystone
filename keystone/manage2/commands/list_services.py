from keystone.manage2 import base
from keystone.manage2 import mixins


class Command(base.BaseBackendCommand, mixins.ListMixin):
    """Lists all services in the system."""

    # pylint: disable=E1101
    def get_services(self):
        return self.service_manager.get_all()

    def run(self, args):
        """Process argparse args, and print results to stdout"""
        table = self.build_table(["ID", "Name", "Type", "Owner ID",
            "Description"])

        for obj in self.get_services():
            row = [obj.id, obj.name, obj.type, obj.owner_id, obj.desc]
            table.add_row(row)

        self.print_table(table)

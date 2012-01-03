import datetime
import prettytable


class ListMixin(object):
    """Implements common patterns for list_* commands"""

    @staticmethod
    def build_table(fields):
        table = prettytable.PrettyTable(fields)

        # set default alignment
        for field in fields:
            table.set_field_align(field, "l")

        return table

    @staticmethod
    def print_table(table):
        if "Name" in table.fields:
            table.printt(sortby="Name")
        else:
            table.printt()


class DateTimeMixin(object):
    datetime_format = '%Y-%m-%dT%H:%M'

    def datetime_to_str(self, dt):
        """Return a string representing the given datetime"""
        return dt.strftime(self.datetime_format)

    def str_to_datetime(self, string):
        """Return a datetime representing the given string"""
        return datetime.datetime.strptime(string, self.datetime_format)

    @staticmethod
    def get_datetime_tomorrow():
        """Returns a datetime representing 24 hours from now"""
        today = datetime.datetime.utcnow()
        tomorrow = today + datetime.timedelta(days=1)
        return tomorrow

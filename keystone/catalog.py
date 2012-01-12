# vim: tabstop=4 shiftwidth=4 softtabstop=4

from keystone import config
from keystone import manager


CONF = config.CONF


class Manager(manager.Manager):
    def __init__(self):
        super(Manager, self).__init__(CONF.catalog.driver)

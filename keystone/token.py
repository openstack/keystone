# vim: tabstop=4 shiftwidth=4 softtabstop=4

# the token interfaces

import uuid

from keystone import config
from keystone import logging
from keystone import utils


CONF = config.CONF


class Manager(object):
    def __init__(self):
        self.driver = utils.import_object(CONF.token.driver)

    def create_token(self, context, data):
        token = uuid.uuid4().hex
        data['id'] = token
        token_ref = self.driver.create_token(token, data)
        return token_ref

    @logging.log_debug
    def get_token(self, context, token_id):
        """Return info for a token if it is valid."""
        return self.driver.get_token(token_id)

    def delete_token(self, context, token_id):
        self.driver.delete_token(token_id)

# vim: tabstop=4 shiftwidth=4 softtabstop=4

"""Main entry point into the Token service."""

import datetime

from keystone import config
from keystone.common import manager


CONF = config.CONF
config.register_int('expiration', group='token', default=86400)


class Manager(manager.Manager):
    """Default pivot point for the Token backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.token.driver)


class Driver(object):
    """Interface description for a Token driver."""

    def get_token(self, token_id):
        """Get a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: token_ref
        :raises: keystone.exception.TokenNotFound

        """
        raise NotImplementedError()

    def create_token(self, token_id, data):
        """Create a token by id and data.

        :param token_id: identity of the token
        :type token_id: string
        :param data: dictionary with additional reference information

        ::

            {
                expires=''
                id=token_id,
                user=user_ref,
                tenant=tenant_ref,
                metadata=metadata_ref
            }

        :type data: dict
        :returns: token_ref or None.

        """
        raise NotImplementedError()

    def delete_token(self, token_id):
        """Deletes a token by id.

        :param token_id: identity of the token
        :type token_id: string
        :returns: None.
        :raises: keystone.exception.TokenNotFound

        """
        raise NotImplementedError()

    def _get_default_expire_time(self):
        """Determine when a token should expire based on the config.

        :returns: datetime.datetime object

        """
        expire_delta = datetime.timedelta(seconds=CONF.token.expiration)
        return datetime.datetime.now() + expire_delta

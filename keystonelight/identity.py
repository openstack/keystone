# vim: tabstop=4 shiftwidth=4 softtabstop=4

# these will be the basic data types for tenants and users
# backends will make use of them to return something that conforms to their apis


import hflags as flags

from keystonelight import utils


FLAGS = flags.FLAGS
flags.DEFINE_string('identity_driver',
                    'keystonelight.backends.pam.PamIdentity',
                    'identity driver to handle identity requests')


class Manager(object):
    def __init__(self):
        self.driver = utils.import_object(FLAGS.identity_driver)


    def authenticate(self, context, **kwargs):
        """Passthru authentication to the identity driver.

        This call will basically just result in getting a token.
        """
        return self.driver.authenticate(**kwargs)

    def get_tenants(self, context, user_id):
        return self.driver.get_tenants(user_id)

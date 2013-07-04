
import os
import webtest

from keystone import test


def _generate_paste_config():
    # Generate a file, based on keystone-paste.ini, that doesn't include
    # admin_token_auth in the pipeline

    with open(test.etcdir('keystone-paste.ini'), 'r') as f:
        contents = f.read()

    new_contents = contents.replace(' admin_token_auth ', ' ')

    with open(test.tmpdir('no_admin_token_auth-paste.ini'), 'w') as f:
        f.write(new_contents)


class TestNoAdminTokenAuth(test.TestCase):
    def setUp(self):
        super(TestNoAdminTokenAuth, self).setUp()
        self.load_backends()

        _generate_paste_config()

        self.admin_app = webtest.TestApp(
            self.loadapp(test.tmpdir('no_admin_token_auth'), name='admin'),
            extra_environ=dict(REMOTE_ADDR='127.0.0.1'))

    def tearDown(self):
        self.admin_app = None
        os.remove(test.tmpdir('no_admin_token_auth-paste.ini'))

    def test_request_no_admin_token_auth(self):
        # This test verifies that if the admin_token_auth middleware isn't
        # in the paste pipeline that users can still make requests.

        # Note(blk-u): Picked /v2.0/tenants because it's an operation that
        # requires is_admin in the context, any operation that requires
        # is_admin would work for this test.
        REQ_PATH = '/v2.0/tenants'

        # If the following does not raise, then the test is successful.
        self.admin_app.get(REQ_PATH, headers={'X-Auth-Token': 'NotAdminToken'},
                           status=401)

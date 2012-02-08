import webob

from keystone import test
from keystone.common import wsgi


class FakeApp(wsgi.Application):
    def index(self, context):
        return {'a': 'b'}


class ApplicationTest(test.TestCase):
    def setUp(self):
        self.app = FakeApp()

    def _make_request(self):
        req = webob.Request.blank('/')
        args = {'action': 'index', 'controller': self.app}
        req.environ['wsgiorg.routing_args'] = [None, args]
        return req

    def test_response_content_type(self):
        req = self._make_request()
        resp = req.get_response(self.app)
        self.assertEqual(resp.content_type, 'application/json')

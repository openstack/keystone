from . import AdminTestCase

class TestContentTypes(AdminTestCase):
    def test_simple(self):
        self.request(path='/v2.0/')

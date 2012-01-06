import json
from lxml import etree
import unittest2 as unittest

from keystone.models import User
from keystone.test import utils as testutils


class TestModelsUser(unittest.TestCase):
    '''Unit tests for keystone/models.py:User class.'''

    def test_user(self):
        user = User()
        self.assertEquals(str(user.__class__),
                          "<class 'keystone.models.User'>",
                          "user should be of instance "
                          "class keystone.models.User but instead "
                          "was '%s'" % str(user.__class__))
        self.assertIsInstance(user, dict, "")

    def test_user_static_properties(self):
        user = User(id=1, name="the user", blank=None)
        self.assertEquals(user.id, 1)
        self.assertEquals(user.name, "the user")
        self.assertRaises(AttributeError, getattr, user,
                          'some_bad_property')

    def test_user_properties(self):
        user = User(id=1, name="the user", blank=None)
        user["dynamic"] = "test"
        self.assertEquals(user["dynamic"], "test")

    def test_user_json_serialization(self):
        user = User(id=1, name="the user", blank=None)
        user["dynamic"] = "test"
        json_str = user.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"user": {"name": "the user", \
                          "id": 1, "dynamic": "test"}}')
        self.assertDictEqual(d1, d2)

    def test_user_xml_serialization(self):
        user = User(id=1, name="the user", blank=None)
        xml_str = user.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<user name="the user" id="1"/>'))

    def test_user_json_deserialization(self):
        user = User.from_json('{"name": "the user", "id": 1}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(user, User)
        self.assertEquals(user.id, 1)
        self.assertEquals(user.name, "the user")

    def test_user_xml_deserialization(self):
        user = User(id=1, name="the user", blank=None)
        self.assertIsInstance(user, User)

    def test_user_inspection(self):
        user = User(id=1, name="the user", blank=None)
        self.assertFalse(user.inspect())

    def test_user_validation(self):
        user = User(id=1, name="the user", blank=None)
        self.assertTrue(user.validate())


if __name__ == '__main__':
    unittest.main()

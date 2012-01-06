import json
from lxml import etree
import unittest2 as unittest

from keystone.models import Token
from keystone.test import utils as testutils


class TestModelsToken(unittest.TestCase):
    '''Unit tests for keystone/models.py:Token class.'''

    def test_token(self):
        token = Token()
        self.assertEquals(str(token.__class__),
                          "<class 'keystone.models.Token'>",
                          "token should be of instance "
                          "class keystone.models.Token but instead "
                          "was '%s'" % str(token.__class__))
        self.assertIsInstance(token, dict, "")

    def test_token_static_properties(self):
        token = Token(id=1, name="the token", enabled=True, blank=None)
        self.assertEquals(token.id, 1)
        self.assertEquals(token.name, "the token")
        self.assertTrue(token.enabled)
        self.assertRaises(AttributeError, getattr, token,
                          'some_bad_property')

    def test_token_properties(self):
        token = Token(id=1, name="the token", blank=None)
        token["dynamic"] = "test"
        self.assertEquals(token["dynamic"], "test")

    def test_token_json_serialization(self):
        token = Token(id=1, name="the token", blank=None)
        token["dynamic"] = "test"
        json_str = token.to_json()
        d1 = json.loads(json_str)
        d2 = json.loads('{"token": {"name": "the token", \
                          "id": 1, "dynamic": "test"}}')
        self.assertDictEqual(d1, d2)

    def test_token_xml_serialization(self):
        token = Token(id=1, name="the token", blank=None)
        xml_str = token.to_xml()
        self.assertTrue(testutils.XMLTools.xmlEqual(xml_str,
                        '<token id="1" name="the token"/>'))

    def test_token_json_deserialization(self):
        token = Token.from_json('{"name": "the token", "id": 1}',
                            hints={"contract_attributes": ['id', 'name']})
        self.assertIsInstance(token, Token)
        self.assertEquals(token.id, 1)
        self.assertEquals(token.name, "the token")

    def test_token_xml_deserialization(self):
        token = Token(id=1, name="the token", blank=None)
        self.assertIsInstance(token, Token)

    def test_token_inspection(self):
        token = Token(id=1, name="the token", blank=None)
        self.assertFalse(token.inspect())

    def test_token_validation(self):
        token = Token(id=1, name="the token", blank=None)
        self.assertTrue(token.validate())


if __name__ == '__main__':
    unittest.main()

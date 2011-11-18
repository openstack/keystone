import unittest2 as unittest
from keystone import utils


class TestStringEmpty(unittest.TestCase):
    '''Unit tests for string functions of utils.py.'''

    def test_is_empty_for_a_valid_string(self):
        self.assertFalse(utils.is_empty_string('asdfgf'))

    def test_is_empty_for_a_blank_string(self):
        self.assertTrue(utils.is_empty_string(''))

    def test_is_empty_for_none(self):
        self.assertTrue(utils.is_empty_string(None))

    def test_is_empty_for_a_number(self):
        self.assertFalse(utils.is_empty_string(0))

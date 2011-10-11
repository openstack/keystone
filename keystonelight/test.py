import os
import unittest


ROOTDIR = os.path.dirname(os.path.dirname(__file__))
VENDOR = os.path.join(ROOTDIR, 'vendor')


class TestCase(unittest.TestCase):
  def assertDictEquals(self, expected, actual):
    for k in expected:
      self.assertTrue(k in actual,
                      "Expected key %s not in %s." % (k, actual))
      self.assertEquals(expected[k], actual[k],
                        "Expected value for %s to be '%s', not '%s'."
                            % (k, expected[k], actual[k]))
    for k in actual:
      self.assertTrue(k in expected,
                      "Unexpected key %s in %s." % (k, actual))


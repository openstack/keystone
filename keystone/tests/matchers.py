# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import six

from lxml import etree
from testtools import matchers


class XMLEquals(object):
    """Parses two XML documents from strings and compares the results.

    """

    def __init__(self, expected):
        self.expected = expected

    def __str__(self):
        return "%s(%r)" % (self.__class__.__name__, self.expected)

    def match(self, other):
        parser = etree.XMLParser(remove_blank_text=True)

        def canonical_xml(s):
            s = s.strip()

            fp = six.StringIO()
            dom = etree.fromstring(s, parser)
            dom.getroottree().write_c14n(fp)
            s = fp.getvalue()

            dom = etree.fromstring(s, parser)
            return etree.tostring(dom, pretty_print=True)

        expected = canonical_xml(self.expected)
        other = canonical_xml(other)
        if expected == other:
            return
        return XMLMismatch(expected, other)


class XMLMismatch(matchers.Mismatch):

    def __init__(self, expected, other):
        self.expected = expected
        self.other = other

    def describe(self):
        return 'expected = %s\nactual = %s' % (self.expected, self.other)

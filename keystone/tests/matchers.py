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
        def xml_element_equals(expected_doc, observed_doc):
            """Tests whether two XML documents are equivalent.

            This is a recursive algorithm that operates on each element in
            the hierarchy. Siblings are sorted before being checked to
            account for two semantically equivalent documents where siblings
            appear in different document order.

            The sorting algorithm is a little weak in that it could fail for
            documents where siblings at a given level are the same, but have
            different children.

            """

            if expected_doc.tag != observed_doc.tag:
                return False

            if expected_doc.attrib != observed_doc.attrib:
                return False

            def _sorted_children(doc):
                return sorted(doc.getchildren(), key=lambda el: el.tag)

            expected_children = _sorted_children(expected_doc)
            observed_children = _sorted_children(observed_doc)

            if len(expected_children) != len(observed_children):
                return False

            for expected_el, observed_el in zip(expected_children,
                                                observed_children):
                if not xml_element_equals(expected_el, observed_el):
                    return False

            return True

        parser = etree.XMLParser(remove_blank_text=True)
        expected_doc = etree.fromstring(self.expected.strip(), parser)
        observed_doc = etree.fromstring(other.strip(), parser)

        if xml_element_equals(expected_doc, observed_doc):
            return

        return XMLMismatch(self.expected, other)


class XMLMismatch(matchers.Mismatch):

    def __init__(self, expected, other):
        self.expected = expected
        self.other = other

    def describe(self):
        def pretty_xml(xml):
            parser = etree.XMLParser(remove_blank_text=True)
            doc = etree.fromstring(xml.strip(), parser)
            return (etree.tostring(doc, encoding='utf-8', pretty_print=True)
                    .decode('utf-8'))

        return 'expected =\n%s\nactual =\n%s' % (
            pretty_xml(self.expected), pretty_xml(self.other))

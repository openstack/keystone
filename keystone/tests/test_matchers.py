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

from testtools.tests.matchers import helpers

from keystone import tests
from keystone.tests import matchers


class TestXMLEquals(tests.BaseTestCase, helpers.TestMatchersInterface):
    matches_xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<test xmlns="http://docs.openstack.org/identity/api/v2.0">
    <first z="0" y="1" x="2"/>
    <second a="a" b="b"></second>
</test>
"""
    equivalent_xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<test xmlns="http://docs.openstack.org/identity/api/v2.0">
    <second a="a" b="b"/>
    <first z="0" y="1" x="2"></first>
</test>
"""
    mismatches_xml = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<test xmlns="http://docs.openstack.org/identity/api/v2.0">
    <nope_it_fails/>
</test>
"""
    mismatches_description = """\
expected =
<test xmlns="http://docs.openstack.org/identity/api/v2.0">
  <first z="0" y="1" x="2"/>
  <second a="a" b="b"/>
</test>

actual =
<test xmlns="http://docs.openstack.org/identity/api/v2.0">
  <nope_it_fails/>
</test>
"""

    matches_matcher = matchers.XMLEquals(matches_xml)
    matches_matches = [matches_xml, equivalent_xml]
    matches_mismatches = [mismatches_xml]
    describe_examples = [
        (mismatches_description, mismatches_xml, matches_matcher),
    ]
    str_examples = [('XMLEquals(%r)' % matches_xml, matches_matcher)]

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

# NOTE(morganfainberg) This file shouldn't have flake8 run on it as it has
# code examples that will fail normal CI pep8/flake8 tests. This is expected.
# The code has been moved here to ensure that proper tests occur on the
# test_hacking_checks test cases.
# flake8: noqa

import fixtures


class HackingCode(fixtures.Fixture):
    """A fixture to house the various code examples for the keystone hacking
    style checks.
    """

    mutable_default_args = {
        'code': """
                def f():
                    pass

                def f(a, b='', c=None):
                    pass

                def f(bad=[]):
                    pass

                def f(foo, bad=[], more_bad=[x for x in range(3)]):
                    pass

                def f(foo, bad={}):
                    pass

                def f(foo, bad={}, another_bad=[], fine=None):
                    pass

                def f(bad=[]): # noqa
                    pass

            """,
        'expected_errors': [
            (7, 10, 'K001'),
            (10, 15, 'K001'),
            (10, 29, 'K001'),
            (13, 15, 'K001'),
            (16, 15, 'K001'),
            (16, 31, 'K001'),
        ]}

    comments_begin_with_space = {
        'code': """
            # This is a good comment

            #This is a bad one

            # This is alright and can
            #    be continued with extra indentation
            #    if that's what the developer wants.
        """,
        'expected_errors': [
            (3, 0, 'K002'),
        ]}

    asserting_none_equality = {
        'code': """
            class Test(object):

                def test(self):
                    self.assertEqual('', '')
                    self.assertEqual('', None)
                    self.assertEqual(None, '')
                    self.assertNotEqual('', None)
                    self.assertNotEqual(None, '')
                    self.assertNotEqual('', None) # noqa
                    self.assertNotEqual(None, '') # noqa
        """,
        'expected_errors': [
            (5, 8, 'K003'),
            (6, 8, 'K003'),
            (7, 8, 'K004'),
            (8, 8, 'K004'),
        ]}

    assert_no_translations_for_debug_logging = {
        'code': """
            import logging
            import logging as stlib_logging
            from keystone.i18n import _
            from keystone.i18n import _ as oslog_i18n
            from keystone.openstack.common import log
            from keystone.openstack.common import log as oslo_logging

            # stdlib logging
            L0 = logging.getLogger()
            L0.debug(_('text'))
            class C:
                def __init__(self):
                    L0.debug(oslog_i18n('text', {}))

            # stdlib logging w/ alias and specifying a logger
            class C:
                def __init__(self):
                    self.L1 = logging.getLogger(__name__)
                def m(self):
                    self.L1.debug(
                        _('text'), {}
                    )

            # oslo logging and specifying a logger
            L2 = log.getLogger(__name__)
            L2.debug(oslog_i18n('text'))

            # oslo logging w/ alias
            class C:
                def __init__(self):
                    self.L3 = oslo_logging.getLogger()
                    self.L3.debug(_('text'))

            # translation on a separate line
            msg = _('text')
            L2.debug(msg)
        """,
        'expected_errors': [
            (10, 9, 'K005'),
            (13, 17, 'K005'),
            (21, 12, 'K005'),
            (26, 9, 'K005'),
            (32, 22, 'K005'),
            (36, 9, 'K005'),
        ]
    }

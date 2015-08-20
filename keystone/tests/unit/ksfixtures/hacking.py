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

                def funcs(bad=dict(), more_bad=list(), even_more_bad=set()):
                    "creating mutables through builtins"

                def funcs(bad=something(), more_bad=some_object.something()):
                    "defaults from any functions"

                def f(bad=set(), more_bad={x for x in range(3)},
                       even_more_bad={1, 2, 3}):
                    "set and set comprehession"

                def f(bad={x: x for x in range(3)}):
                    "dict comprehension"
            """,
        'expected_errors': [
            (7, 10, 'K001'),
            (10, 15, 'K001'),
            (10, 29, 'K001'),
            (13, 15, 'K001'),
            (16, 15, 'K001'),
            (16, 31, 'K001'),
            (22, 14, 'K001'),
            (22, 31, 'K001'),
            (22, 53, 'K001'),
            (25, 14, 'K001'),
            (25, 36, 'K001'),
            (28, 10, 'K001'),
            (28, 27, 'K001'),
            (29, 21, 'K001'),
            (32, 11, 'K001'),
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
            from keystone.i18n import _ as oslo_i18n
            from oslo_log import log
            from oslo_log import log as oslo_logging

            # stdlib logging
            L0 = logging.getLogger()
            L0.debug(_('text'))
            class C:
                def __init__(self):
                    L0.debug(oslo_i18n('text', {}))

            # stdlib logging w/ alias and specifying a logger
            class C:
                def __init__(self):
                    self.L1 = logging.getLogger(__name__)
                def m(self):
                    self.L1.debug(
                        _('text'), {}
                    )

            # oslo logging and specifying a logger
            L2 = logging.getLogger(__name__)
            L2.debug(oslo_i18n('text'))

            # oslo logging w/ alias
            class C:
                def __init__(self):
                    self.L3 = oslo_logging.getLogger()
                    self.L3.debug(_('text'))

            # translation on a separate line
            msg = _('text')
            L2.debug(msg)

            # this should not fail
            if True:
                msg = _('message %s') % X
                L2.error(msg)
                raise TypeError(msg)
            if True:
                msg = 'message'
                L2.debug(msg)

            # this should not fail
            if True:
                if True:
                    msg = _('message')
                else:
                    msg = _('message')
                L2.debug(msg)
                raise Exception(msg)
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

    dict_constructor = {
        'code': """
            lower_res = {k.lower(): v for k, v in six.iteritems(res[1])}
            fool = dict(a='a', b='b')
            lower_res = dict((k.lower(), v) for k, v in six.iteritems(res[1]))
            attrs = dict([(k, _from_json(v))])
            dict([[i,i] for i in range(3)])
            dict(({1:2}))
        """,
        'expected_errors': [
            (3, 0, 'K008'),
            (4, 0, 'K008'),
            (5, 0, 'K008'),
        ]}


class HackingLogging(fixtures.Fixture):

    shared_imports = """
                import logging
                import logging as stlib_logging
                from keystone.i18n import _
                from keystone.i18n import _ as oslo_i18n
                from keystone.i18n import _LC
                from keystone.i18n import _LE
                from keystone.i18n import _LE as error_hint
                from keystone.i18n import _LI
                from keystone.i18n import _LW
                from oslo_log import log
                from oslo_log import log as oslo_logging
    """

    examples = [
        {
            'code': """
                # stdlib logging
                LOG = logging.getLogger()
                LOG.info(_('text'))
                class C:
                    def __init__(self):
                        LOG.warn(oslo_i18n('text', {}))
                        LOG.warn(_LW('text', {}))
            """,
            'expected_errors': [
                (3, 9, 'K006'),
                (6, 17, 'K006'),
            ],
        },
        {
            'code': """
                # stdlib logging w/ alias and specifying a logger
                class C:
                    def __init__(self):
                        self.L = logging.getLogger(__name__)
                    def m(self):
                        self.L.warning(
                            _('text'), {}
                        )
                        self.L.warning(
                            _LW('text'), {}
                        )
            """,
            'expected_errors': [
                (7, 12, 'K006'),
            ],
        },
        {
            'code': """
                # oslo logging and specifying a logger
                L = log.getLogger(__name__)
                L.error(oslo_i18n('text'))
                L.error(error_hint('text'))
            """,
            'expected_errors': [
                (3, 8, 'K006'),
            ],
        },
        {
            'code': """
                # oslo logging w/ alias
                class C:
                    def __init__(self):
                        self.LOG = oslo_logging.getLogger()
                        self.LOG.critical(_('text'))
                        self.LOG.critical(_LC('text'))
            """,
            'expected_errors': [
                (5, 26, 'K006'),
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                # translation on a separate line
                msg = _('text')
                LOG.exception(msg)
                msg = _LE('text')
                LOG.exception(msg)
            """,
            'expected_errors': [
                (4, 14, 'K006'),
            ],
        },
        {
            'code': """
                LOG = logging.getLogger()

                # ensure the correct helper is being used
                LOG.warn(_LI('this should cause an error'))

                # debug should not allow any helpers either
                LOG.debug(_LI('this should cause an error'))
            """,
            'expected_errors': [
                (4, 9, 'K006'),
                (7, 10, 'K005'),
            ],
        },
        {
            'code': """
                # this should not be an error
                L = log.getLogger(__name__)
                msg = _('text')
                L.warn(msg)
                raise Exception(msg)
            """,
            'expected_errors': [],
        },
        {
            'code': """
                L = log.getLogger(__name__)
                def f():
                    msg = _('text')
                    L2.warn(msg)
                    something = True  # add an extra statement here
                    raise Exception(msg)
            """,
            'expected_errors': [],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                def func():
                    msg = _('text')
                    LOG.warn(msg)
                    raise Exception('some other message')
            """,
            'expected_errors': [
                (4, 13, 'K006'),
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                if True:
                    msg = _('text')
                else:
                    msg = _('text')
                LOG.warn(msg)
                raise Exception(msg)
            """,
            'expected_errors': [
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                if True:
                    msg = _('text')
                else:
                    msg = _('text')
                LOG.warn(msg)
            """,
            'expected_errors': [
                (6, 9, 'K006'),
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                msg = _LW('text')
                LOG.warn(msg)
                raise Exception(msg)
            """,
            'expected_errors': [
                (3, 9, 'K007'),
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                msg = _LW('text')
                LOG.warn(msg)
                msg = _('something else')
                raise Exception(msg)
            """,
            'expected_errors': [],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                msg = _LW('hello %s') % 'world'
                LOG.warn(msg)
                raise Exception(msg)
            """,
            'expected_errors': [
                (3, 9, 'K007'),
            ],
        },
        {
            'code': """
                LOG = log.getLogger(__name__)
                msg = _LW('hello %s') % 'world'
                LOG.warn(msg)
            """,
            'expected_errors': [],
        },
        {
            'code': """
                # this should not be an error
                LOG = log.getLogger(__name__)
                try:
                    something = True
                except AssertionError as e:
                    LOG.warning(six.text_type(e))
                    raise exception.Unauthorized(e)
            """,
            'expected_errors': [],
        },
    ]

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystone.common import base64utils
from keystone import tests

base64_alphabet = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                   'abcdefghijklmnopqrstuvwxyz'
                   '0123456789'
                   '+/=')       # includes pad char

base64url_alphabet = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                      'abcdefghijklmnopqrstuvwxyz'
                      '0123456789'
                      '-_=')    # includes pad char


class TestValid(tests.TestCase):
    def test_valid_base64(self):
        self.assertTrue(base64utils.is_valid_base64('+/=='))
        self.assertTrue(base64utils.is_valid_base64('+/+='))
        self.assertTrue(base64utils.is_valid_base64('+/+/'))

        self.assertFalse(base64utils.is_valid_base64('-_=='))
        self.assertFalse(base64utils.is_valid_base64('-_-='))
        self.assertFalse(base64utils.is_valid_base64('-_-_'))

        self.assertTrue(base64utils.is_valid_base64('abcd'))
        self.assertFalse(base64utils.is_valid_base64('abcde'))
        self.assertFalse(base64utils.is_valid_base64('abcde=='))
        self.assertFalse(base64utils.is_valid_base64('abcdef'))
        self.assertTrue(base64utils.is_valid_base64('abcdef=='))
        self.assertFalse(base64utils.is_valid_base64('abcdefg'))
        self.assertTrue(base64utils.is_valid_base64('abcdefg='))
        self.assertTrue(base64utils.is_valid_base64('abcdefgh'))

        self.assertFalse(base64utils.is_valid_base64('-_=='))

    def test_valid_base64url(self):
        self.assertFalse(base64utils.is_valid_base64url('+/=='))
        self.assertFalse(base64utils.is_valid_base64url('+/+='))
        self.assertFalse(base64utils.is_valid_base64url('+/+/'))

        self.assertTrue(base64utils.is_valid_base64url('-_=='))
        self.assertTrue(base64utils.is_valid_base64url('-_-='))
        self.assertTrue(base64utils.is_valid_base64url('-_-_'))

        self.assertTrue(base64utils.is_valid_base64url('abcd'))
        self.assertFalse(base64utils.is_valid_base64url('abcde'))
        self.assertFalse(base64utils.is_valid_base64url('abcde=='))
        self.assertFalse(base64utils.is_valid_base64url('abcdef'))
        self.assertTrue(base64utils.is_valid_base64url('abcdef=='))
        self.assertFalse(base64utils.is_valid_base64url('abcdefg'))
        self.assertTrue(base64utils.is_valid_base64url('abcdefg='))
        self.assertTrue(base64utils.is_valid_base64url('abcdefgh'))

        self.assertTrue(base64utils.is_valid_base64url('-_=='))


class TestBase64Padding(tests.TestCase):

    def test_filter(self):
        self.assertEqual(base64utils.filter_formatting(''), '')
        self.assertEqual(base64utils.filter_formatting(' '), '')
        self.assertEqual(base64utils.filter_formatting('a'), 'a')
        self.assertEqual(base64utils.filter_formatting(' a'), 'a')
        self.assertEqual(base64utils.filter_formatting('a '), 'a')
        self.assertEqual(base64utils.filter_formatting('ab'), 'ab')
        self.assertEqual(base64utils.filter_formatting(' ab'), 'ab')
        self.assertEqual(base64utils.filter_formatting('ab '), 'ab')
        self.assertEqual(base64utils.filter_formatting('a b'), 'ab')
        self.assertEqual(base64utils.filter_formatting(' a b'), 'ab')
        self.assertEqual(base64utils.filter_formatting('a b '), 'ab')
        self.assertEqual(base64utils.filter_formatting('a\nb\n '), 'ab')

        text = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                'abcdefghijklmnopqrstuvwxyz'
                '0123456789'
                '+/=')
        self.assertEqual(base64_alphabet,
                         base64utils.filter_formatting(text))

        text = (' ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
                ' abcdefghijklmnopqrstuvwxyz\n'
                '\t\f\r'
                ' 0123456789\n'
                ' +/=')
        self.assertEqual(base64_alphabet,
                         base64utils.filter_formatting(text))
        self.assertEqual(base64url_alphabet,
                         base64utils.base64_to_base64url(base64_alphabet))

        text = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                'abcdefghijklmnopqrstuvwxyz'
                '0123456789'
                '-_=')
        self.assertEqual(base64url_alphabet,
                         base64utils.filter_formatting(text))

        text = (' ABCDEFGHIJKLMNOPQRSTUVWXYZ\n'
                ' abcdefghijklmnopqrstuvwxyz\n'
                '\t\f\r'
                ' 0123456789\n'
                '-_=')
        self.assertEqual(base64url_alphabet,
                         base64utils.filter_formatting(text))

    def test_alphabet_conversion(self):
        self.assertEqual(base64url_alphabet,
                         base64utils.base64_to_base64url(base64_alphabet))

        self.assertEqual(base64_alphabet,
                         base64utils.base64url_to_base64(base64url_alphabet))

    def test_is_padded(self):
        self.assertTrue(base64utils.base64_is_padded('ABCD'))
        self.assertTrue(base64utils.base64_is_padded('ABC='))
        self.assertTrue(base64utils.base64_is_padded('AB=='))

        self.assertTrue(base64utils.base64_is_padded('1234ABCD'))
        self.assertTrue(base64utils.base64_is_padded('1234ABC='))
        self.assertTrue(base64utils.base64_is_padded('1234AB=='))

        self.assertFalse(base64utils.base64_is_padded('ABC'))
        self.assertFalse(base64utils.base64_is_padded('AB'))
        self.assertFalse(base64utils.base64_is_padded('A'))
        self.assertFalse(base64utils.base64_is_padded(''))

        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64_is_padded, '=')

        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64_is_padded, 'AB=C')

        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64_is_padded, 'AB=')

        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64_is_padded, 'ABCD=')

    def test_strip_padding(self):
        self.assertEqual(base64utils.base64_strip_padding('ABCD'), 'ABCD')
        self.assertEqual(base64utils.base64_strip_padding('ABC='), 'ABC')
        self.assertEqual(base64utils.base64_strip_padding('AB=='), 'AB')

    def test_assure_padding(self):
        self.assertEqual(base64utils.base64_assure_padding('ABCD'), 'ABCD')
        self.assertEqual(base64utils.base64_assure_padding('ABC'), 'ABC=')
        self.assertEqual(base64utils.base64_assure_padding('ABC='), 'ABC=')
        self.assertEqual(base64utils.base64_assure_padding('AB'), 'AB==')
        self.assertEqual(base64utils.base64_assure_padding('AB=='), 'AB==')

    def test_base64_percent_encoding(self):
        self.assertEqual(base64utils.base64url_percent_encode('ABCD'), 'ABCD')
        self.assertEqual(base64utils.base64url_percent_encode('ABC='),
                         'ABC%3D')
        self.assertEqual(base64utils.base64url_percent_encode('AB=='),
                         'AB%3D%3D')

        self.assertEqual(base64utils.base64url_percent_decode('ABCD'), 'ABCD')
        self.assertEqual(base64utils.base64url_percent_decode('ABC%3D'),
                         'ABC=')
        self.assertEqual(base64utils.base64url_percent_decode('AB%3D%3D'),
                         'AB==')


class TestTextWrap(tests.TestCase):

    def test_wrapping(self):
        raw_text = 'abcdefgh'
        wrapped_text = 'abc\ndef\ngh\n'

        self.assertEqual(base64utils.base64_wrap(raw_text, width=3),
                         wrapped_text)

        t = '\n'.join(base64utils.base64_wrap_iter(raw_text, width=3)) + '\n'
        self.assertEqual(t, wrapped_text)

        raw_text = 'abcdefgh'
        wrapped_text = 'abcd\nefgh\n'

        self.assertEqual(base64utils.base64_wrap(raw_text, width=4),
                         wrapped_text)

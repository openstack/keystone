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
from keystone.tests import unit

base64_alphabet = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                   'abcdefghijklmnopqrstuvwxyz'
                   '0123456789'
                   '+/=')       # includes pad char

base64url_alphabet = ('ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                      'abcdefghijklmnopqrstuvwxyz'
                      '0123456789'
                      '-_=')    # includes pad char


class TestValid(unit.BaseTestCase):
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


class TestBase64Padding(unit.BaseTestCase):

    def test_filter(self):
        self.assertEqual('', base64utils.filter_formatting(''))
        self.assertEqual('', base64utils.filter_formatting(' '))
        self.assertEqual('a', base64utils.filter_formatting('a'))
        self.assertEqual('a', base64utils.filter_formatting(' a'))
        self.assertEqual('a', base64utils.filter_formatting('a '))
        self.assertEqual('ab', base64utils.filter_formatting('ab'))
        self.assertEqual('ab', base64utils.filter_formatting(' ab'))
        self.assertEqual('ab', base64utils.filter_formatting('ab '))
        self.assertEqual('ab', base64utils.filter_formatting('a b'))
        self.assertEqual('ab', base64utils.filter_formatting(' a b'))
        self.assertEqual('ab', base64utils.filter_formatting('a b '))
        self.assertEqual('ab', base64utils.filter_formatting('a\nb\n '))

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

        self.assertRaises(ValueError, base64utils.base64_is_padded,
                          'ABC', pad='==')
        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64_is_padded, 'A=BC')

    def test_strip_padding(self):
        self.assertEqual('ABCD', base64utils.base64_strip_padding('ABCD'))
        self.assertEqual('ABC', base64utils.base64_strip_padding('ABC='))
        self.assertEqual('AB', base64utils.base64_strip_padding('AB=='))
        self.assertRaises(ValueError, base64utils.base64_strip_padding,
                          'ABC=', pad='==')
        self.assertEqual('ABC', base64utils.base64_strip_padding('ABC'))

    def test_assure_padding(self):
        self.assertEqual('ABCD', base64utils.base64_assure_padding('ABCD'))
        self.assertEqual('ABC=', base64utils.base64_assure_padding('ABC'))
        self.assertEqual('ABC=', base64utils.base64_assure_padding('ABC='))
        self.assertEqual('AB==', base64utils.base64_assure_padding('AB'))
        self.assertEqual('AB==', base64utils.base64_assure_padding('AB=='))
        self.assertRaises(ValueError, base64utils.base64_assure_padding,
                          'ABC', pad='==')

    def test_base64_percent_encoding(self):
        self.assertEqual('ABCD', base64utils.base64url_percent_encode('ABCD'))
        self.assertEqual('ABC%3D',
                         base64utils.base64url_percent_encode('ABC='))
        self.assertEqual('AB%3D%3D',
                         base64utils.base64url_percent_encode('AB=='))

        self.assertEqual('ABCD', base64utils.base64url_percent_decode('ABCD'))
        self.assertEqual('ABC=',
                         base64utils.base64url_percent_decode('ABC%3D'))
        self.assertEqual('AB==',
                         base64utils.base64url_percent_decode('AB%3D%3D'))
        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64url_percent_encode, 'chars')
        self.assertRaises(base64utils.InvalidBase64Error,
                          base64utils.base64url_percent_decode, 'AB%3D%3')


class TestTextWrap(unit.BaseTestCase):

    def test_wrapping(self):
        raw_text = 'abcdefgh'
        wrapped_text = 'abc\ndef\ngh\n'

        self.assertEqual(wrapped_text,
                         base64utils.base64_wrap(raw_text, width=3))

        t = '\n'.join(base64utils.base64_wrap_iter(raw_text, width=3)) + '\n'
        self.assertEqual(wrapped_text, t)

        raw_text = 'abcdefgh'
        wrapped_text = 'abcd\nefgh\n'

        self.assertEqual(wrapped_text,
                         base64utils.base64_wrap(raw_text, width=4))

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

import base64
from keystone.common import pemutils
from keystone import tests


# List of 2-tuples, (pem_type, pem_header)
headers = pemutils.PEM_TYPE_TO_HEADER.items()


def make_data(size, offset=0):
    return ''.join([chr(x % 255) for x in xrange(offset, size + offset)])


def make_base64_from_data(data):
    return base64.b64encode(data)


def wrap_base64(base64_text):
    wrapped_text = '\n'.join([base64_text[x:x + 64]
                              for x in xrange(0, len(base64_text), 64)])
    wrapped_text += '\n'
    return wrapped_text


def make_pem(header, data):
    base64_text = make_base64_from_data(data)
    wrapped_text = wrap_base64(base64_text)

    result = '-----BEGIN %s-----\n' % header
    result += wrapped_text
    result += '-----END %s-----\n' % header

    return result


class PEM(object):
    """PEM text and it's associated data broken out, used for testing.

    """
    def __init__(self, pem_header='CERTIFICATE', pem_type='cert',
                 data_size=70, data_offset=0):
        self.pem_header = pem_header
        self.pem_type = pem_type
        self.data_size = data_size
        self.data_offset = data_offset
        self.data = make_data(self.data_size, self.data_offset)
        self.base64_text = make_base64_from_data(self.data)
        self.wrapped_base64 = wrap_base64(self.base64_text)
        self.pem_text = make_pem(self.pem_header, self.data)


class TestPEMParseResult(tests.TestCase):

    def test_pem_types(self):
        for pem_type in pemutils.pem_types:
            pem_header = pemutils.PEM_TYPE_TO_HEADER[pem_type]
            r = pemutils.PEMParseResult(pem_type=pem_type)
            self.assertEqual(pem_type, r.pem_type)
            self.assertEqual(pem_header, r.pem_header)

        pem_type = 'xxx'
        self.assertRaises(ValueError,
                          pemutils.PEMParseResult, pem_type=pem_type)

    def test_pem_headers(self):
        for pem_header in pemutils.pem_headers:
            pem_type = pemutils.PEM_HEADER_TO_TYPE[pem_header]
            r = pemutils.PEMParseResult(pem_header=pem_header)
            self.assertEqual(pem_type, r.pem_type)
            self.assertEqual(pem_header, r.pem_header)

        pem_header = 'xxx'
        self.assertRaises(ValueError,
                          pemutils.PEMParseResult, pem_header=pem_header)


class TestPEMParse(tests.TestCase):
    def test_parse_none(self):
        text = ''
        text += 'bla bla\n'
        text += 'yada yada yada\n'
        text += 'burfl blatz bingo\n'

        parse_results = pemutils.parse_pem(text)
        self.assertEqual(len(parse_results), 0)

        self.assertEqual(pemutils.is_pem(text), False)

    def test_parse_invalid(self):
        p = PEM(pem_type='xxx',
                pem_header='XXX')
        text = p.pem_text

        self.assertRaises(ValueError,
                          pemutils.parse_pem, text)

    def test_parse_one(self):
        data_size = 70
        count = len(headers)
        pems = []

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            p = pems[i]
            text = p.pem_text

            parse_results = pemutils.parse_pem(text)
            self.assertEqual(len(parse_results), 1)

            r = parse_results[0]
            self.assertEqual(p.pem_type, r.pem_type)
            self.assertEqual(p.pem_header, r.pem_header)
            self.assertEqual(p.pem_text,
                             text[r.pem_start:r.pem_end])
            self.assertEqual(p.wrapped_base64,
                             text[r.base64_start:r.base64_end])
            self.assertEqual(p.data, r.binary_data)

    def test_parse_one_embedded(self):
        p = PEM(data_offset=0)
        text = ''
        text += 'bla bla\n'
        text += 'yada yada yada\n'
        text += p.pem_text
        text += 'burfl blatz bingo\n'

        parse_results = pemutils.parse_pem(text)
        self.assertEqual(len(parse_results), 1)

        r = parse_results[0]
        self.assertEqual(p.pem_type, r.pem_type)
        self.assertEqual(p.pem_header, r.pem_header)
        self.assertEqual(p.pem_text,
                         text[r.pem_start:r.pem_end])
        self.assertEqual(p.wrapped_base64,
                         text[r.base64_start: r.base64_end])
        self.assertEqual(p.data, r.binary_data)

    def test_parse_multple(self):
        data_size = 70
        count = len(headers)
        pems = []
        text = ''

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            text += pems[i].pem_text

        parse_results = pemutils.parse_pem(text)
        self.assertEqual(len(parse_results), count)

        for i in xrange(count):
            r = parse_results[i]
            p = pems[i]

            self.assertEqual(p.pem_type, r.pem_type)
            self.assertEqual(p.pem_header, r.pem_header)
            self.assertEqual(p.pem_text,
                             text[r.pem_start:r.pem_end])
            self.assertEqual(p.wrapped_base64,
                             text[r.base64_start: r.base64_end])
            self.assertEqual(p.data, r.binary_data)

    def test_parse_multple_find_specific(self):
        data_size = 70
        count = len(headers)
        pems = []
        text = ''

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            text += pems[i].pem_text

        for i in xrange(count):
            parse_results = pemutils.parse_pem(text, pem_type=headers[i][0])
            self.assertEqual(len(parse_results), 1)

            r = parse_results[0]
            p = pems[i]

            self.assertEqual(p.pem_type, r.pem_type)
            self.assertEqual(p.pem_header, r.pem_header)
            self.assertEqual(p.pem_text,
                             text[r.pem_start:r.pem_end])
            self.assertEqual(p.wrapped_base64,
                             text[r.base64_start:r.base64_end])
            self.assertEqual(p.data, r.binary_data)

    def test_parse_multple_embedded(self):
        data_size = 75
        count = len(headers)
        pems = []
        text = ''

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            text += 'bla bla\n'
            text += 'yada yada yada\n'
            text += pems[i].pem_text
            text += 'burfl blatz bingo\n'

        parse_results = pemutils.parse_pem(text)
        self.assertEqual(len(parse_results), count)

        for i in xrange(count):
            r = parse_results[i]
            p = pems[i]

            self.assertEqual(p.pem_type, r.pem_type)
            self.assertEqual(p.pem_header, r.pem_header)
            self.assertEqual(p.pem_text,
                             text[r.pem_start:r.pem_end])
            self.assertEqual(p.wrapped_base64,
                             text[r.base64_start:r.base64_end])
            self.assertEqual(p.data, r.binary_data)

    def test_get_pem_data_none(self):
        text = ''
        text += 'bla bla\n'
        text += 'yada yada yada\n'
        text += 'burfl blatz bingo\n'

        data = pemutils.get_pem_data(text)
        self.assertEqual(None, data)

    def test_get_pem_data_invalid(self):
        p = PEM(pem_type='xxx',
                pem_header='XXX')
        text = p.pem_text

        self.assertRaises(ValueError,
                          pemutils.get_pem_data, text)

    def test_get_pem_data(self):
        data_size = 70
        count = len(headers)
        pems = []

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            p = pems[i]
            text = p.pem_text

            data = pemutils.get_pem_data(text, p.pem_type)
            self.assertEqual(p.data, data)

    def test_is_pem(self):
        data_size = 70
        count = len(headers)
        pems = []

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            p = pems[i]
            text = p.pem_text
            self.assertTrue(pemutils.is_pem(text, pem_type=p.pem_type))
            self.assertFalse(pemutils.is_pem(text,
                                             pem_type=p.pem_type + 'xxx'))

    def test_base64_to_pem(self):
        data_size = 70
        count = len(headers)
        pems = []

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            p = pems[i]
            pem = pemutils.base64_to_pem(p.base64_text, p.pem_type)
            self.assertEqual(pemutils.get_pem_data(pem, p.pem_type), p.data)

    def test_binary_to_pem(self):
        data_size = 70
        count = len(headers)
        pems = []

        for i in xrange(count):
            pems.append(PEM(pem_type=headers[i][0],
                            pem_header=headers[i][1],
                            data_size=data_size + i,
                            data_offset=i))

        for i in xrange(count):
            p = pems[i]
            pem = pemutils.binary_to_pem(p.data, p.pem_type)
            self.assertEqual(pemutils.get_pem_data(pem, p.pem_type), p.data)

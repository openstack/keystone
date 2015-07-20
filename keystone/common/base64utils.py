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

"""

Python provides the base64 module as a core module but this is mostly
limited to encoding and decoding base64 and it's variants. It is often
useful to be able to perform other operations on base64 text. This
module is meant to be used in conjunction with the core base64 module.

Standardized base64 is defined in
RFC-4648 "The Base16, Base32, and Base64 Data Encodings".

This module provides the following base64 utility functionality:

    * tests if text is valid base64
    * filter formatting from base64
    * convert base64 between different alphabets
    * Handle padding issues
        - test if base64 is padded
        - removes padding
        - restores padding
    * wraps base64 text into formatted blocks
        - via iterator
        - return formatted string

"""

import re
import string

import six
from six.moves import urllib

from keystone.i18n import _


class InvalidBase64Error(ValueError):
    pass

base64_alphabet_re = re.compile(r'^[^A-Za-z0-9+/=]+$')
base64url_alphabet_re = re.compile(r'^[^A-Za-z0-9---_=]+$')

base64_non_alphabet_re = re.compile(r'[^A-Za-z0-9+/=]+')
base64url_non_alphabet_re = re.compile(r'[^A-Za-z0-9---_=]+')

_strip_formatting_re = re.compile(r'\s+')

if six.PY2:
    str_ = string
else:
    str_ = str

_base64_to_base64url_trans = str_.maketrans('+/', '-_')
_base64url_to_base64_trans = str_.maketrans('-_', '+/')


def _check_padding_length(pad):
    if len(pad) != 1:
        raise ValueError(_('pad must be single character'))


def is_valid_base64(text):
    """Test if input text can be base64 decoded.

    :param text: input base64 text
    :type text: string
    :returns: bool -- True if text can be decoded as base64, False otherwise
    """

    text = filter_formatting(text)

    if base64_non_alphabet_re.search(text):
        return False

    try:
        return base64_is_padded(text)
    except InvalidBase64Error:
        return False


def is_valid_base64url(text):
    """Test if input text can be base64url decoded.

    :param text: input base64 text
    :type text: string
    :returns: bool -- True if text can be decoded as base64url,
              False otherwise
    """

    text = filter_formatting(text)

    if base64url_non_alphabet_re.search(text):
        return False

    try:
        return base64_is_padded(text)
    except InvalidBase64Error:
        return False


def filter_formatting(text):
    """Return base64 text without any formatting, just the base64.

    Base64 text is often formatted with whitespace, line endings,
    etc. This function strips out any formatting, the result will
    contain only base64 characters.

    Note, this function does not filter out all non-base64 alphabet
    characters, it only removes characters used for formatting.

    :param text: input text to filter
    :type text: string
    :returns: string -- filtered text without formatting
    """
    return _strip_formatting_re.sub('', text)


def base64_to_base64url(text):
    """Convert base64 text to base64url text.

    base64url text is designed to be safe for use in file names and
    URL's. It is defined in RFC-4648 Section 5.

    base64url differs from base64 in the last two alphabet characters
    at index 62 and 63, these are sometimes referred as the
    altchars. The '+' character at index 62 is replaced by '-'
    (hyphen) and the '/' character at index 63 is replaced by '_'
    (underscore).

    This function only translates the altchars, non-alphabet
    characters are not filtered out.

    WARNING::

        base64url continues to use the '=' pad character which is NOT URL
        safe. RFC-4648 suggests two alternate methods to deal with this:

        percent-encode
            percent-encode the pad character (e.g. '=' becomes
            '%3D'). This makes the base64url text fully safe. But
            percent-encoding has the downside of requiring
            percent-decoding prior to feeding the base64url text into a
            base64url decoder since most base64url decoders do not
            recognize %3D as a pad character and most decoders require
            correct padding.

        no-padding
            padding is not strictly necessary to decode base64 or
            base64url text, the pad can be computed from the input text
            length. However many decoders demand padding and will consider
            non-padded text to be malformed. If one wants to omit the
            trailing pad character(s) for use in URL's it can be added back
            using the base64_assure_padding() function.

        This function makes no decisions about which padding methodology to
        use. One can either call base64_strip_padding() to remove any pad
        characters (restoring later with base64_assure_padding()) or call
        base64url_percent_encode() to percent-encode the pad characters.

    :param text: input base64 text
    :type text: string
    :returns: string -- base64url text
    """
    return text.translate(_base64_to_base64url_trans)


def base64url_to_base64(text):
    """Convert base64url text to base64 text.

    See base64_to_base64url() for a description of base64url text and
    it's issues.

    This function does NOT handle percent-encoded pad characters, they
    will be left intact. If the input base64url text is
    percent-encoded you should call

    :param text: text in base64url alphabet
    :type text: string
    :returns: string -- text in base64 alphabet

    """
    return text.translate(_base64url_to_base64_trans)


def base64_is_padded(text, pad='='):
    """Test if the text is base64 padded.

    The input text must be in a base64 alphabet. The pad must be a
    single character. If the text has been percent-encoded (e.g. pad
    is the string '%3D') you must convert the text back to a base64
    alphabet (e.g. if percent-encoded use the function
    base64url_percent_decode()).

    :param text: text containing ONLY characters in a base64 alphabet
    :type text: string
    :param pad: pad character (must be single character) (default: '=')
    :type pad: string
    :returns: bool -- True if padded, False otherwise
    :raises: ValueError, InvalidBase64Error
    """

    _check_padding_length(pad)

    text_len = len(text)
    if text_len > 0 and text_len % 4 == 0:
        pad_index = text.find(pad)
        if pad_index >= 0 and pad_index < text_len - 2:
            raise InvalidBase64Error(_('text is multiple of 4, '
                                       'but pad "%s" occurs before '
                                       '2nd to last char') % pad)
        if pad_index == text_len - 2 and text[-1] != pad:
            raise InvalidBase64Error(_('text is multiple of 4, '
                                       'but pad "%s" occurs before '
                                       'non-pad last char') % pad)
        return True

    if text.find(pad) >= 0:
        raise InvalidBase64Error(_('text is not a multiple of 4, '
                                   'but contains pad "%s"') % pad)
    return False


def base64url_percent_encode(text):
    """Percent-encode base64url padding.

    The input text should only contain base64url alphabet
    characters. Any non-base64url alphabet characters will also be
    subject to percent-encoding.

    :param text: text containing ONLY characters in the base64url alphabet
    :type text: string
    :returns: string -- percent-encoded base64url text
    :raises: InvalidBase64Error
    """

    if len(text) % 4 != 0:
        raise InvalidBase64Error(_('padded base64url text must be '
                                   'multiple of 4 characters'))

    return urllib.parse.quote(text)


def base64url_percent_decode(text):
    """Percent-decode base64url padding.

    The input text should only contain base64url alphabet
    characters and the percent-encoded pad character. Any other
    percent-encoded characters will be subject to percent-decoding.

    :param text: base64url alphabet text
    :type text: string
    :returns: string -- percent-decoded base64url text
    """

    decoded_text = urllib.parse.unquote(text)

    if len(decoded_text) % 4 != 0:
        raise InvalidBase64Error(_('padded base64url text must be '
                                   'multiple of 4 characters'))

    return decoded_text


def base64_strip_padding(text, pad='='):
    """Remove padding from input base64 text.

    :param text: text containing ONLY characters in a base64 alphabet
    :type text: string
    :param pad: pad character (must be single character) (default: '=')
    :type pad: string
    :returns: string -- base64 text without padding
    :raises: ValueError
    """
    _check_padding_length(pad)

    # Can't be padded if text is less than 4 characters.
    if len(text) < 4:
        return text

    if text[-1] == pad:
        if text[-2] == pad:
            return text[0:-2]
        else:
            return text[0:-1]
    else:
        return text


def base64_assure_padding(text, pad='='):
    """Assure the input text ends with padding.

    Base64 text is normally expected to be a multiple of 4
    characters. Each 4 character base64 sequence produces 3 octets of
    binary data. If the binary data is not a multiple of 3 the base64
    text is padded at the end with a pad character such that it is
    always a multiple of 4. Padding is ignored and does not alter the
    binary data nor it's length.

    In some circumstances it is desirable to omit the padding
    character due to transport encoding conflicts. Base64 text can
    still be correctly decoded if the length of the base64 text
    (consisting only of characters in the desired base64 alphabet) is
    known, padding is not absolutely necessary.

    Some base64 decoders demand correct padding or one may wish to
    format RFC compliant base64, this function performs this action.

    Input is assumed to consist only of members of a base64
    alphabet (i.e no whitespace). Iteration yields a sequence of lines.
    The line does NOT terminate with a line ending.

    Use the filter_formatting() function to assure the input text
    contains only the members of the alphabet.

    If the text ends with the pad it is assumed to already be
    padded. Otherwise the binary length is computed from the input
    text length and correct number of pad characters are appended.

    :param text: text containing ONLY characters in a base64 alphabet
    :type text: string
    :param pad: pad character (must be single character) (default: '=')
    :type pad: string
    :returns: string -- input base64 text with padding
    :raises: ValueError
    """
    _check_padding_length(pad)

    if text.endswith(pad):
        return text

    n = len(text) % 4
    if n == 0:
        return text

    n = 4 - n
    padding = pad * n
    return text + padding


def base64_wrap_iter(text, width=64):
    """Fold text into lines of text with max line length.

    Input is assumed to consist only of members of a base64
    alphabet (i.e no whitespace). Iteration yields a sequence of lines.
    The line does NOT terminate with a line ending.

    Use the filter_formatting() function to assure the input text
    contains only the members of the alphabet.

    :param text: text containing ONLY characters in a base64 alphabet
    :type text: string
    :param width: number of characters in each wrapped line (default: 64)
    :type width: int
    :returns: generator -- sequence of lines of base64 text.
    """

    text = six.text_type(text)
    for x in six.moves.range(0, len(text), width):
        yield text[x:x + width]


def base64_wrap(text, width=64):
    """Fold text into lines of text with max line length.

    Input is assumed to consist only of members of a base64
    alphabet (i.e no whitespace). Fold the text into lines whose
    line length is width chars long, terminate each line with line
    ending (default is '\\n'). Return the wrapped text as a single
    string.

    Use the filter_formatting() function to assure the input text
    contains only the members of the alphabet.

    :param text: text containing ONLY characters in a base64 alphabet
    :type text: string
    :param width: number of characters in each wrapped line (default: 64)
    :type width: int
    :returns: string -- wrapped text.
    """

    buf = six.StringIO()

    for line in base64_wrap_iter(text, width):
        buf.write(line)
        buf.write(u'\n')

    text = buf.getvalue()
    buf.close()
    return text

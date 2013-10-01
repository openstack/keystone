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


"""
PEM formatted data is used frequenlty in conjunction with X509 PKI as
a data exchange mechanism for binary data. The acronym PEM stands for
Privacy Enhanced Mail as defined in RFC-1421. Contrary to expectation
the PEM format in common use has little to do with RFC-1421. Instead
what we know as PEM format grew out of the need for a data exchange
mechanism largely by the influence of OpenSSL. Other X509
implementations have adopted it.

Unfortunately PEM format has never been officialy standarized. It's
basic format is as follows:

1) A header consisting of 5 hyphens followed by the word BEGIN and a
single space. Then an upper case string describing the contents of the
PEM block, this is followed by 5 hyphens and a newline.

2) Binary data (typically in DER ASN.1 format) encoded in base64. The
base64 text is line wrapped so that each line of base64 is 64
characters long and terminated with a newline. The last line of base64
text may be less than 64 characters. The content and format of the
binary data is entirely dependent upon the type of data announced in
the header and footer.

3) A footer in the exact same as the header execpt the word BEGIN is
replaced by END. The content name in both the header and footer should
exactly match.

The above is called a PEM block. It is permissible for multiple PEM
blocks to appear in a single file or block of text. This is often used
when specifying multiple X509 certificates.

An example PEM block for a certificate is:

-----BEGIN CERTIFICATE-----
MIIC0TCCAjqgAwIBAgIJANsHKV73HYOwMA0GCSqGSIb3DQEBBQUAMIGeMQowCAYD
VQQFEwE1MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVN1bm55
dmFsZTESMBAGA1UEChMJT3BlblN0YWNrMREwDwYDVQQLEwhLZXlzdG9uZTElMCMG
CSqGSIb3DQEJARYWa2V5c3RvbmVAb3BlbnN0YWNrLm9yZzEUMBIGA1UEAxMLU2Vs
ZiBTaWduZWQwIBcNMTIxMTA1MTgxODI0WhgPMjA3MTA0MzAxODE4MjRaMIGeMQow
CAYDVQQFEwE1MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVN1
bm55dmFsZTESMBAGA1UEChMJT3BlblN0YWNrMREwDwYDVQQLEwhLZXlzdG9uZTEl
MCMGCSqGSIb3DQEJARYWa2V5c3RvbmVAb3BlbnN0YWNrLm9yZzEUMBIGA1UEAxML
U2VsZiBTaWduZWQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALzI17ExCaqd
r7xY2Q5CBZ1bW1lsrXxS8eNJRdQtskDuQVAluY03/OGZd8HQYiiY/ci2tYy7BNIC
bh5GaO95eqTDykJR3liOYE/tHbY6puQlj2ZivmhlSd2d5d7lF0/H28RQsLu9VktM
uw6q9DpDm35jfrr8LgSeA3MdVqcS/4OhAgMBAAGjEzARMA8GA1UdEwEB/wQFMAMB
Af8wDQYJKoZIhvcNAQEFBQADgYEAjSQND7i1dNZtLKpWgX+JqMr3BdVlM15mFeVr
C26ZspZjZVY5okdozO9gU3xcwRe4Cg30sKFOe6EBQKpkTZucFOXwBtD3h6dWJrdD
c+m/CL/rs0GatDavbaIT2vv405SQUQooCdVh72LYel+4/a6xmRd7fQx3iEXN9QYj
vmHJUcA=
-----END CERTIFICATE-----

PEM format is safe for transmission in 7-bit ASCII systems
(i.e. standard email). Since 7-bit ASCII is a proper subset of UTF-8
and Latin-1 it is not affected by transcoding between those
charsets. Nor is PEM format affected by the choice of line
endings. This makes PEM format particularity attractive for transport
and storage of binary data.

This module provides a number of utilities supporting the generation
and consumption of PEM formatted data including:

    * parse text and find all PEM blocks contained in the
      text. Information on the location of the block in the text, the
      type of PEM block, and it's base64 and binary data contents.

    * parse text assumed to contain PEM data and return the binary
      data.

    * test if a block of text is a PEM block

    * convert base64 text into a formatted PEM block

    * convert binary data into a formatted PEM block

    * access to the valid PEM types and their headers

"""

import base64
import io
from keystone.common import base64utils
import re

PEM_TYPE_TO_HEADER = {
    u'cms': u'CMS',
    u'dsa-private': u'DSA PRIVATE KEY',
    u'dsa-public': u'DSA PUBLIC KEY',
    u'ecdsa-public': u'ECDSA PUBLIC KEY',
    u'ec-private': u'EC PRIVATE KEY',
    u'pkcs7': u'PKCS7',
    u'pkcs7-signed': u'PKCS',
    u'pkcs8': u'ENCRYPTED PRIVATE KEY',
    u'private-key': u'PRIVATE KEY',
    u'public-key': u'PUBLIC KEY',
    u'rsa-private': u'RSA PRIVATE KEY',
    u'rsa-public': u'RSA PUBLIC KEY',
    u'cert': u'CERTIFICATE',
    u'crl': u'X509 CRL',
    u'cert-pair': u'CERTIFICATE PAIR',
    u'csr': u'CERTIFICATE REQUEST',
}

# This is not a 1-to-1 reverse map of PEM_TYPE_TO_HEADER
# because it includes deprecated headers that map to 1 pem_type.
PEM_HEADER_TO_TYPE = {
    u'CMS': u'cms',
    u'DSA PRIVATE KEY': u'dsa-private',
    u'DSA PUBLIC KEY': u'dsa-public',
    u'ECDSA PUBLIC KEY': u'ecdsa-public',
    u'EC PRIVATE KEY': u'ec-private',
    u'PKCS7': u'pkcs7',
    u'PKCS': u'pkcs7-signed',
    u'ENCRYPTED PRIVATE KEY': u'pkcs8',
    u'PRIVATE KEY': u'private-key',
    u'PUBLIC KEY': u'public-key',
    u'RSA PRIVATE KEY': u'rsa-private',
    u'RSA PUBLIC KEY': u'rsa-public',
    u'CERTIFICATE': u'cert',
    u'X509 CERTIFICATE': u'cert',
    u'CERTIFICATE PAIR': u'cert-pair',
    u'X509 CRL': u'crl',
    u'CERTIFICATE REQUEST': u'csr',
    u'NEW CERTIFICATE REQUEST': u'csr',
}

# List of valid pem_types
pem_types = sorted(PEM_TYPE_TO_HEADER.keys())

# List of valid pem_headers
pem_headers = sorted(PEM_TYPE_TO_HEADER.values())

_pem_begin_re = re.compile(r'^-{5}BEGIN\s+([^-]+)-{5}\s*$', re.MULTILINE)
_pem_end_re = re.compile(r'^-{5}END\s+([^-]+)-{5}\s*$', re.MULTILINE)


class PEMParseResult(object):
    """Information returned when a PEM block is found in text.

    PEMParseResult contains information about a PEM block discovered
    while parsing text. The following properties are defined:

    pem_type
        A short hand name for the type of the PEM data, e.g. cert,
        csr, crl, cms, key. Valid pem_types are listed in pem_types.
        When the pem_type is set the pem_header is updated to match it.

    pem_header
        The text following '-----BEGIN ' in the PEM header.
        Common examples are:

            -----BEGIN CERTIFICATE-----
            -----BEGIN CMS-----

        Thus the pem_header would be CERTIFICATE and CMS respectively.
        When the pem_header is set the pem_type is updated to match it.

    pem_start, pem_end
        The beginning and ending positions of the PEM block
        including the PEM header and footer.

    base64_start, base64_end
        The beginning and ending positions of the base64 data
        contained inside the PEM header and footer. Includes trailing
        new line

    binary_data
        The decoded base64 data. None if not decoded.

    """

    def __init__(self, pem_type=None, pem_header=None,
                 pem_start=None, pem_end=None,
                 base64_start=None, base64_end=None,
                 binary_data=None):

        self._pem_type = None
        self._pem_header = None

        if pem_type is not None:
            self.pem_type = pem_type

        if pem_header is not None:
            self.pem_header = pem_header

        self.pem_start = pem_start
        self.pem_end = pem_end
        self.base64_start = base64_start
        self.base64_end = base64_end
        self.binary_data = binary_data

    @property
    def pem_type(self):
        return self._pem_type

    @pem_type.setter
    def pem_type(self, pem_type):
        if pem_type is None:
            self._pem_type = None
            self._pem_header = None
        else:
            pem_header = PEM_TYPE_TO_HEADER.get(pem_type)
            if pem_header is None:
                raise ValueError(_('unknown pem_type "%(pem_type)s", '
                                   'valid types are: %(valid_pem_types)s') %
                                 {'pem_type': pem_type,
                                  'valid_pem_types': ', '.join(pem_types)})
            self._pem_type = pem_type
            self._pem_header = pem_header

    @property
    def pem_header(self):
        return self._pem_header

    @pem_header.setter
    def pem_header(self, pem_header):
        if pem_header is None:
            self._pem_type = None
            self._pem_header = None
        else:
            pem_type = PEM_HEADER_TO_TYPE.get(pem_header)
            if pem_type is None:
                raise ValueError(_('unknown pem header "%(pem_header)s", '
                                   'valid headers are: '
                                   '%(valid_pem_headers)s') %
                                 {'pem_header': pem_header,
                                  'valid_pem_headers':
                                  ', '.join("'%s'" %
                                            [x for x in pem_headers])})

            self._pem_type = pem_type
            self._pem_header = pem_header

#------------------------------------------------------------------------------


def pem_search(text, start=0):
    """Search for a block of PEM formatted data

    Search for a PEM block in a text string. The search begins at
    start. If a PEM block is found a PEMParseResult object is
    returned, otherwise if no PEM block is found None is returned.

    If the pem_type is not the same in both the header and footer
    a ValueError is raised.

    The start and end positions are suitable for use as slices into
    the text. To search for multiple PEM blocks pass pem_end as the
    start position for the next iteration. Terminate the iteration
    when None is returned. Example:

        start = 0
        while True:
            block = pem_search(text, start)
            if block is None:
                break
            base64_data = text[block.base64_start : block.base64_end]
            start = block.pem_end

    :param text: the text to search for PEM blocks
    :type text: string
    :param start: the position in text to start searching from (default: 0)
    :type start: int
    :returns: PEMParseResult or None if not found
    :raises: ValueError
    """

    match = _pem_begin_re.search(text, pos=start)
    if match:
        pem_start = match.start()
        begin_text = match.group(0)
        base64_start = min(len(text), match.end() + 1)
        begin_pem_header = match.group(1).strip()

        match = _pem_end_re.search(text, pos=base64_start)
        if match:
            pem_end = min(len(text), match.end() + 1)
            base64_end = match.start()
            end_pem_header = match.group(1).strip()
        else:
            raise ValueError(_('failed to find end matching "%s"') %
                             begin_text)

        if begin_pem_header != end_pem_header:
            raise ValueError(_('beginning & end PEM headers do not match '
                               '(%(begin_pem_header)s'
                               '!= '
                               '%(end_pem_header)s)') %
                             {'begin_pem_header': begin_pem_header,
                              'end_pem_header': end_pem_header})
    else:
        return None

    result = PEMParseResult(pem_header=begin_pem_header,
                            pem_start=pem_start, pem_end=pem_end,
                            base64_start=base64_start, base64_end=base64_end)

    return result


def parse_pem(text, pem_type=None, max_items=None):
    """Scan text for PEM data, return list of PEM items

    The input text is scanned for PEM blocks, for each one found a
    PEMParseResult is contructed and added to the return list.

    pem_type operates as a filter on the type of PEM desired. If
    pem_type is specified only those PEM blocks which match will be
    included. The pem_type is a logical name, not the actual text in
    the pem header (e.g. 'cert'). If the pem_type is None all PEM
    blocks are returned.

    If max_items is specified the result is limited to that number of
    items.

    The return value is a list of PEMParseResult objects.  The
    PEMParseResult provides complete information about the PEM block
    including the decoded binary data for the PEM block.  The list is
    ordered in the same order as found in the text.

    Examples:

        # Get all certs
        certs = parse_pem(text, 'cert')

        # Get the first cert
        try:
            binary_cert = parse_pem(text, 'cert', 1)[0].binary_data
        except IndexError:
            raise ValueError('no cert found')

    :param text: The text to search for PEM blocks
    :type text: string
    :param pem_type: Only return data for this pem_type.
                     Valid types are: csr, cert, crl, cms, key.
                     If pem_type is None no filtering is performed.
                     (default: None)
    :type pem_type: string or None
    :param max_items: Limit the number of blocks returned. (default: None)
    :type max_items: int or None
    :return: List of PEMParseResult, one for each PEM block found
    :raises: ValueError, InvalidBase64Error
    """

    pem_blocks = []
    start = 0

    while True:
        block = pem_search(text, start)
        if block is None:
            break
        start = block.pem_end
        if pem_type is None:
            pem_blocks.append(block)
        else:
            try:
                if block.pem_type == pem_type:
                    pem_blocks.append(block)
            except KeyError:
                raise ValueError(_('unknown pem_type: "%s"') % (pem_type))

        if max_items is not None and len(pem_blocks) >= max_items:
            break

    for block in pem_blocks:
        base64_data = text[block.base64_start:block.base64_end]
        try:
            binary_data = base64.b64decode(base64_data)
        except Exception as e:
            block.binary_data = None
            raise base64utils.InvalidBase64Error(
                _('failed to base64 decode %(pem_type)s PEM at position'
                  '%(position)d: %(err_msg)s') %
                {'pem_type': block.pem_type,
                 'position': block.pem_start,
                 'err_msg': str(e)})
        else:
            block.binary_data = binary_data

    return pem_blocks


def get_pem_data(text, pem_type='cert'):
    """Scan text for PEM data, return binary contents

    The input text is scanned for a PEM block which matches the pem_type.
    If found the binary data contained in the PEM block is returned.
    If no PEM block is found or it does not match the specified pem type
    None is returned.

    :param text: The text to search for the PEM block
    :type text: string
    :param pem_type: Only return data for this pem_type.
                     Valid types are: csr, cert, crl, cms, key.
                     (default: 'cert')
    :type pem_type: string
    :return: binary data or None if not found.
    """

    blocks = parse_pem(text, pem_type, 1)
    if not blocks:
        return None
    return blocks[0].binary_data


def is_pem(text, pem_type='cert'):
    """Does this text contain a PEM block.

    Check for the existence of a PEM formatted block in the
    text, if one is found verify it's contents can be base64
    decoded, if so return True. Return False otherwise.

    :param text: The text to search for PEM blocks
    :type text: string
    :param pem_type: Only return data for this pem_type.
                     Valid types are: csr, cert, crl, cms, key.
                     (default: 'cert')
    :type pem_type: string
    :returns: bool -- True if text contains PEM matching the pem_type,
              False otherwise.
    """

    try:
        pem_blocks = parse_pem(text, pem_type, max_items=1)
    except base64utils.InvalidBase64Error:
        return False

    if pem_blocks:
        return True
    else:
        return False


def base64_to_pem(base64_text, pem_type='cert'):
    """Format string of base64 text into PEM format

    Input is assumed to consist only of members of the base64 alphabet
    (i.e no whitepace). Use one of the filter functions from
    base64utils to assure the input is clean
    (i.e. strip_whitespace()).

    :param base64_text: text containing ONLY base64 alphabet
                        characters to be inserted into PEM output.
    :type base64_text: string
    :param pem_type: Produce a PEM block for this type.
                     Valid types are: csr, cert, crl, cms, key.
                     (default: 'cert')
    :type pem_type: string
    :returns: string -- PEM formatted text


    """
    pem_header = PEM_TYPE_TO_HEADER[pem_type]
    buf = io.StringIO()

    buf.write(u'-----BEGIN %s-----' % pem_header)
    buf.write(u'\n')

    for line in base64utils.base64_wrap_iter(base64_text, width=64):
        buf.write(line)
        buf.write(u'\n')

    buf.write(u'-----END %s-----' % pem_header)
    buf.write(u'\n')

    text = buf.getvalue()
    buf.close()
    return text


def binary_to_pem(binary_data, pem_type='cert'):
    """Format binary data into PEM format

    Example:

        # get the certificate binary data in DER format
        der_data = certificate.der
        # convert the DER binary data into a PEM
        pem = binary_to_pem(der_data, 'cert')


    :param binary_data: binary data to encapsulate into PEM
    :type binary_data: buffer
    :param pem_type: Produce a PEM block for this type.
                     Valid types are: csr, cert, crl, cms, key.
                     (default: 'cert')
    :type pem_type: string
    :returns: string -- PEM formatted text

    """
    base64_text = base64.b64encode(binary_data)
    return base64_to_pem(base64_text, pem_type)

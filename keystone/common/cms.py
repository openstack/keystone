import os
import stat
import subprocess

from keystone.common import logging


LOG = logging.getLogger(__name__)
UUID_TOKEN_LENGTH = 32


def cms_verify(formatted, signing_cert_file_name, ca_file_name):
    """
        verifies the signature of the contents IAW CMS syntax
    """
    process = subprocess.Popen(["openssl", "cms", "-verify",
                                "-certfile", signing_cert_file_name,
                                "-CAfile", ca_file_name,
                                "-inform", "PEM",
                                "-nosmimecap", "-nodetach",
                                "-nocerts", "-noattr"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    output, err = process.communicate(formatted)
    retcode = process.poll()
    if retcode:
        LOG.error('Verify error: %s' % err)
        raise subprocess.CalledProcessError(retcode, "openssl", output=err)
    return output


def token_to_cms(signed_text):
    copy_of_text = signed_text.replace('-', '/')

    formatted = "-----BEGIN CMS-----\n"
    line_length = 64
    while len(copy_of_text) > 0:
        if (len(copy_of_text) > line_length):
            formatted += copy_of_text[:line_length]
            copy_of_text = copy_of_text[line_length:]
        else:
            formatted += copy_of_text
            copy_of_text = ""
        formatted += "\n"

    formatted += "-----END CMS-----\n"

    return formatted


def verify_token(token, signing_cert_file_name, ca_file_name):
    return cms_verify(token_to_cms(token),
                      signing_cert_file_name,
                      ca_file_name)


def cms_sign_text(text, signing_cert_file_name, signing_key_file_name):
    """ Uses OpenSSL to sign a document
    Produces a Base64 encoding of a DER formatted CMS Document
    http://en.wikipedia.org/wiki/Cryptographic_Message_Syntax
    """

    process = subprocess.Popen(["openssl", "cms", "-sign",
                                "-signer", signing_cert_file_name,
                                "-inkey", signing_key_file_name,
                                "-outform", "PEM",
                                "-nosmimecap", "-nodetach",
                                "-nocerts", "-noattr"],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    output, err = process.communicate(text)
    retcode = process.poll()
    if retcode:
        LOG.error('Signing error: %s' % err)
        raise subprocess.CalledProcessError(retcode,
                                            "openssl", output=output)
    return cms_to_token(output)


def cms_to_token(cms_text):

    start_delim = "-----BEGIN CMS-----"
    end_delim = "-----END CMS-----"
    signed_text = cms_text
    signed_text = signed_text.replace('/', '-')
    signed_text = signed_text.replace(start_delim, '')
    signed_text = signed_text.replace(end_delim, '')
    signed_text = signed_text.replace('\n', '')

    return signed_text

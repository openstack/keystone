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

import datetime
import os
import subprocess
import uuid

import saml2
from saml2 import saml
from saml2 import samlp
import xmldsig

from keystone.common import config
from keystone import exception
from keystone.i18n import _LE
from keystone.openstack.common import fileutils
from keystone.openstack.common import log
from keystone.openstack.common import timeutils


LOG = log.getLogger(__name__)
CONF = config.CONF


class SAMLGenerator(object):
    """A class to generate SAML assertions."""

    def __init__(self):
        self.assertion_id = uuid.uuid4().hex

    def samlize_token(self, issuer, recipient, user, roles, project,
                      expires_in=None):
        """Convert Keystone attributes to a SAML assertion.

        :param issuer: URL of the issuing party
        :type issuer: string
        :param recipient: URL of the recipient
        :type recipient: string
        :param user: User name
        :type user: string
        :param roles: List of role names
        :type roles: list
        :param project: Project name
        :type project: string
        :param expires_in: Sets how long the assertion is valid for, in seconds
        :type expires_in: int

        :return: XML <Response> object

        """
        expiration_time = self._determine_expiration_time(expires_in)
        status = self._create_status()
        saml_issuer = self._create_issuer(issuer)
        subject = self._create_subject(user, expiration_time, recipient)
        attribute_statement = self._create_attribute_statement(user, roles,
                                                               project)
        authn_statement = self._create_authn_statement(issuer, expiration_time)
        signature = self._create_signature()

        assertion = self._create_assertion(saml_issuer, signature,
                                           subject, authn_statement,
                                           attribute_statement)

        assertion = _sign_assertion(assertion)

        response = self._create_response(saml_issuer, status, assertion,
                                         recipient)
        return response

    def _determine_expiration_time(self, expires_in):
        if expires_in is None:
            expires_in = CONF.saml.assertion_expiration_time
        now = timeutils.utcnow()
        future = now + datetime.timedelta(seconds=expires_in)
        return timeutils.isotime(future, subsecond=True)

    def _create_status(self):
        """Create an object that represents a SAML Status.

        <ns0:Status xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol">
            <ns0:StatusCode
              Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </ns0:Status>

        :return: XML <Status> object

        """
        status = samlp.Status()
        status_code = samlp.StatusCode()
        status_code.value = samlp.STATUS_SUCCESS
        status_code.set_text('')
        status.status_code = status_code
        return status

    def _create_issuer(self, issuer_url):
        """Create an object that represents a SAML Issuer.

        <ns0:Issuer
          xmlns:ns0="urn:oasis:names:tc:SAML:2.0:assertion"
          Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
          https://acme.com/FIM/sps/openstack/saml20</ns0:Issuer>

        :return: XML <Issuer> object

        """
        issuer = saml.Issuer()
        issuer.format = saml.NAMEID_FORMAT_ENTITY
        issuer.set_text(issuer_url)
        return issuer

    def _create_subject(self, user, expiration_time, recipient):
        """Create an object that represents a SAML Subject.

        <ns0:Subject>
            <ns0:NameID
              Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                john@smith.com</ns0:NameID>
            <ns0:SubjectConfirmation
              Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <ns0:SubjectConfirmationData
                  NotOnOrAfter="2014-08-19T11:53:57.243106Z"
                  Recipient="http://beta.com/Shibboleth.sso/SAML2/POST" />
            </ns0:SubjectConfirmation>
        </ns0:Subject>

        :return: XML <Subject> object

        """
        name_id = saml.NameID()
        name_id.set_text(user)
        subject_conf_data = saml.SubjectConfirmationData()
        subject_conf_data.recipient = recipient
        subject_conf_data.not_on_or_after = expiration_time
        subject_conf = saml.SubjectConfirmation()
        subject_conf.method = saml.SCM_BEARER
        subject_conf.subject_confirmation_data = subject_conf_data
        subject = saml.Subject()
        subject.subject_confirmation = subject_conf
        subject.name_id = name_id
        return subject

    def _create_attribute_statement(self, user, roles, project):
        """Create an object that represents a SAML AttributeStatement.

        <ns0:AttributeStatement
          xmlns:ns0="urn:oasis:names:tc:SAML:2.0:assertion"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <ns0:Attribute Name="user">
                <ns0:AttributeValue
                  xsi:type="xs:string">test_user</ns0:AttributeValue>
            </ns0:Attribute>
            <ns0:Attribute Name="roles"
              NameFormat="urn:oasis:...:SAML:2.0:attrname-format:unspecified">
                <ns0:AttributeValue
                  xsi:type="xs:string">admin</ns0:AttributeValue>
                <ns0:AttributeValue
                  xsi:type="xs:string">member</ns0:AttributeValue>
            </ns0:Attribute>
            <ns0:Attribute Name="projects"
              NameFormat="urn:oasis:...:SAML:2.0:attrname-format:unspecified">
                <ns0:AttributeValue
                  xsi:type="xs:string">development</ns0:AttributeValue>
            </ns0:Attribute>
        </ns0:AttributeStatement>

        :return: XML <AttributeStatement> object

        """
        openstack_user = 'openstack_user'
        user_attribute = saml.Attribute()
        user_attribute.name = openstack_user
        user_value = saml.AttributeValue()
        user_value.set_text(user)
        user_attribute.attribute_value = user_value

        openstack_roles = 'openstack_roles'
        roles_attribute = saml.Attribute()
        roles_attribute.name = openstack_roles

        for role in roles:
            role_value = saml.AttributeValue()
            role_value.set_text(role)
            roles_attribute.attribute_value.append(role_value)

        openstack_project = 'openstack_project'
        project_attribute = saml.Attribute()
        project_attribute.name = openstack_project
        project_value = saml.AttributeValue()
        project_value.set_text(project)
        project_attribute.attribute_value = project_value

        attribute_statement = saml.AttributeStatement()
        attribute_statement.attribute.append(user_attribute)
        attribute_statement.attribute.append(roles_attribute)
        attribute_statement.attribute.append(project_attribute)
        return attribute_statement

    def _create_authn_statement(self, issuer, expiration_time):
        """Create an object that represents a SAML AuthnStatement.

        <ns0:AuthnStatement xmlns:ns0="urn:oasis:names:tc:SAML:2.0:assertion"
          AuthnInstant="2014-07-30T03:04:25Z" SessionIndex="47335964efb"
          SessionNotOnOrAfter="2014-07-30T03:04:26Z">
            <ns0:AuthnContext>
                <ns0:AuthnContextClassRef>
                  urn:oasis:names:tc:SAML:2.0:ac:classes:Password
                </ns0:AuthnContextClassRef>
                <ns0:AuthenticatingAuthority>
                  https://acme.com/FIM/sps/openstack/saml20
                </ns0:AuthenticatingAuthority>
            </ns0:AuthnContext>
        </ns0:AuthnStatement>

        :return: XML <AuthnStatement> object

        """
        authn_statement = saml.AuthnStatement()
        authn_statement.authn_instant = timeutils.isotime()
        authn_statement.session_index = uuid.uuid4().hex
        authn_statement.session_not_on_or_after = expiration_time

        authn_context = saml.AuthnContext()
        authn_context_class = saml.AuthnContextClassRef()
        authn_context_class.set_text(saml.AUTHN_PASSWORD)

        authn_authority = saml.AuthenticatingAuthority()
        authn_authority.set_text(issuer)
        authn_context.authn_context_class_ref = authn_context_class
        authn_context.authenticating_authority = authn_authority

        authn_statement.authn_context = authn_context

        return authn_statement

    def _create_assertion(self, issuer, signature, subject, authn_statement,
                          attribute_statement):
        """Create an object that represents a SAML Assertion.

        <ns0:Assertion
          ID="35daed258ba647ba8962e9baff4d6a46"
          IssueInstant="2014-06-11T15:45:58Z"
          Version="2.0">
            <ns0:Issuer> ... </ns0:Issuer>
            <ns1:Signature> ... </ns1:Signature>
            <ns0:Subject> ... </ns0:Subject>
            <ns0:AuthnStatement> ... </ns0:AuthnStatement>
            <ns0:AttributeStatement> ... </ns0:AttributeStatement>
        </ns0:Assertion>

        :return: XML <Assertion> object

        """
        assertion = saml.Assertion()
        assertion.id = self.assertion_id
        assertion.issue_instant = timeutils.isotime()
        assertion.issuer = issuer
        assertion.signature = signature
        assertion.subject = subject
        assertion.authn_statement = authn_statement
        assertion.attribute_statement = attribute_statement
        return assertion

    def _create_response(self, issuer, status, assertion, recipient):
        """Create an object that represents a SAML Response.

        <ns0:Response
          Destination="http://beta.com/Shibboleth.sso/SAML2/POST"
          ID="c5954543230e4e778bc5b92923a0512d"
          IssueInstant="2014-07-30T03:19:45Z"
          Version="2.0" />
            <ns0:Issuer> ... </ns0:Issuer>
            <ns0:Assertion> ... </ns0:Assertion>
            <ns0:Status> ... </ns0:Status>
        </ns0:Response>

        :return: XML <Response> object

        """
        response = samlp.Response()
        response.id = uuid.uuid4().hex
        response.destination = recipient
        response.issue_instant = timeutils.isotime()
        response.version = '2.0'
        response.issuer = issuer
        response.status = status
        response.assertion = assertion
        return response

    def _create_signature(self):
        """Create an object that represents a SAML <Signature>.

        This must be filled with algorithms that the signing binary will apply
        in order to sign the whole message.
        Currently we enforce X509 signing.
        Example of the template::

        <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
          <SignedInfo>
            <CanonicalizationMethod
              Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod
              Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <Reference URI="#<Assertion ID>">
              <Transforms>
                <Transform
            Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
               <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
              </Transforms>
             <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
             <DigestValue />
            </Reference>
          </SignedInfo>
          <SignatureValue />
          <KeyInfo>
            <X509Data />
          </KeyInfo>
        </Signature>

        :return: XML <Signature> object

        """
        canonicalization_method = xmldsig.CanonicalizationMethod()
        canonicalization_method.algorithm = xmldsig.ALG_EXC_C14N
        signature_method = xmldsig.SignatureMethod(
            algorithm=xmldsig.SIG_RSA_SHA1)

        transforms = xmldsig.Transforms()
        envelope_transform = xmldsig.Transform(
            algorithm=xmldsig.TRANSFORM_ENVELOPED)

        c14_transform = xmldsig.Transform(algorithm=xmldsig.ALG_EXC_C14N)
        transforms.transform = [envelope_transform, c14_transform]

        digest_method = xmldsig.DigestMethod(algorithm=xmldsig.DIGEST_SHA1)
        digest_value = xmldsig.DigestValue()

        reference = xmldsig.Reference()
        reference.uri = '#' + self.assertion_id
        reference.digest_method = digest_method
        reference.digest_value = digest_value
        reference.transforms = transforms

        signed_info = xmldsig.SignedInfo()
        signed_info.canonicalization_method = canonicalization_method
        signed_info.signature_method = signature_method
        signed_info.reference = reference

        key_info = xmldsig.KeyInfo()
        key_info.x509_data = xmldsig.X509Data()

        signature = xmldsig.Signature()
        signature.signed_info = signed_info
        signature.signature_value = xmldsig.SignatureValue()
        signature.key_info = key_info

        return signature


def _sign_assertion(assertion):
    """Sign a SAML assertion.

    This method utilizes ``xmlsec1`` binary and signs SAML assertions in a
    separate process. ``xmlsec1`` cannot read input data from stdin so the
    prepared assertion needs to be serialized and stored in a temporary
    file. This file will be deleted immediately after ``xmlsec1`` returns.
    The signed assertion is redirected to a standard output and read using
    subprocess.PIPE redirection. A ``saml.Assertion`` class is created
    from the signed string again and returned.

    Parameters that are required in the CONF::
    * xmlsec_binary
    * private key file path
    * public key file path
    :return: XML <Assertion> object

    """
    xmlsec_binary = CONF.saml.xmlsec1_binary
    idp_private_key = CONF.saml.keyfile
    idp_public_key = CONF.saml.certfile

    # xmlsec1 --sign --privkey-pem privkey,cert --id-attr:ID <tag> <file>
    certificates = '%(idp_private_key)s,%(idp_public_key)s' % {
        'idp_public_key': idp_public_key,
        'idp_private_key': idp_private_key
    }

    command_list = [xmlsec_binary, '--sign', '--privkey-pem', certificates,
                    '--id-attr:ID', 'Assertion']

    try:
        file_path = fileutils.write_to_tempfile(assertion.to_string())
        command_list.append(file_path)
        stdout = subprocess.check_output(command_list)
    except Exception as e:
        msg = _LE('Error when signing assertion, reason: %(reason)s')
        msg = msg % {'reason': e}
        LOG.error(msg)
        raise exception.SAMLSigningError(reason=e)
    finally:
        try:
            os.remove(file_path)
        except OSError:
            pass

    return saml2.create_class_from_xml_string(saml.Assertion, stdout)

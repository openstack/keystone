.. -*- rst -*-

*New in version 1.1*

Generate a SAML assertion
=========================

.. rest_method::  POST /v3/auth/OS-FEDERATION/saml2

A user may generate a SAML assertion document based on the scoped token that is
used in the request.

Request Parameters:

To generate a SAML assertion, a user must provides a scoped token ID and
Service Provider ID in the request body.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/saml2``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/assertion/parameters.yaml

   - auth: auth

Example
~~~~~~~

.. literalinclude:: federation/assertion/samples/saml-assertion-request.json
   :language: javascript

The response will be a full SAML assertion. Note that for readability the
certificate has been truncated. Server will also set two HTTP headers:
``X-sp-url`` and ``X-auth-url``. The former is the URL where assertion should
be sent, whereas the latter remote URL where token will be issued once the
client is finally authenticated.

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/assertion/parameters.yaml

   - Headers: headers
   - xml: saml_xml

Example
~~~~~~~

.. literalinclude:: federation/assertion/samples/saml-assertion-response.xml
   :language: xml

For more information about how a SAML assertion is structured, refer to the
`specification <http://saml.xml.org/saml-specifications>`__.

Generate an ECP wrapped SAML assertion
======================================

.. rest_method::  POST /v3/auth/OS-FEDERATION/saml2/ecp

A user may generate a SAML assertion document to work with the
*Enhanced Client or Proxy* (ECP) profile based on the scoped token that is
used in the request.

Request Parameters:

To generate an ECP wrapped SAML assertion, a user must provides a scoped token
ID and Service Provider ID in the request body.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/saml2/ecp``

Request
-------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/assertion/parameters.yaml

   - auth: auth

Example
~~~~~~~

.. literalinclude:: federation/assertion/samples/ecp-saml-assertion-request.json
   :language: javascript

The response will be an ECP wrapped SAML assertion. Note that for readability
the certificate has been truncated. Server will also set two HTTP headers:
``X-sp-url`` and ``X-auth-url``. The former is the URL where assertion should
be sent, whereas the latter remote URL where token will be issued once the
client is finally authenticated.

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/assertion/parameters.yaml

   - Headers: headers
   - xml: saml_xml

Example
~~~~~~~

.. literalinclude:: federation/assertion/samples/ecp-saml-assertion-response.xml
   :language: xml


Retrieve Metadata properties
============================

.. rest_method::  GET /v3/OS-FEDERATION/saml2/metadata

A user may retrieve Metadata about an Identity Service acting as an Identity
Provider.

The response will be a full document with Metadata properties. Note that for
readability, this example certificate has been truncated.

Relationship: ``https://docs.openstack.org/api/openstack-identity/3/ext/OS-FEDERATION/1.0/rel/metadata``

Response
--------

Parameters
~~~~~~~~~~

.. rest_parameters:: federation/assertion/parameters.yaml

   - Headers: headers
   - xml: metadata_xml

Example
~~~~~~~

.. literalinclude:: federation/assertion/samples/metadata-response.xml
   :language: xml

For more information about how a SAML assertion is structured, refer to the
`specification <http://saml.xml.org/saml-specifications>`__.
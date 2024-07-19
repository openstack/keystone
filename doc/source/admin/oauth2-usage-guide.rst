======================================
OAuth2.0 Client Credentials Grant Flow
======================================

Overview
~~~~~~~~
OAuth2.0 Client Credentials Grant based on `RFC6749`_ is implemented as an
extension of Keystone. This extension uses the `application credentials`_ as
its back-end because they have some similar features. Users can use
``application_credentials_id`` and ``application_credentials_secret`` as client
credentials to obtain the OAuth2.0 access token. The access token can then be
used to access the protected resources of the OpenStack API using
Keystonemiddleware that supports receiving access tokens in the Authorization
header.  See the `Identity API reference`_ for more information on generating
OAuth2.0 access token.

Guide
~~~~~
Enable Keystone identity server to support OAuth2.0 Client Credentials
Grant by the following steps in this guide. In this example,
``keystone.host`` is the domain name used by the Keystone identity server.

.. _application credentials: https://docs.openstack.org/api-ref/identity/v3/index.html#application-credentials
.. _`Identity API reference`: https://docs.openstack.org/api-ref/identity/v3/index.html#os-oauth2-api

.. warning::

   It is strongly recommended that HTTPS be enabled in Keystone when using
   OAuth2.0 Client Credentials. See :doc:`./configure-https` for details.
   According to `RFC6749`_ , HTTPS **must** be enabled in the authorization
   server since requests include sensitive information, e.g., a client secret,
   in plain text. Note that you might have to enable both HTTP and HTTPS as
   some other OpenStack services or third-party applications don't use OAuth2.0
   and need HTTP for the authentication with the Keystone identity server.

Enable application credentials authentication
---------------------------------------------
Due to the design of the current implementation, the application credentials
must be enabled in Keystone as it is used for the management of OAuth2.0
client credentials.

1. Modify ``keystone.conf`` to support application credentials authentication.

.. code-block:: console

    stack@oauth2-0-server:/$ vi /etc/keystone/keystone.conf
    [auth]
    methods = external,password,token,application_credential

2. Restart Keystone service so that the modified configuration information takes
   effect.

.. code-block:: console

    stack@oauth2-0-server:/$ sudo systemctl restart devstack@keystone.service

Try to access the Keystone APIs
-------------------------------
At last, try to access the Keystone APIs to confirm that the server is working
properly.

1. Create OAuth2.0 client credentials through the application credentials API.

.. code-block:: console

    stack@oauth2-0-server:/$ openstack application credential create sample_001
    +--------------+----------------------------------------------------------------------------------------+
    | Field        | Value                                                                                  |
    +--------------+----------------------------------------------------------------------------------------+
    | description  | None                                                                                   |
    | expires_at   | None                                                                                   |
    | id           | a7850381222a4e2cb595664dfd57d083                                                       |
    | name         | sample_001                                                                             |
    | project_id   | 2b90a96668694041a640a2ef84be6de7                                                       |
    | roles        | admin reader member                                                                    |
    | secret       | GVm33KC6AqpDZj_ZzKhZClDqnCpNDMNh66Mvait8Dxw7Kc8kwVj7ImkwnRWvovs437f2aftbW46wEMtH0cyBQA |
    | system       | None                                                                                   |
    | unrestricted | False                                                                                  |
    | user_id      | 0b8426bb83d944bc8d0fe4c3b9a3f635                                                       |
    +--------------+----------------------------------------------------------------------------------------+

2. Obtain oauth2.0 access tokens through the "Basic" HTTP authentication with
   OAuth2.0 client credentials.

.. code-block:: console

    stack@oauth2-0-server:/$ curl -sik -u "$a7850381222a4e2cb595664dfd57d083:GVm33KC6AqpDZj_ZzKhZClDqnCpNDMNh66Mvait8Dxw7Kc8kwVj7ImkwnRWvovs437f2aftbW46wEMtH0cyBQA" \
    -X POST https://keystone.host/identity/v3/OS-OAUTH2/token
    -H "application/x-www-form-urlencoded" -d "grant_type=client_credentials"
    HTTP/1.1 200 OK
    Date: Tue, 01 Mar 2022 00:56:59 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Content-Type: application/json
    Content-Length: 264
    Vary: X-Auth-Token
    x-openstack-request-id: req-a8358f51-2e0f-45a7-bb1e-7d29c6a793f4
    Connection: close

    {"access_token":"gAAAAABhi1cMynG89h8t6TJrxNiZuNzjcIUIxNctoVfuqTw7BpUedLKxjPymClVEnj9GhIT5u2mpjaJATlEAtaa3D6_t8jk_fV-mqo2IUlsmTPTnMwkcjh5FSHQVRdqvDxgY3nSqLA_Hfv-zPmjS5KWX3hmyDE5YWO1ztX6QNVQb4wTPyNL1-7I","expires_in":3600,"token_type":"Bearer"}


.. _RFC6749: https://datatracker.ietf.org/doc/html/rfc6749
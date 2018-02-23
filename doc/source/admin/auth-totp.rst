..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

===================================
Time-based One-time Password (TOTP)
===================================

Configuring TOTP
================

TOTP is not enabled in Keystone by default.  To enable it add the ``totp``
authentication method to the ``[auth]`` section in ``keystone.conf``:

.. code-block:: ini

    [auth]
    methods = external,password,token,oauth1,totp

For a user to have access to TOTP, he must have configured TOTP credentials in
Keystone and a TOTP device (i.e. `Google Authenticator`_).

.. _Google Authenticator: http://www.google.com/2step

TOTP uses a base32 encoded string for the secret. The secret must be at least
128 bits (16 bytes). The following python code can be used to generate a TOTP
secret:

.. code-block:: python

    import base64
    message = '1234567890123456'
    print base64.b32encode(message).rstrip('=')

Example output::

    GEZDGNBVGY3TQOJQGEZDGNBVGY

This generated secret can then be used to add new 'totp' credentials to a
specific user.

Create a TOTP credential
------------------------

Create ``totp`` credentials for user:

.. code-block:: bash

    USER_ID=b7793000f8d84c79af4e215e9da78654
    SECRET=GEZDGNBVGY3TQOJQGEZDGNBVGY

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    {
        "credential": {
            "blob": "'$SECRET'",
            "type": "totp",
            "user_id": "'$USER_ID'"
        }
    }' \
      http://localhost:5000/v3/credentials ; echo

Google Authenticator
--------------------

On a device install Google Authenticator and inside the app click on 'Set up
account' and then click on 'Enter provided key'.  In the input fields enter
account name and secret.  Optionally a QR code can be generated programmatically
to avoid having to type the information.

QR code
-------

Create TOTP QR code for device:

.. code-block:: python

    import qrcode

    secret='GEZDGNBVGY3TQOJQGEZDGNBVGY'
    uri = 'otpauth://totp/{name}?secret={secret}&issuer={issuer}'.format(
        name='name',
        secret=secret,
        issuer='Keystone')

    img = qrcode.make(uri)
    img.save('totp.png')

In Google Authenticator app click on 'Set up account' and then click on 'Scan
a barcode', and then scan the 'totp.png' image.  This should create a new TOTP
entry in the application.

Authenticate with TOTP
======================

Google Authenticator will generate a 6 digit PIN (passcode) every few seconds.
Use the passcode and your user ID to authenticate using the ``totp`` method.

Tokens
------

Get a token with default scope (may be unscoped) using totp:

.. code-block:: bash

    USER_ID=b7793000f8d84c79af4e215e9da78654
    PASSCODE=012345

    curl -i \
      -H "Content-Type: application/json" \
      -d '
    { "auth": {
            "identity": {
                "methods": [
                    "totp"
                ],
                "totp": {
                    "user": {
                        "id": "'$USER_ID'",
                        "passcode": "'$PASSCODE'"
                    }
                }
            }
        }
    }' \
      http://localhost:5000/v3/auth/tokens ; echo

.. _multi_factor_authentication_user_guide:

===========================
Multi-Factor Authentication
===========================

Configuring MFA
===============

Configuring MFA right now has to be done entirely by an admin, for how to do
that, see :ref:`multi_factor_authentication`.

Using MFA
=========

Multi-Factor Authentication with Keystone can be used in two ways, either you
treat it like current single method authentication and provide all the details
upfront, or you doing it as a multi-step process with auth receipts.

Single step
-----------

In the single step approach you would supply all the required authentication
methods in your request for a token.

Here is an example using 2 factors (``password`` and ``totp``):

.. code-block:: json

    { "auth": {
            "identity": {
                "methods": [
                    "password",
                    "totp"
                ],
                "totp": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "passcode": "012345"
                    }
                },
                "password": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "password": "super sekret pa55word"
                    }
                }
            }
        }
    }

If all the supplied auth methods are valid, Keystone will return a token.

Multi-Step
----------

In the multi-step approach you can supply any one method from the auth rules:

Again we do a 2 factor example, starting with ``password``:

.. code-block:: json

    { "auth": {
            "identity": {
                "methods": [
                    "password"
                ],
                "password": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "password": "super sekret pa55word"
                    }
                }
            }
        }
    }

Provided the method is valid, Keystone will still return a ``401``, but will in
the response header ``Openstack-Auth-Receipt`` return a receipt of valid auth
method for reuse later.

The response body will also contain information about the auth receipt, and
what auth methods may be missing:

.. code-block:: json

    {
        "receipt":{
            "expires_at":"2018-07-05T08:39:23.000000Z",
            "issued_at":"2018-07-05T08:34:23.000000Z",
            "methods": [
                "password"
            ],
            "user": {
                "domain": {
                    "id": "default",
                    "name": "Default"
                },
                "id": "ee4dfb6e5540447cb3741905149d9b6e",
                "name": "admin"
            }
        },
        "required_auth_methods": [
            ["totp", "password"]
        ]
    }

Now you can continue authenticating by supplying the missing auth methods, and
supplying the header ``Openstack-Auth-Receipt`` as gotten from the previous
response:

.. code-block:: json

    { "auth": {
            "identity": {
                "methods": [
                    "totp"
                ],
                "totp": {
                    "user": {
                        "id": "2ed179c6af12496cafa1d279cb51a78f",
                        "passcode": "012345"
                    }
                }
            }
        }
    }

Provided the auth methods are valid, Keystone will now supply a token. If not
you can try again until the auth receipt expires (e.g in case of TOTP timeout).

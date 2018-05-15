OAuth1 1.0a
===========

The OAuth 1.0a feature provides the ability for Identity users to delegate
roles to third party consumers via the OAuth 1.0a specification.

To enable OAuth1:

1. Add the oauth1 driver to the ``[oauth1]`` section in ``keystone.conf``. For
   example:

.. code-block:: ini

    [oauth1]
    driver = sql

2. Add the ``oauth1`` authentication method to the ``[auth]`` section in
   ``keystone.conf``:

.. code-block:: ini

    [auth]
    methods = external,password,token,oauth1

3. If deploying under Apache httpd with ``mod_wsgi``, set the
   `WSGIPassAuthorization` to allow the OAuth Authorization headers to pass
   through `mod_wsgi`. For example, add the following to the keystone virtual
   host file:

.. code-block:: ini

    WSGIPassAuthorization On

See `API Specification for OAuth 1.0a <https://developer.openstack.org/
api-ref/identity/v3-ext/index.html#os-oauth1-api>`_ for the details of
API definition.
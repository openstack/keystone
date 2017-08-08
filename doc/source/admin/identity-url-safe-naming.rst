=======================================
URL safe naming of projects and domains
=======================================

In the future, keystone may offer the ability to identify a project in a
hierarchy via a URL style of naming from the root of the hierarchy (for example
specifying 'projectA/projectB/projectC' as the project name in an
authentication request). In order to prepare for this, keystone supports the
optional ability to ensure both projects and domains are named without
including any of the reserved characters specified in section 2.2 of
`rfc3986 <http://tools.ietf.org/html/rfc3986>`_.

The safety of the names of projects and domains can be controlled via two
configuration options:

.. code-block:: ini

    [resource]
    project_name_url_safe = off
    domain_name_url_safe = off

When set to ``off`` (which is the default), no checking is done on the URL
safeness of names. When set to ``new``, an attempt to create a new project or
domain with an unsafe name (or update the name of a project or domain to be
unsafe) will cause a status code of 400 (Bad Request) to be returned. Setting
the configuration option to ``strict`` will, in addition to preventing the
creation and updating of entities with unsafe names, cause an authentication
attempt which specifies a project or domain name that is unsafe to return a
status code of 401 (Unauthorized).

It is recommended that installations take the steps necessary to where they
can run with both options set to ``strict`` as soon as is practical.

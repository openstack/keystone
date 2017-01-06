.. -*- rst -*-

===========
API Details
===========

Overview
========

The OpenStack Identity API is implemented using a RESTful web service
interface. All requests to authenticate and operate against the
OpenStack Identity API should be performed using HTTPS.

OpenStack Identity enables clients to obtain tokens that permit access
to OpenStack cloud services.

Intended audience
-----------------

This reference is for software developers who develop applications that
use the Identity API for authentication.

This reference assumes that the reader is familiar with RESTful web
services, HTTP/1.1, and JSON serialization formats.

Identity concepts
-----------------

To use OpenStack Identity, you must be familiar with these key concepts:

**User**
    A digital representation of a person, system, or service that uses
    OpenStack cloud services. OpenStack Identity authentication services
    validate that an incoming request is being made by the user who
    claims to be making the call.

    Users have a login and may be assigned tokens to access resources.
    Users may be directly assigned to a particular tenant and behave as
    if they are contained in that tenant.

**Token**
    An arbitrary bit of text that is used to access resources. Each
    token has a scope that describes which resources are accessible with
    it. A token may be revoked at anytime and is valid for a finite
    duration.

    While OpenStack Identity supports token-based authentication, the
    intention is for it to support additional protocols in the future.
    The intent is for it to be an integration service foremost, and not
    aspire to be a full-fledged identity store and management solution.

**Credentials**
    Data that belongs to, is owned by, and generally only known by a
    user that the user can present to prove their identity.

    Examples include:

    -  A matching username and password

    -  A matching username and API key

    -  A token that was issued to you

**Authentication**
    In the context of the OpenStack Identity Service, the act of confirming
    the identity of a user or the truth of a claim. OpenStack Identity
    confirms that an incoming request is being made by the user who
    claims to be making the call by validating a set of identity information
    provided by the user.

    These claims are initially in the form of a set of credentials
    (username & password, or username and API key). After initial
    confirmation, OpenStack Identity issues the user a token, which the
    user can then provide to demonstrate that their identity has been
    authenticated when making subsequent requests.

**Tenant**
    A container used to group or isolate resources and/or identity
    objects. Depending on the service operator, a tenant can map to a
    customer, account, organization, or project.

**Service**
    An OpenStack service, such as Compute (Nova), Object Storage
    (Swift), or Image Service (Glance). A service provides one or more
    endpoints through which users can access resources and perform
    operations.

**Endpoint**
    A network-accessible address, usually described by a URL, where a
    service may be accessed. If using an extension for templates, you
    can create an endpoint template, which represents the templates of
    all the consumable services that are available across the regions.

**Role**
    A personality that a user assumes when performing a specific set of
    operations. A role includes a set of rights and privileges. A user
    assuming that role inherits those rights and privileges.

    In OpenStack Identity, a token that is issued to a user includes the
    list of roles that user can assume. Services that are being called
    by that user determine how they interpret the set of roles a user
    has and to which operations or resources each role grants access.

    It is up to individual services such as the Compute service and
    Image service to assign meaning to these roles. As far as the
    Identity service is concerned, a role is an arbitrary name assigned
    by the user.

Paginated collections
=====================

To reduce load on the service, list operations return a maximum number
of items at a time. The maximum number of items returned is determined
by the Identity provider. To navigate the collection, you can set the
``limit`` and ``marker`` parameters in the URI. For example,
``?limit=100&marker=1234``. The ``marker`` parameter
is the ID of the last item in the previous list. Items are sorted by
update time. When an update time is not available they are sorted by ID.
The ``limit`` parameter sets the page size. Both parameters are
optional. If the client requests a ``limit`` beyond that which is
supported by the deployment a ``413`` response code may be thrown. A
marker with an invalid ID returns a ``404`` response code.

.. note::

    Paginated collections will never return a ``404`` error when the
    collection is empty - clients should expect an empty collection.

For convenience, collections contain atom ``next`` and ``previous`` links.
The first page in the list does not contain a ``previous`` link, the
last page in the list does not contain a ``next`` link. The following
examples illustrate three pages in a collection of tenants. The first
page was retrieved through a **GET** to
``http://identity.api.openstack.org/v2.0/1234/tenants?limit=1``. In
these examples, the ``limit`` parameter sets the page size to a single
item. Subsequent ``next`` and ``previous`` links honor the initial page
size. Thus, a client might follow links to traverse a paginated
collection without having to input the ``marker`` parameter.

**Example: Tenant collection, first page:**

.. code:: javascript

    {
        "tenants": [
            {
                "id": "1234",
                "name": "ACME corp",
                "description": "A description ...",
                "enabled": true
            }
        ],
        "tenants_links": [
            {
                "rel": "next",
                "href": "http://identity.api.openstack.org/v2.0/tenants?limit=1&marker=1234"
            }
        ]
    }



**Example: Tenant collection, second page:**

.. code:: javascript

    {
        "tenants": [
            {
                "id": "3645",
                "name": "Iron Works",
                "description": "A description ...",
                "enabled": true
            }
        ],
        "tenants_links": [
            {
                "rel": "next",
                "href": "http://identity.api.openstack.org/v2.0/tenants?limit=1&marker=3645"
            },
            {
                "rel": "previous",
                "href": "http://identity.api.openstack.org/v2.0/tenants?limit=1"
            }
        ]
    }



**Example: Tenant collection, last page:**

.. code:: javascript

    {
        "tenants": [
            {
                "id": "9999",
                "name": "Bigz",
                "description": "A description ...",
                "enabled": true
            }
        ],
        "tenants_links": [
            {
                "rel": "previous",
                "href": "http://identity.api.openstack.org/v2.0/tenants?limit=1&marker=1234"
            }
        ]
    }



Paginated collections contain a values property that contains the items in the
collections. Links are accessed via the links property. The approach allows for
extensibility of both the collection members and of the paginated collection
itself. It also allows collections to be embedded in other objects as
illustrated below.  Here, a subset of groups are presented within a user.
Clients must follow the ``next`` link to continue to retrieve additional groups
belonging to a user.

**Example: Paginated roles in user:**

.. code:: javascript

    {
        "user": {
            "OS-ROLE:roles": [
                {
                    "tenantId": "1234",
                    "id": "Admin"
                },
                {
                    "tenantId": "1234",
                    "id": "DBUser"
                }
            ],
            "OS-ROLE:roles_links": [
                {
                    "rel": "next",
                    "href": "http://identity.api.openstack.org/v2.0/tenants/1234/users/u1000/roles?marker=Super"
                }
            ],
            "id": "u1000",
            "username": "jqsmith",
            "email": "john.smith@example.org",
            "enabled": true
        }
    }

Request and response formats
============================

The OpenStack Identity API only supports JSON data serialization request and
response formats.

Use the ``Content-Type`` request header to specify the request format.
This header is required for operations that have a request body.

The syntax for the ``Content-Type`` header is:

.. code::

    Content-Type: application/json

Use the ``Accept`` header to specify the response format:

.. code::

    Accept: application/json

If you do not specify a response format, the ``Accept`` header will be
set to ``application/json`` by default.
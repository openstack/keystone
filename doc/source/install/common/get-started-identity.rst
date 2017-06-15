Identity service overview
~~~~~~~~~~~~~~~~~~~~~~~~~

The OpenStack Identity service provides a single point of integration for
managing authentication, authorization, and a catalog of services.

The Identity service is typically the first service a user interacts with. Once
authenticated, an end user can use their identity to access other OpenStack
services. Likewise, other OpenStack services leverage the Identity service to
ensure users are who they say they are and discover where other services are
within the deployment. The Identity service can also integrate with some
external user management systems (such as LDAP).

Users and services can locate other services by using the service catalog,
which is managed by the Identity service. As the name implies, a service
catalog is a collection of available services in an OpenStack deployment. Each
service can have one or many endpoints and each endpoint can be one of three
types: admin, internal, or public. In a production environment, different
endpoint types might reside on separate networks exposed to different types of
users for security reasons. For instance, the public API network might be
visible from the Internet so customers can manage their clouds. The admin API
network might be restricted to operators within the organization that manages
cloud infrastructure. The internal API network might be restricted to the hosts
that contain OpenStack services. Also, OpenStack supports multiple regions for
scalability. For simplicity, this guide uses the management network for all
endpoint types and the default ``RegionOne`` region. Together, regions,
services, and endpoints created within the Identity service comprise the
service catalog for a deployment. Each OpenStack service in your deployment
needs a service entry with corresponding endpoints stored in the Identity
service. This can all be done after the Identity service has been installed and
configured.

The Identity service contains these components:

Server
    A centralized server provides authentication and authorization
    services using a RESTful interface.

Drivers
    Drivers or a service back end are integrated to the centralized
    server. They are used for accessing identity information in
    repositories external to OpenStack, and may already exist in
    the infrastructure where OpenStack is deployed (for example, SQL
    databases or LDAP servers).

Modules
    Middleware modules run in the address space of the OpenStack
    component that is using the Identity service. These modules
    intercept service requests, extract user credentials, and send them
    to the centralized server for authorization. The integration between
    the middleware modules and OpenStack components uses the Python Web
    Server Gateway Interface.

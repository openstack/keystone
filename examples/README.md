RUNNING THE TEST SERVICE (Echo.py):
----------------------------------

    Standalone stack (with Auth_Token)
    $ cd echo/bin
    $ ./echod

    Distributed stack (with RemoteAuth local and Auth_Token remote)
    $ cd echo/bin
    $ ./echod --remote

    in separate session
    $ cd keystone/middleware
    $ python auth_token.py


DEMO CLIENT:
------------
A sample client that gets a token from Keystone and then uses it to call Echo (and a few other example calls):

    $ cd echo/echo
    $ python echo_client.py
    Note: this requires test data. See section TESTING for initializing data


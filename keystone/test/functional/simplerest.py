# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import httplib
import json
import re
import string
import urllib
import urlparse


class HTTPRequest(object):
    """Represent an HTTP request.

    Represents an HTTP request.  Headers can be manipulated using
    standard dictionary access (i.e., req["accept"] will be the
    contents of the "Accept" header), and the body can be fed in using
    write().  Note that headers are manipulated in a case-insensitive
    fashion; that is, the "accept" header is the same thing as the
    "ACCEPT" header or the "aCcEpT" header.

    """

    def __init__(self, method, uri, body=None, headers=None):
        """Initialize an HTTP request.

        :param method: The HTTP method, i.e., "GET".
        :param uri: The full path of the resource.
        :param body: A string giving the body of the request.
        :param headers: A dictionary of headers.
        """

        # Save the relevant data
        self.method = method.upper()
        self.uri = uri
        self.body = body or ''
        self.headers = {}

        # Set the headers...
        if headers:
            for hdr, value in headers.items():
                # Allows appropriate case mapping
                self[hdr] = value

    def write(self, data):
        """Write data to the request body.

        :param data: Data to be appended to the request body.
        """

        # Add the written data to our body
        self.body += data

    def flush(self):
        """Flush data to the request body.

        Does nothing.  Provided just in case something tries to call
        flush().
        """

        # Do-nothing to allow stream compatibility
        pass

    def __getitem__(self, item):
        """Allow access to headers."""

        # Headers are done by item access
        return self.headers[item.title()]

    def __setitem__(self, item, value):
        """Allow access to headers."""

        # Headers are done by item access
        self.headers[item.title()] = value

    def __delitem__(self, item):
        """Allow access to headers."""

        # Headers are done by item access
        del self.headers[item.title()]

    def __contains__(self, item):
        """Allow access to headers."""

        # Headers are done by item access
        return item.title() in self.headers

    def __len__(self):
        """Allow access to headers."""

        # Headers are done by item access
        return len(self.headers)


class RESTClient(object):
    """Represent a REST client connection.

    Represents a REST client connection.  All calls will be made
    relative to the base URL defined when the class is instantiated.
    Note that 301, 302, 303, and 307 redirects are honored.  By
    default, redirects are limited to a maximum of 10; this may be
    modified by setting the max_redirects class attribute.

    """

    # Maximum number of redirects we'll follow
    max_redirects = 10

    def __init__(self, baseurl, debug_stream=None):
        """Initialize a REST client.

        :param baseurl: The base URL for the client connection.
        :param debug_stream: An optional stream for receiving debug.
        """

        # Save the base URL and debug stream
        self._baseurl = baseurl
        self._debug_stream = debug_stream

        # Pull it apart, also...
        parsed = urlparse.urlparse(baseurl)

        # Make sure the scheme makes sense
        if parsed.scheme not in ('http', 'https'):
            raise httplib.InvalidURL("invalid scheme: '%s'" % parsed.scheme)

        # We're only concerned with the scheme, netloc, and path...
        self._scheme = parsed.scheme
        self._netloc = parsed.netloc
        self._path = parsed.path or '/'

        # We'll keep a cached HTTPConnection for our baseurl around...
        self._connect = None

    @classmethod
    def _open(cls, scheme, netloc, cache=None):
        """Open an HTTPConnection.

        Opens an HTTPConnection or returns an open one from the cache,
        if given.  If the scheme is "https", returns an
        HTTPSConnection.

        :param scheme: The URI scheme; one of 'http' or 'https'.
        :param netloc: The network location.
        :param cache: Optional dictionary caching connections.
        """

        # If cache is present, look up the scheme and netloc in it...
        if cache and (scheme, netloc) in cache:
            # Return the pre-existing connection
            return cache[(scheme, netloc)]

        # Open a connection for the given scheme and netloc
        if scheme == 'http':
            connect = httplib.HTTPConnection(netloc)
        elif scheme == 'https':
            connect = httplib.HTTPSConnection(netloc)

        # Make sure to cache it...
        if cache is not None:
            cache[(scheme, netloc)] = connect

        return connect

    def _debug(self, msg, *args, **kwargs):
        """Generate debugging output."""

        # If we have a declared debug stream, output to it
        if self._debug_stream:
            print >>self._debug_stream, msg % (kwargs if kwargs else args)

    def make_req(self, method, reluri, query=None, obj=None, headers=None):
        """Makes an HTTPRequest.

        Generates an instance of HTTPRequest and returns it.

        :param method: The HTTP method, i.e., "GET".
        :param reluri: The resource URI, relative to the base URL.
        :param query: Optional dictionary to convert into a query.
        :param obj: Optional object to serialize as a JSON object.
        :param headers: Optional dictionary of headers.
        """

        # First, let's compose the path with the reluri
        joincond = (self._path[-1:], reluri[:1])
        if joincond == ('/', '/'):
            fulluri = self._path + reluri[1:]
        elif '/' in joincond:
            fulluri = self._path + reluri
        else:
            fulluri = self._path + '/' + reluri

        # Add the query, if there is one
        if query:
            fulluri += '?%s' % urllib.urlencode(query)

        self._debug("Creating %s request for %s", method, fulluri)

        # Set up a default for the accept header
        if headers is None:
            headers = {}
        headers.setdefault('accept', 'application/json')

        # Build a request
        req = HTTPRequest(method, fulluri, headers=headers)

        # If there's an object, jsonify it
        if obj is not None:
            json.dump(obj, req)
            req['content-type'] = 'application/json'
            self._debug("  Request body: %r" % req.body)

        # Now, return the request
        return req

    def send(self, req):
        """Send request.

        Sends a request, which must have been generated using
        make_req() (assumes URL is relative to the base URL).  Honors
        redirects (even to URLs not relative to base URL).  If the
        status code of the response is >= 400, raises an appropriate
        exception derived from HTTPException (of this module).
        Returns an HTTPResponse (defined by httplib).  If a JSON
        object is available in the body, the obj attribute of the
        response will be set to it; otherwise, obj is None.
        """

        self._debug("Sending request on client %s: (%r, %r, %r, %r)",
                    self._baseurl, req.method, req.uri, req.body, req.headers)

        # First, get a connection
        if self._connect is None:
            self._connect = self._open(self._scheme, self._netloc)

        # Pre-initialize the cache...
        cache = {(self._scheme, self._netloc): self._connect}

        # Get the initial connection we'll be using...
        connect = self._connect

        # Also get the initial URI we're using...
        uri = req.uri

        # Need the full URL, with e.g., netloc
        fullurl = urlparse.urlunparse((self._scheme, self._netloc, uri,
                                       None, None, None))

        # Loop for redirection handling
        seen = set([fullurl])
        for i in range(self.max_redirects):
            # Make the request
            self._debug("  Issuing request to %s (%s)", fullurl, uri)
            connect.request(req.method, uri, req.body, req.headers)

            # Get the response
            resp = connect.getresponse()

            # Now, is the response a redirection?
            newurl = None
            if resp.status in (301, 302, 303, 307):
                # Find the forwarding header...
                if 'location' in resp.msg:
                    newurl = resp.getheader('location')
                elif 'uri' in resp.msg:
                    newurl = resp.getheader('uri')

            # If we have a newurl, process the redirection
            if newurl is not None:
                # Canonicalize it; it could be relative
                fullurl = urlparse.urljoin(fullurl, newurl)

                self._debug("  Got redirected to %s" % fullurl)

                # Make sure we haven't seen it before...
                if fullurl in seen:
                    self._debug("    Redirected URL already seen!")
                    break

                seen.add(fullurl)

                # Now, split it back up
                tmp = urlparse.urlparse(newurl)

                # Get the path part of the URL
                uri = urlparse.urlunparse((None, None, tmp.path, tmp.params,
                                           tmp.query, tmp.fragment))

                # Finally, get a connection
                connect = self._open(tmp.scheme, tmp.netloc, cache)

                # And we try again
                continue

            # We have a response and it's not a redirection; let's
            # interpret the JSON in the response (safely)...
            self._debug("  Received %s response (%s)", resp.status,
                        resp.reason)
            resp.body = resp.read()
            try:
                resp.obj = json.loads(resp.body)
                self._debug("    Received entity: %r", resp.obj)
            except ValueError:
                resp.obj = None
                self._debug("    No received entity; body %r", resp.body)

            # If this is an error response, let's raise an appropriate
            # exception
            if resp.status >= 400:
                exc = exceptions.get(resp.status, HTTPException)
                self._debug("    Response was a fault, raising %s",
                            exc.__name__)
                raise exc(resp)

            # Return the response
            return resp

        # Exceeded the maximum number of redirects
        self._debug("  Redirect loop detected")
        raise RESTException("Redirect loop detected")

    def get(self, reluri, query=None, headers=None):
        """Send a GET request.

        :param reluri: The resource URI, relative to the base URL.
        :param query: Optional dictionary to convert into a query.
        :param headers: Optional dictionary of headers.
        """

        # Make a GET request...
        req = self.make_req('GET', reluri, query=query, headers=headers)

        # And issue it
        return self.send(req)

    def put(self, reluri, query=None, obj=None, headers=None):
        """Send a PUT request.

        :param reluri: The resource URI, relative to the base URL.
        :param query: Optional dictionary to convert into a query.
        :param obj: Optional object to serialize as a JSON object.
        :param headers: Optional dictionary of headers.
        """

        # Make a PUT request...
        req = self.make_req('PUT', reluri, query=query, obj=obj,
                            headers=headers)

        # And issue it
        return self.send(req)

    def post(self, reluri, query=None, obj=None, headers=None):
        """Send a POST request.

        :param reluri: The resource URI, relative to the base URL.
        :param query: Optional dictionary to convert into a query.
        :param obj: Optional object to serialize as a JSON object.
        :param headers: Optional dictionary of headers.
        """

        # Make a POST request...
        req = self.make_req('POST', reluri, query=query, obj=obj,
                            headers=headers)

        # And issue it
        return self.send(req)

    def delete(self, reluri, query=None, headers=None):
        """Send a DELETE request.

        :param reluri: The resource URI, relative to the base URL.
        :param query: Optional dictionary to convert into a query.
        :param headers: Optional dictionary of headers.
        """

        # Make a DELETE request...
        req = self.make_req('DELETE', reluri, query=query, headers=headers)

        # And issue it
        return self.send(req)


class RESTException(Exception):
    """Superclass for exceptions from this module."""

    pass


class HTTPException(RESTException):
    """Superclass of exceptions raised if an error status is returned."""

    def __init__(self, response):
        """Initializes exception, attaching response."""

        # Formulate a message from the response
        msg = response.reason

        # Initialize superclass
        super(RESTException, self).__init__(msg)

        # Also attach status code and the response
        self.status = response.status
        self.response = response


# Set up more specific exceptions
exceptions = {}
for _status, _name in httplib.responses.items():
    # Skip non-error codes
    if _status < 400:
        continue

    # Make a valid name
    _exname = re.sub(r'\W+', '', _name) + 'Exception'

    # Make a class
    _cls = type(_exname, (HTTPException,), {'__doc__': _name})

    # Now, put it in the right places
    vars()[_name] = _cls
    exceptions[_status] = _cls


class RESTMethod(object):
    """Represent a REST method.

    Represents a class method which should be translated into a
    request to a REST server.

    """

    def __init__(self, name, method, uri, argorder=None, reqwrapper=None,
                 **kwargs):
        """Initialize a REST method.

        Creates a method that will use the defined HTTP method to
        access the defined resource.  Extra keyword arguments specify
        the names and dispositions of arguments not derived from the
        uri format string.  The values of those extra arguments may be
        'query', 'req', or 'header', to indicate that the argument
        goes in the query string, the request object, or the request
        headers.  (Note that header names have '_' mapped to '-' for
        convenience.)  If a value is a tuple, the first element of the
        tuple must be the type ('query', 'req', or 'header'), and the
        second element must be either True or False, to indicate that
        the argument is required.  By default, all query arguments are
        optional, and all other arguments are required.

        :param name: The method name.
        :param method: The corresponding HTTP method.
        :param uri: A relative URI for the resource.  A format string.
        :param reqwrapper: Key for the wrapping dictionary of the request.
        :param argorder: Order arguments may be specified in.
        """

        # Save our name and method
        self.name = name
        self.method = method.upper()

        # Need to save the various construction information
        self.uri = uri
        self.reqwrapper = reqwrapper
        self.argorder = argorder or []

        # Need to determine what keys are required and where they
        # go...
        self.kwargs = {}

        # Start by parsing the uri format string
        for text, field, fmt, conv in string.Formatter().parse(uri):
            # Add field as a required kw argument
            if field is not None:
                self.kwargs[field] = ('uri', True)

        # Now consider other mentioned arguments...
        for field, type_ in kwargs.items():
            # Don't allow duplicate fields
            if field in self.kwargs:
                raise RESTException("Field %r of %s() already defined as %r" %
                                    (field, name, self.kwargs[field][0]))

            # If type_ is a tuple, first element is type and second is
            # required or not
            required = None
            if isinstance(type_, (tuple, list)):
                required = type_[1]
                type_ = type_[0]

            # Ensure valid type...
            if (type_ not in ('query', 'req', 'header') or
                (type_ == 'req' and reqwrapper is None)):
                raise RESTException("Invalid type %r for field %r of %s()" %
                                    (type_, field, name))

            # For query arguments, required defaults to False
            if required is None:
                if type_ == 'query':
                    required = False
                else:
                    required = True

            # Add the field
            self.kwargs[field] = (type_, required)

    def __get__(self, obj, owner):
        """Retrieve a wrapper to call this REST method."""

        # If access via class, return ourself
        if obj is None:
            return self

        # OK, construct a wrapper to call the method with the
        # appropriate RESTClient
        def wrapper(*args, **kwargs):
            # Build a dictionary from zipping together argorder and
            # args
            newkw = dict(zip(self.argorder, args))

            # Make kwargs override
            newkw.update(kwargs)

            return self(obj._rc, newkw)

        # Copy over the name for prettiness sake
        wrapper.__name__ = self.name
        wrapper.func_name = self.name

        return wrapper

    def __call__(self, rc, kwargs):
        """Call this REST method.

        :param rc: A RESTClient instance.
        :param kwargs: A dictionary of arguments to this REST method.
        """

        rc._debug("Called %s(%r)", self.name, kwargs)

        # We're going to build an object, a query, and headers
        headers = {}
        query = {}
        if self.reqwrapper is None:
            obj = None
            reqobj = None
        else:
            obj = {}
            reqobj = {self.reqwrapper: obj}

        # Let's walk through kwargs and make sure our required
        # arguments are present
        seen = set()
        for field, (type_, required) in self.kwargs.items():
            # Is the field present?
            if field not in kwargs:
                # Is it required?
                if required:
                    rc._debug("  Required %r argument %r missing",
                              type_, field)
                    raise RESTException("Missing required argument "
                                        "%r of %s()" %
                                        (field, self.name))

                # Not required, don't worry about it
                rc._debug("  Optional %r argument %r missing",
                          type_, field)
                continue

            # Send it to the right place
            if type_ == 'query':
                rc._debug("  Query argument %r: %r", field, kwargs[field])
                query[field] = kwargs[field]
            elif type_ == 'req':
                rc._debug("  Request object argument %r: %r", field,
                          kwargs[field])
                obj[field] = kwargs[field]
            elif type_ == 'header':
                # Reformulate the name
                hdr = '-'.join(field.split('_')).title()
                rc._debug("  Header %r argument %r: %r", hdr, field,
                          kwargs[field])
                headers[hdr] = kwargs[field]

            # Keep track of arguments we've used
            seen.add(field)

        # Deal with unprocessed arguments
        if obj is not None:
            for arg in set(kwargs.keys()) - seen:
                rc._debug("  Extra request object argument %r: %r",
                          arg, kwargs[arg])
                obj[arg] = kwargs[arg]

        # Format the URI
        uri = self.uri.format(**kwargs)
        rc._debug("  Request URI: %s", uri)

        # We now have all the pieces we need; create a request...
        req = rc.make_req(self.method, uri, query, reqobj, headers)

        # And send it
        return rc.send(req)


class RESTAPI(object):
    """Represent a REST API.

    A convenient superclass for defining REST APIs using this toolkit.
    Methods should be defined by assigning instances of RESTMethod to
    class variables.

    """

    def __init__(self, baseurl, debug_stream=None):
        """Initialize a REST API.

        Creates a RESTClient instance from the baseurl and attaches it
        where RESTMethod expects to find it.
        """

        # Create and save a RESTClient for our use
        self._rc = RESTClient(baseurl, debug_stream)

    @property
    def rc(self):
        """Retrieve the RESTClient instance."""

        return self._rc

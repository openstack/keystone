
import os
import sys

# NOTE(mikal): All of this is because if dnspython is present in your
# environment then eventlet monkeypatches socket.getaddrinfo() with an
# implementation which doesn't work for IPv6. What we're checking here is
# that the magic environment variable was set when the import happened.
if ('eventlet' in sys.modules and os.environ.get(
        'EVENTLET_NO_GREENDNS', '').lower() != 'yes'):
    raise ImportError('eventlet imported before keystone '
                      '(env var set to %s)'
                      % os.environ.get('EVENTLET_NO_GREENDNS'))

os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

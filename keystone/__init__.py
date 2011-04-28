#TOKEN AUTH
from auth_protocols.auth_token \
        import filter_factory as tokenauth_factory

#BASIC AUTH
from auth_protocols.auth_basic \
        import filter_factory as basicauth_factory

#OPENID AUTH
from auth_protocols.auth_openid \
        import filter_factory as openidauth_factory

#Remote Auth handler
from middleware.remoteauth \
        import filter_factory as remoteauth_factory

from middleware.papiauth import filter_factory as papiauth_factory

#TOKEN AUTH
from auth_protocols.auth_protocol_token \
        import filter_factory as tokenauth_factory

#BASIC AUTH
from auth_protocols.auth_protocol_basic \
        import filter_factory as basicauth_factory

#OPENID AUTH
from auth_protocols.auth_protocol_openid \
        import filter_factory as openidauth_factory

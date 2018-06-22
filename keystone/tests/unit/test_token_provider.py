# Copyright 2013 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import datetime

from oslo_utils import timeutils
from six.moves import urllib

from keystone.common import provider_api
from keystone.common import utils
import keystone.conf
from keystone import exception
from keystone.models import token_model
from keystone.tests import unit
from keystone.tests.unit import ksfixtures
from keystone.tests.unit.ksfixtures import database
from keystone import token
from keystone.token import provider


CONF = keystone.conf.CONF
PROVIDERS = provider_api.ProviderAPIs

FUTURE_DELTA = datetime.timedelta(seconds=CONF.token.expiration)
CURRENT_DATE = timeutils.utcnow()

SAMPLE_V3_TOKEN = {
    "token": {
        "catalog": [
            {
                "endpoints": [
                    {
                        "id": "02850c5d1d094887bdc46e81e1e15dc7",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:35357/v3"
                    },
                    {
                        "id": "446e244b75034a9ab4b0811e82d0b7c8",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:5000/v3"
                    },
                    {
                        "id": "47fa3d9f499240abb5dfcf2668f168cd",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:5000/v3"
                    }
                ],
                "id": "26d7541715a44a4d9adad96f9872b633",
                "type": "identity",
            },
            {
                "endpoints": [
                    {
                        "id": "aaa17a539e364297a7845d67c7c7cc4b",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    },
                    {
                        "id": "4fa9620e42394cb1974736dce0856c71",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    },
                    {
                        "id": "9673687f9bc441d88dec37942bfd603b",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    }
                ],
                "id": "d27a41843f4e4b0e8cf6dac4082deb0d",
                "type": "image",
            },
            {
                "endpoints": [
                    {
                        "id": "7bd0c643e05a4a2ab40902b2fa0dd4e6",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1"
                    },
                    {
                        "id": "43bef154594d4ccb8e49014d20624e1d",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1/AUTH_01257"
                    },
                    {
                        "id": "e63b5f5d7aa3493690189d0ff843b9b3",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1/AUTH_01257"
                    }
                ],
                "id": "a669e152f1104810a4b6701aade721bb",
                "type": "object-store",
            },
            {
                "endpoints": [
                    {
                        "id": "51934fe63a5b4ac0a32664f64eb462c3",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    },
                    {
                        "id": "869b535eea0d42e483ae9da0d868ebad",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    },
                    {
                        "id": "93583824c18f4263a2245ca432b132a6",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    }
                ],
                "id": "7f32cc2af6c9476e82d75f80e8b3bbb8",
                "type": "compute",
            },
            {
                "endpoints": [
                    {
                        "id": "b06997fd08414903ad458836efaa9067",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Admin"
                    },
                    {
                        "id": "411f7de7c9a8484c9b46c254fb2676e2",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Cloud"
                    },
                    {
                        "id": "f21c93f3da014785854b4126d0109c49",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Cloud"
                    }
                ],
                "id": "b08c9c7d4ef543eba5eeb766f72e5aa1",
                "type": "ec2",
            },
            {
                "endpoints": [
                    {
                        "id": "077d82df25304abeac2294004441db5a",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    },
                    {
                        "id": "875bf282362c40219665278b4fd11467",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    },
                    {
                        "id": "cd229aa6df0640dc858a8026eb7e640c",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    }
                ],
                "id": "5db21b82617f4a95816064736a7bec22",
                "type": "volume",
            }
        ],
        "expires_at": "2013-05-22T00:02:43.941430Z",
        "issued_at": "2013-05-21T00:02:43.941473Z",
        "methods": [
            "password"
        ],
        "project": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "01257",
            "name": "service"
        },
        "is_domain": False,
        "roles": [
            {
                "id": "9fe2ff9ee4384b1894a90878d3e92bab",
                "name": "_member_"
            },
            {
                "id": "53bff13443bd4450b97f978881d47b18",
                "name": "admin"
            }
        ],
        "user": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "f19ddbe2c53c46f189fe66d0a7a9c9ce",
            "name": "nova",
            "password_expires_at": "2013-08-21T00:02:43.941473Z"
        },
        "OS-TRUST:trust": {
            "id": "abc123",
            "trustee_user_id": "123456",
            "trustor_user_id": "333333",
            "impersonation": False
        }
    }
}

SAMPLE_V3_TOKEN_WITH_EMBEDED_VERSION = {
    "token": {
        "catalog": [
            {
                "endpoints": [
                    {
                        "id": "02850c5d1d094887bdc46e81e1e15dc7",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:35357/v3"
                    },
                    {
                        "id": "446e244b75034a9ab4b0811e82d0b7c8",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:5000/v3"
                    },
                    {
                        "id": "47fa3d9f499240abb5dfcf2668f168cd",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:5000/v3"
                    }
                ],
                "id": "26d7541715a44a4d9adad96f9872b633",
                "type": "identity",
            },
            {
                "endpoints": [
                    {
                        "id": "aaa17a539e364297a7845d67c7c7cc4b",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    },
                    {
                        "id": "4fa9620e42394cb1974736dce0856c71",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    },
                    {
                        "id": "9673687f9bc441d88dec37942bfd603b",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:9292"
                    }
                ],
                "id": "d27a41843f4e4b0e8cf6dac4082deb0d",
                "type": "image",
            },
            {
                "endpoints": [
                    {
                        "id": "7bd0c643e05a4a2ab40902b2fa0dd4e6",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1"
                    },
                    {
                        "id": "43bef154594d4ccb8e49014d20624e1d",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1/AUTH_01257"
                    },
                    {
                        "id": "e63b5f5d7aa3493690189d0ff843b9b3",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8080/v1/AUTH_01257"
                    }
                ],
                "id": "a669e152f1104810a4b6701aade721bb",
                "type": "object-store",
            },
            {
                "endpoints": [
                    {
                        "id": "51934fe63a5b4ac0a32664f64eb462c3",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    },
                    {
                        "id": "869b535eea0d42e483ae9da0d868ebad",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    },
                    {
                        "id": "93583824c18f4263a2245ca432b132a6",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8774/v1.1/01257"
                    }
                ],
                "id": "7f32cc2af6c9476e82d75f80e8b3bbb8",
                "type": "compute",
            },
            {
                "endpoints": [
                    {
                        "id": "b06997fd08414903ad458836efaa9067",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Admin"
                    },
                    {
                        "id": "411f7de7c9a8484c9b46c254fb2676e2",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Cloud"
                    },
                    {
                        "id": "f21c93f3da014785854b4126d0109c49",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8773/services/Cloud"
                    }
                ],
                "id": "b08c9c7d4ef543eba5eeb766f72e5aa1",
                "type": "ec2",
            },
            {
                "endpoints": [
                    {
                        "id": "077d82df25304abeac2294004441db5a",
                        "interface": "admin",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    },
                    {
                        "id": "875bf282362c40219665278b4fd11467",
                        "interface": "internal",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    },
                    {
                        "id": "cd229aa6df0640dc858a8026eb7e640c",
                        "interface": "public",
                        "region": "RegionOne",
                        "url": "http://localhost:8776/v1/01257"
                    }
                ],
                "id": "5db21b82617f4a95816064736a7bec22",
                "type": "volume",
            }
        ],
        "expires_at": "2013-05-22T00:02:43.941430Z",
        "issued_at": "2013-05-21T00:02:43.941473Z",
        "methods": [
            "password"
        ],
        "project": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "01257",
            "name": "service"
        },
        "roles": [
            {
                "id": "9fe2ff9ee4384b1894a90878d3e92bab",
                "name": "_member_"
            },
            {
                "id": "53bff13443bd4450b97f978881d47b18",
                "name": "admin"
            }
        ],
        "user": {
            "domain": {
                "id": "default",
                "name": "Default"
            },
            "id": "f19ddbe2c53c46f189fe66d0a7a9c9ce",
            "name": "nova"
        },
        "OS-TRUST:trust": {
            "id": "abc123",
            "trustee_user_id": "123456",
            "trustor_user_id": "333333",
            "impersonation": False
        }
    },
    'token_version': 'v3.0'
}


def create_v3_token():
    return {
        "token": {
            'methods': [],
            "expires_at": utils.isotime(timeutils.utcnow() + FUTURE_DELTA),
            "issued_at": "2013-05-21T00:02:43.941473Z",
        }
    }


SAMPLE_V3_TOKEN_EXPIRED = {
    "token": {
        "expires_at": utils.isotime(CURRENT_DATE),
        "issued_at": "2013-05-21T00:02:43.941473Z",
    }
}

SAMPLE_MALFORMED_TOKEN = {
    "token": {
        "bogus": {
            "no expiration data": None
        }
    }
}


class TestTokenProvider(unit.TestCase):
    def setUp(self):
        super(TestTokenProvider, self).setUp()
        self.useFixture(database.Database())
        self.useFixture(
            ksfixtures.KeyRepository(
                self.config_fixture,
                'fernet_tokens',
                CONF.fernet_tokens.max_active_keys
            )
        )
        self.load_backends()

    def test_strings_are_url_safe(self):
        s = provider.random_urlsafe_str()
        self.assertEqual(s, urllib.parse.quote_plus(s))

    def test_unsupported_token_provider(self):
        self.config_fixture.config(group='token',
                                   provider='MyProvider')
        self.assertRaises(ImportError,
                          token.provider.Manager)

    def test_provider_token_expiration_validation(self):
        token = token_model.TokenModel()
        token.issued_at = "2013-05-21T00:02:43.941473Z"
        token.expires_at = utils.isotime(CURRENT_DATE)

        self.assertRaises(exception.TokenNotFound,
                          PROVIDERS.token_provider_api._is_valid_token,
                          token)

        token = token_model.TokenModel()
        token.issued_at = "2013-05-21T00:02:43.941473Z"
        token.expires_at = utils.isotime(timeutils.utcnow() + FUTURE_DELTA)
        self.assertIsNone(PROVIDERS.token_provider_api._is_valid_token(token))

    def test_validate_v3_token_with_no_token_raises_token_not_found(self):
        self.assertRaises(
            exception.TokenNotFound,
            PROVIDERS.token_provider_api.validate_token,
            None)

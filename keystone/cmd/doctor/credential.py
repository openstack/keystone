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

import keystone.conf


CONF = keystone.conf.CONF


def symptom_unique_key_repositories():
    """Key repositories for encryption should be unique.

    Even though credentials are encrypted using the same mechanism as Fernet
    tokens, they should have key repository locations that are independent of
    one another. Using the same repository to encrypt credentials and tokens
    can be considered a security vulnerability because ciphertext from the keys
    used to encrypt credentials is exposed as the token ID. Sharing a key
    repository can also lead to premature key removal during key rotation. This
    could result in indecipherable credentials, rendering them completely
    useless, or early token invalidation because the key that was used to
    encrypt the entity has been deleted.

    Ensure `keystone.conf [credential] key_repository` and `keystone.conf
    [fernet_tokens] key_repository` are not pointing to the same location.
    """
    return (
        CONF.credential.key_repository == CONF.fernet_tokens.key_repository
    )

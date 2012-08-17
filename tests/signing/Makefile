# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Red Hat,. Inc

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



.SUFFIXES:  .json .pem

SOURCES=auth_token_unscoped.json auth_token_scoped.json revocation_list.json
SIGNED=$(SOURCES:.json=.pem)
TARGETS=$(SIGNED)

all: $(TARGETS)
clean:
	rm -f $(TARGETS) *~

.json.pem :
	openssl cms  -sign -in $<  -nosmimecap  -signer signing_cert.pem -inkey private_key.pem -outform PEM -nodetach -nocerts  -noattr -out $@




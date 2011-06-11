## Lines beginning with '##' are for explaining the contents of this
## file, and should be removed if you copy the file to create a new
## (set of) tests.  Also note that the file must be named to match the
## scheme "test_[...].py", i.e., "test_tokens.py".
##
## I don't think I need to explain the copyright notice :)
##
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


## This test suite uses the DTest framework, which can be found on
## PyPi ("pip install dtest").  DTest uses threading to perform tests
## in parallel; the threading can be limited by using dependencies,
## but the purpose of dependencies is really to say that some test
## must pass before other actions can be performed.  Within dtest, the
## util module contains a number of useful "assert_*()" functions, but
## if you want, you can just use the "assert" statement.
##
## Also note that names are important.  Modules should be named
## "test_[...].py", as mentioned above.  Classes must extend
## base.KeystoneTest (a subclass of dtest.DTestCase), and test methods
## should have names like "test_[...]" (or be decorated with the
## @dtest.istest decorator).  Adhere to these rules, and DTest can
## discover and run the tests without you having to do anything other
## than create them.
import dtest
from dtest import util

## The "base" module contains KeystoneTest, which ensures that there's
## a Keystone authentication token in self.token and an API accessor
## in self.ks.  See ksapi.py for a list of what methods are available
## on self.ks.
import base


## Tests should be gathered together in classes, not too dissimilar
## from how unittest works.  Extend base.KeystoneTest, so you get
## self.token and self.ks.  If you override setUp(), make sure you
## call the superclass's setUp() method (it's responsible for setting
## self.ks).  Try to avoid overriding setUpClass() or tearDownClass()
## if you can help it (they're responsible for setting up and
## destroying self.token).
class SampleTest(base.KeystoneTest):
    def test_sample(self):
        """Test that we can do sample."""
        ## You don't *have* to declare a doc string, but it's good
        ## practice.

        ## Here we're making a "sample_call()", passing self.token as
        ## the authentication token.  For available calls and the
        ## order of arguments, check out ksapi.py.  The return value
        ## will be an httplib.HTTPResponse object with additional
        ## 'body' (str) and 'obj' (dict) attributes.  If a status code
        ## greater than or equal to 400 is returned from the other
        ## end, an exception will be raised; the response will be
        ## attached to the 'response' attribute of the exception, and
        ## the status will be on the 'status' attribute of the
        ## exception.  Note that redirects are followed.
        resp = self.ks.sample_call(self.token, 'argument 1', 'argument 2')

        # Verify that resp is correct
        util.assert_equal(resp.status, 200)
        util.assert_in('sample', resp.obj)
        ## Place your various assertions about the response here.

        ## Rinse, lather, repeat.  You should perform only a single
        ## test per test method, but if you're doing creation tests,
        ## it makes sense to include the deletion test in the same
        ## test method.  Remember, the only control you have over test
        ## ordering is by setting up dependencies (@dtest.depends()).
        ## No return value is necessary.

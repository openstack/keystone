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

# NOTE(dstanek): Uncomment the [pbr] section in setup.cfg and remove this
# Sphinx extension when https://launchpad.net/bugs/1260495 is fixed.

import os.path as path

from sphinx import apidoc


# NOTE(dstanek): pbr will run Sphinx multiple times when it generates
# documentation. Once for each builder. To run this extension we use the
# 'builder-inited' hook that fires at the beginning of a Sphinx build.
# We use ``run_already`` to make sure apidocs are only generated once
# even if Sphinx is run multiple times.
run_already = False


def run_apidoc(app):
    global run_already
    if run_already:
        return
    run_already = True

    package_dir = path.abspath(path.join(app.srcdir, '..', '..', 'keystone'))
    source_dir = path.join(app.srcdir, 'api')
    apidoc.main(['apidoc', package_dir, '-f',
                 '-H', 'Keystone Modules',
                 '-o', source_dir])


def setup(app):
    app.connect('builder-inited', run_apidoc)

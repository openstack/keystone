==================================
Building Contributor Documentation
==================================

This documentation is written by contributors, for contributors.

The source is maintained in the `doc/source` folder using
`reStructuredText`_ and built by `Sphinx`_ (a dependency from `tools/pip-requires`).

.. _reStructuredText: http://docutils.sourceforge.net/rst.html
.. _Sphinx: http://sphinx.pocoo.org/

Building automatically
======================

From the project root, just type::

    $ python setup.py build_sphinx

Building manually
=================

#. Generate the code.rst file so that Sphinx will pull in our docstrings::

    $ python doc/generate_autodoc_index.py

#. Use `sphinx-build` to produce the docs in HTML::

    $ sphinx-build -b html doc/source/ build/sphinx/html/

#. Similarly, build the man pages (optional)::

    $ sphinx-build -b man doc/source/ build/sphinx/man/

After building
==============

Navigate to the `build/sphinx/html` directory to browse generated the HTML docs.

==========================
Building the Documentation
==========================

Using setup.py
==============

From the project root, just type::

  % setup.py build_sphinx



Manually
========

  1. Generate the code.rst file so that Sphinx will pull in our docstrings::

      % ./generate_autodoc_index.py

  2. Run `sphinx_build`::

      % sphinx-build -b html source build/html


The docs have been built
========================

Check out the `build` directory to find them. Yay!


How to build this documentation from the source
===============================================

Pre-requisites for the simple build, or to update man pages:

* Sphinx 1.0.4 or higher (See http://sphinx.pocoo.org) with “autodoc”
  extension installed.

Additional prerequisites to include the API reference based on Doxygen
markup:

* python 2.5 with the Cheetah, lxml, and xml modules
* Doxygen


Simple build without API reference
----------------------------------

To test simple changes to the RST sources, you can build the
documentation without the Doxygen reference by running, from the doc
directory::

    sphinx-build rst_source test_html

You will see a number of warnings about missing files.  This is
expected.


Updating man pages
------------------

Man pages are generated from the RST sources and checked into the
``src/man`` directory of the repository.  This allows man pages to be
installed without requiring Sphinx when using a source checkout.  To
regenerate these files, run ``make rstman`` from the man subdirectory
of a configured build tree.  You can also do this from an unconfigured
source tree with::

    cd src/man
    make -f Makefile.in top_srcdir=.. srcdir=. rstman
    make clean

As with the simple build, it is normal to see warnings about missing
files when rebuilding the man pages.


Building for a release tarball or web site
------------------------------------------

To generate documentation in HTML format, run ``make rsthtml`` in the
``doc`` subdirectory of a configured build tree (the build directory
corresponding to ``src/doc``, not the top-level ``doc`` directory).
The output will be placed in the top-level ``doc/rst_html`` directory.
This build will include the API reference generated from Doxygen
markup in the source tree.

Documentation generated this way will use symbolic names for paths
(like ``BINDIR`` for the directory containing user programs), with the
symbolic names being links to a table showing typical values for those
paths.

You can also do this from an unconfigured source tree with::

    cd src/doc
    make -f Makefile.in top_srcdir=.. PYTHON=python rsthml
    make -f Makefile.in clean


Building for an OS package or site documentation
------------------------------------------------

To generate documentation specific to a build of MIT krb5 as you have
configured it, run ``make substhtml`` in the ``doc`` subdirectory of a
configured build tree (the build directory corresponding to
``src/doc``, not the top-level ``doc`` directory).  The output will be
placed in the ``rst_html_subst`` subdirectory of that build directory.
This build will include the API reference.

Documentation generated this way will use concrete paths (like
``/usr/local/bin`` for the directory containing user programs, for a
default custom build).

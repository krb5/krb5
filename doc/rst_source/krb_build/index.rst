.. _build_V5:

Building Kerberos V5
====================

.. note:: This document was copied from **Kerberos V5 Installation
          Guide** with minor changes.  Currently it is under
          review.  Please, send your feedback, corrections and
          additions to krb5-bugs@mit.edu.  Your contribution is
          greatly appreciated.


Build Requirements
------------------

In order to build Kerberos V5, you will need approximately 60-70
megabytes of disk space.  The exact amount will vary depending on the
platform and whether the distribution is compiled with debugging
symbol tables or not.

Your C compiler must conform to ANSI C (ISO/IEC 9899:1990, "c89").
Some operating systems do not have an ANSI C compiler, or their
default compiler requires extra command-line options to enable ANSI C
conformance.

If you wish to keep a separate build tree, which contains the compiled
\*.o file and executables, separate from your source tree, you will
need a make program which supports **VPATH**, or you will need to use
a tool such as lndir to produce a symbolic link tree for your build
tree.

The first step in each of these build procedures is to unpack the
source distribution.  The Kerberos V5 distribution comes in a tar
file, generally named krb5-1.9.tar (for version 1.9. We will assume
that version is 1.9. Please, adjust this number accordingly), which
contains a compressed tar file consisting of the sources for all of
Kerberos (generally krb5-1.9.tar.gz) and a PGP signature for this
source tree (generally krb5-1.9.tar.gz.asc).  MIT highly recommends
that you verify the integrity of the source code using this signature.

Unpack the compressed tar file in some directory, such as
``/u1/krb5-1.9``.  (In the rest of this document, we will assume that
you have chosen to unpack the Kerberos V5 source distribution in this
directory.  Note that the tarfiles will by default all unpack into the
``./krb5-1.9`` directory, so that if your current directory is ``/u1``
when you unpack the tarfiles, you will get ``/u1/krb5-1.9/src``, etc.)


Contents
--------

.. toctree::
   :maxdepth: 1

   directory_org.rst
   doing_build.rst
   options2configure.rst
   osconf.rst
   test_cov.rst

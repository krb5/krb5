Doing the build
======================

Using *autoconf*
-------------------

(If you are not a developer, you can skip this section.)

In most of the Kerberos V5 source directories, there is a *configure* script which automatically determines 
the compilation environment and creates the proper Makefiles for a particular platform. 
These configure files are generated using *autoconf*, which can be found in the *src/util/autoconf* directory in the distribution.

Normal users will not need to worry about running *autoconf*; the distribution comes with the configure files already prebuilt. 

Note that in order to run *autoconf*, you must have GNU m4 in your path. 
Before you use the *autoconf* in the Kerberos V5 source tree, you may also need to run configure, 
and then run make in the *src/util/autoconf* directory in order to properly set up *autoconf*.

One tool which is provided for the convenience of developers can be found in *src/util/reconf*. 
This program should be run while the current directory is the top source directory. 
It will automatically rebuild any configure files which need rebuilding. 
If you know that you have made a change that will require that all the configure files need to be rebuilt from scratch, specify the *--force* option::

      cd /u1/krb5-1.9/src
      ./util/reconf --force
     
Then follow the instructions for building packaged source trees (below). 
To install the binaries into a binary tree, do::

     cd /u1/krb5-1.9/src
     make all
     make install DESTDIR=somewhere-else
     
You have a number of different options in how to build Kerberos. 

.. _do_build:

Building within a single tree
-------------------------------

If you only need to build Kerberos for one platform, using a single directory tree 
which contains both the source files and the object files is the simplest. 
However, if you need to maintain Kerberos for a large number of platforms, 
you will probably want to use separate build trees for each platform. 
We recommend that you look at OS Incompatibilities, for notes that we have on particular operating systems.

If you don't want separate build trees for each architecture, then use the following abbreviated procedure::

   1. cd /u1/krb5-1.9/src
   2. ./configure
   3. make 

That's it!

Building with separate build directories
--------------------------------------------

If you wish to keep separate build directories for each platform, you can do so using the following procedure. 
(Note, this requires that your make program support *VPATH*. GNU's make will provide this functionality, for example.) 
If your make program does not support this, see the next section.

For example, if you wish to store the binaries in *tmpbuild* build directory you might use the following procedure::

   1. mkdir /u1/tmpbuild
   2. cd /u1/tmpbuild
   3. /u1/krb5-1.9/src/configure
   4. make 

Building using *lndir*
-----------------------

If you wish to keep separate build directories for each platform, 
and you do not have access to a make program which supports VPATH, all is not lost. 
You can use the lndir program to create symbolic link trees in your build directory.

For example, if you wish to create a build directory for solaris binaries you might use the following procedure::

   1. mkdir /u1/krb5-1.9/solaris
   2. cd /u1/krb5-1.9/solaris
   3. /u1/krb5-1.9/src/util/lndir `pwd`/../src
   4. ./configure
   5. make 

You must give an absolute pathname to *lndir* because it has a bug that makes it fail for relative pathnames. 
Note that this version differs from the latest version as distributed and installed by the XConsortium with X11R6. 
Either version should be acceptable. 


Installing the binaries
-------------------------

Once you have built Kerberos, you should install the binaries. You can do this by running::

      make install
     

If you want to install the binaries into a destination directory that is not their final destination, 
which may be convenient if you want to build a binary distribution to be deployed on multiple hosts, you may use::

      make install DESTDIR=/path/to/destdir
     

This will install the binaries under *DESTDIR/PREFIX*, e.g., the user programs will install into *DESTDIR/PREFIX/bin*, 
the libraries into *DESTDIR/PREFIX/lib*, etc.

Some implementations of make allow multiple commands to be run in parallel, for faster builds. 
We test our Makefiles in parallel builds with GNU make only; they may not be compatible with other parallel build implementations.

Testing the build
--------------------

The Kerberos V5 distribution comes with built-in regression tests. 
To run them, simply type the following command while in the top-level build directory 
(i.e., the directory where you sent typed make to start building Kerberos; see :ref:`do_build`)::

     make check
     

However, there are several prerequisites that must be satisfied first:

    * Configure and build Kerberos with Tcl support. Tcl is used to drive the test suite. 
      This often means passing *--with-tcl* to configure to tell it the location of the Tcl configuration script. (See :ref:`options2configure`.)
    * On some operating systems, you have to run *make install* before
      running *make check*, or the test suite will pick up installed
      versions of Kerberos libraries rather than the newly built ones.
      You can install into a prefix that isn't in the system library
      search path, though. Alternatively, you can configure with
      *--disable-rpath*, which renders the build tree less suitable
      for installation, but allows testing without interference from
      previously installed libraries.
    * In order to test the RPC layer, the local system has to be running the *portmap* daemon and 
      it has to be listening to the regular network interface (not just localhost). 


Cleaning up the build 
-------------------------

  - Use *make clean* to remove all files generated by running *make* command. 
  - Use *make distclean* to remove all files generated by running *./configure* script.
    After running *make distclean* your source tree (ideally) should look like the raw (just un-tarred) source tree with executed *util/reconf* command.

    



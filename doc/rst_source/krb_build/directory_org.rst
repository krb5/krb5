Organization of the source directory
============================================

Below is a brief overview of the organization of the complete source directory. More detailed descriptions follow.

=============== ==============================================
*appl*           Kerberos application client and server programs
*clients*          Kerberos V5 user programs (See :ref:`user_commands`)
gen-manpages_     manpages for Kerberos V5 and the Kerberos V5 login program 
*include*        include files needed to build the Kerberos system
*kadmin*         administrative interface to the Kerberos master database: :ref:`kadmin(1)`, :ref:`kdb5_util(8)`, :ref:`ktutil(1)`. 
*kdc*            the Kerberos V5 Authentication Service and Key Distribution Center 
*krb524*         utilities for converting Kerberos V5 credentials into Kerberos V4 credentials suitable for use with applications that for whatever reason do not use V5 directly.
lib_              libraries for use with/by Kerberos V5 
*mac*              source code for building Kerberos V5 on MacOS 
prototype_        templates for source code files 
*slave*           utilities for propagating the database to slave KDCs :ref:`kprop(8)` and :ref:`kpropd(8)`
*tests*            test suite 
util_             various utilities for building/configuring the code, sending bug reports, etc. 
*windows*          source code for building Kerberos V5 on Windows (see windows/README) 
=============== ==============================================


**gen-manpages**
----------------

There are two manual pages in this directory. One is an introduction to the Kerberos system. 
The other describes the *.k5login* file which allows users to give access with their UID 
to other users authenticated by the Kerberos system.

.. _lib:

**lib**
------------------

The *lib* directory contain several subdirectories as well as some definition and glue files. 
The *crypto* subdirectory contains the Kerberos V5 encryption library. 
The *gssapi* library contains the Generic Security Services API, which is a library of commands to be used in secure client-server communication. 
The *kadm5* directory contains the libraries for the KADM5 administration utilities. 
The Kerberos 5 database libraries are contained in *kdb*. 
The *krb5* directory contains Kerberos 5 API. 
The *rpc* directory contains the API for the Kerberos Remote Procedure Call protocol.
The *apputils* directory contains the code for the generic network servicing. 

.. _prototype:

**prototype**
-----------------

This directory contains several template files. 
The *prototype.h* and *prototype.c* files contain the MIT copyright message and a placeholder for the title and description of the file.
*prototype.h* also has a short template for writing ifdef and ifndef preprocessor statements. 
The *getopt.c* file provides a template for writing code that will parse the options with which a program was called.

.. _util:

**util**
-----------------------------------


This directory contains several utility programs and libraries. 
The programs used to configure and build the code, such as *autoconf, lndir, kbuild, reconf, and makedepend*, are in this directory. 
The *profile* directory contains most of the functions which parse the Kerberos configuration files (krb5.conf and kdc.conf). 
Also in this directory are 
the Kerberos error table library and 
utilities (et), 
the Sub-system library and utilities (ss), 
database utilities (db2), 
pseudo-terminal utilities (pty), 
bug-reporting program send-pr, and 
a generic support library support used by several of our other libraries. 


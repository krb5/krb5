Database administration
======================================

.. note:: This document was copied from **Kerberos V5 System Administrator's Guide** with minor changes. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.

Your Kerberos database contains all of your realm's Kerberos principals, their passwords, and other administrative information about each principal. For the most part, you will use the :ref:`kdb5_util(8)` program to manipulate the Kerberos database as a whole, and the kadmin program to make changes to the entries in the database. (One notable exception is that users will use the :ref:`kpasswd(1)` program to change their own passwords.) The kadmin program has its own command-line interface, to which you type the database administrating commands.

:ref:`kdb5_util(8)` provides a means to create, delete, load, or dump a Kerberos database. It also includes a command to stash a copy of the master database key in a file on a KDC, so that the KDC can authenticate itself to the *kadmind* and *krb5kdc* daemons at boot time.

*kadmin* provides for the maintenance of Kerberos principals, KADM5 policies, and service key tables (*keytabs*).  It exists as both a Kerberos client, *kadmin*, using Kerberos authentication and an RPC, to operate securely from anywhere on the network, and as a local client, *kadmin.local*, intended to run directly on the KDC without Kerberos authentication. *kadmin.local* need not run on the kdc if the database is LDAP. Other than the fact that the remote client uses Kerberos to authenticate the person using it, the functionalities of the two versions are identical.  The local version is necessary to enable you to set up enough of the database to be able to use the remote version. It replaces the now obsolete kdb5_edit (except for database dump and load, which are provided by *kdb5_util*).

The remote version authenticates to the KADM5 server using the service principal *kadmin/admin*. If the credentials cache contains a ticket for the *kadmin/admin* principal, and the *-c* ccache option is specified, that ticket is used to authenticate to KADM5. Otherwise, the *-p* and *-k* options are used to specify the client Kerberos principal name used to authenticate. Once *kadmin* has determined the principal name, it requests a *kadmin/admin* Kerberos service ticket from the KDC, and uses that service ticket to authenticate to KADM5.

See :ref:`kadmin(1)` for the available *kadmin* and *kadmin.local* commands and options.

.. toctree::
   :maxdepth: 2

   db_options.rst
   date_format.rst
   db_princs/index.rst
   db_policies/index.rst
   db_operations/index.rst
   ldap_operations/index.rst
   xrealm_authn.rst
   change_tgtkey.rst
   incr_db_prop.rst

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db


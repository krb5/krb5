.. _kadmind(8):

kadmind
==========

SYNOPSIS
-----------
       
**kadmind** [**-x** *db_args*] [**-r** *realm*] [**-m**] [**-nofork**] [**-port** *port-number*] [**-P** *pid_file*]

DESCRIPTION
-----------

This command starts the KADM5 administration server. If the database is db2, the administration server runs on the master Kerberos server, 
which stores the KDC prinicpal database and the KADM5 policy database. If the database is LDAP, the administration server and
the KDC server need not run on the same machine.  *kadmind* accepts remote requests to administer the information in these databases.
Remote requests are sent, for example, by kadmin(8) and the kpasswd(1) command, both of which are clients of *kadmind*.

*kadmind* requires a number of configuration files to be set up in order for it to work:

:ref:`kdc.conf`  
            The KDC configuration file contains configuration informatin for the KDC and the KADM5 system.  *kadmind* understands a number
            of  variable  settings in this file, some of whch are mandatory and some of which are optional.
            See the CONFIGURATION VALUES section below.

*keytab*    
            Kadmind requires a keytab containing correct entries for the kadmin/admin and kadmin/changepw principals for every realm that
            *kadmind* will answer requests for.  The keytab can be created with the kadmin(8) client.
            The location of the keytab is determined by the *admin_keytab* configuration variable (see CONFIGURATION VALUES).

*ACL* file 
            *kadmind*'s *ACL* (access control list) tells it which principals are allowed to perform KADM5 administration actions.
            The  path of  the *ACL* file is specified via the acl_file configuration variable (see CONFIGURATION VALUES).
            The syntax of the *ACL* file is specified in the *ACL* FILE SYNTAX section below.
            
            If the *kadmind*'s ACL file is modified, the *kadmind* daemon needs to be restarted for changes to take effect.

After the server begins running, it puts itself in the background and disassociates itself from its controlling terminal.

*kadmind* can be configured for incremental database propagation.  Incremental propagation allows slave KDC servers to receive  principal
and  policy  updates  incrementally instead of receiving full dumps of the database.  This facility can be enabled in the :ref:`kdc.conf` file
with the *iprop_enable* option.  See the :ref:`kdc.conf` documentation for other options for tuning incremental propagation parameters.
Incremental propagation requires the principal "kiprop/MASTER\@REALM" i
(where MASTER is the master KDC's canonical host name, and REALM the realm name) to be registered in the database.


OPTIONS
-----------

       **-x** *db_args*
              specifies the database specific arguments.

              Options supported for LDAP database are:

                   **-x** *nconns* =<number_of_connections>
                          specifies the number of connections to be maintained per LDAP server.

                   **-x** *host* =<ldapuri>
                          specifies the LDAP server to connect to by a LDAP URI.

                   **-x** *binddn* =<binddn>
                          specifies the DN of the object used by the administration server to bind to the LDAP server.  This object should have the
                          read and write rights on the realm container, principal container and the subtree that is referenced by the realm.

                   **-x** *bindpwd* =<bind_password>
                          specifies the password for the above mentioned binddn. It is recommended not to use this option.
                          Instead, the password can be stashed using the stashsrvpw command of kdb5_ldap_util.

       **-r** *realm*
              specifies the default realm that *kadmind* will serve; if it is not specified, the default realm of the host is used.
              *kadmind* will answer requests for any realm that exists in the local KDC database and for which the appropriate principals are in its keytab.

       **-m**
              specifies that the master database password should be fetched from the keyboard rather than from a file on disk.
              Note that the server gets the password prior to putting itself in the background; 
              in combination with the *-nofork* option, you must place it in the background by hand.

       **-nofork**
              specifies that the server does not put itself in the background and does not disassociate itself from the terminal.
              In normal operation, you should always allow the server place itself in the background.

       **-port** *port-number*
              specifies the port on which the administration server listens for connections.  The default is is controlled by the *kadmind_port*
              configuration variable (see below).

       **-P** *pid_file*
              specifies the file to which the PID of *kadmind* process should be written to after it starts up.  This can be used to identify
              whether *kadmind* is still running and to allow init scripts to stop the correct process.

CONFIGURATION VALUES
---------------------------

In addition to the relations defined in kdc.conf(5), *kadmind* understands the following relations, 
all of which should appear in the [realms] section:

       **acl_file**
              The path of *kadmind*'s *ACL* file.  **Mandatory**.  No default.

       **admin_keytab**
              The  name  of  the keytab containing entries for the principals kadmin/admin and kadmin/changepw in each realm that *kadmind* will
              serve.  The default is the value of the KRB5_KTNAME environment variable, if defined.  **Mandatory**.

       **dict_file**
              The path of *kadmind*'s password dictionary.  A principal with any password policy will not be allowed to select any  password  in
              the dictionary.  Optional.  No default.

       **kadmind_port**
              The TCP port on which *kadmind* will listen.  The default is 749.

*ACL* FILE SYNTAX
-------------------

The *ACL* file controls which principals can or cannot perform which administrative functions.  For operations  that  affect  principals,
the  *ACL* file also controls which principals can operate on which other principals.  This file can contain comment lines, null lines or
lines which contain *ACL* entries.  Comment lines start with the sharp sign (#) and continue until the end of the line.  
Lines containing *ACL* entries have the format of principal whitespace *operation-mask* [whitespace *operation-target*]

Ordering  is important.  The first matching entry is the one which will control access for a particular principal on a particular principal.

       **principal**
              may specify a partially or fully qualified Kerberos version 5 principal name.  Each component of  the  name  may  be  wildcarded
              using the asterisk ( * ) character.

       **operation-target**
              [Optional]  may specify a partially or fully qualified Kerberos version 5 principal name.  Each component of the name may be
              wildcarded using the asterisk ( \* ) character.

       **operation-mask**
              Specifies what operations may or may not be peformed by a principal matching a particular entry.  This is a string of one or
              more of the following list of characters or their upper-case counterparts.  If the character is upper-case, then the operation
              is disallowed.  If the character is lower-case, then the operation is permitted.

              ::

                  a    [Dis]allows the addition of principals or policies in the database.
                  d    [Dis]allows the deletion of principals or policies in the database.
                  m    [Dis]allows the modification of principals or policies in the database.
                  c    [Dis]allows the changing of passwords for principals in the database.
                  i    [Dis]allows inquiries to the database.
                  l    [Dis]allows the listing of principals or policies in the database.
                  p    [Dis]allows the propagation of the principal database.
                  x    Short for admcil.
                  *    Same as x.
       
              Some examples of valid entries here are:


              *user/instance@realm adm*
                  A standard fully qualified name.  
                  The *operation-mask* only applies to this principal and specifies that [s]he may add, 
                  delete  or modify principals and policies, but not change anybody else's password.

              *user/instance@realm cim service/instance@realm*
                  A  standard fully qualified name and a standard fully qualified target.  
                  The *operation-mask* only applies to this principal operating on this target and specifies 
                  that [s]he may change the target's password, request information about the target and  modify it.

              *user/\*@realm ac*
                  A  wildcarded name.  The *operation-mask* applies to all principals in realm "realm" whose first component is "user" and specifies
                  that [s]he may add principals and change anybody's password.

              *user/\*@realm i \*/instance@realm*
                  A wildcarded name and target.  The *operation-mask* applies to all principals in realm "realm" whose first component is "user" and
                  specifies that [s]he may perform inquiries on principals whose second component is "instance" and realm is "realm".

FILES
-----------

Note: The first three files are specific to db2 database.

==================== ===================================================================
principal.db          default name for Kerberos principal database
<dbname>.kadm5        KADM5  administrative database.  (This would be "principal.kadm5", if you use the default database name.)  Contains policy information.
<dbname>.kadm5.lock   lock file for the KADM5 administrative database.  This file works backwards from most other lock files.  I.e., kadmin will exit with an error if this file does not exist.
kadm5.acl             file containing list of principals and their kadmin administrative privileges.  See above for a description.
kadm5.keytab          keytab file for *kadmin/admin* principal.
kadm5.dict            file containing dictionary of strings explicitly disallowed as passwords.
==================== ===================================================================

SEE ALSO
-----------

kpasswd(1), kadmin(8), kdb5_util(8), kadm5_export(8), kadm5_import(8), kdb5_ldap_util(8)



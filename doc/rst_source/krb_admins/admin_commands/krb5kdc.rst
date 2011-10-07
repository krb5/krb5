.. _krb5kdc(8):

krb5kdc
===========================

SYNOPSIS
----------

**krb5kdc**
       [  **-x**  *db_args* ]
       [ **-d** *dbname* ]
       [ **-k** *keytype* ]
       [ **-M** *mkeyname* ] 
       [ **-p** *portnum* ]
       [ **-m** ] 
       [ **-r** *realm* ] 
       [ **-n** ] 
       [ **-w** *numworkers* ] 
       [ **-P** *pid_file* ]

DESCRIPTION
--------------

*krb5kdc* is the Kerberos version 5 Authentication Service and Key Distribution Center (AS/KDC).

OPTIONS
----------

The **-x** *db_args* option specifies the database specific arguments.

       Options supported for LDAP database are:

       **-x** nconns=<number_of_connections>
               Specifies the number of connections to be maintained per LDAP server.

       **-x** host=<ldapuri>
               Specifies the LDAP server to connect to by a LDAP URI.

       **-x** binddn=<binddn>
               Specifies the DN of the object used by the KDC server to bind to the LDAP server. This object should have the rights to read
               the realm container, principal container and the subtree that is referenced by the realm.

       **-x** bindpwd=<bind_password>
               Specifies the password for the above mentioned binddn. It is recommended not to use this option. Instead, the password can be
               stashed using the stashsrvpw command of kdb5_ldap_util.

The **-r** *realm* option specifies the realm for which the server should provide service.

The **-d** *dbname* option specifies the name under which the principal database can be found.
This option does not apply to the LDAP database.

The **-k** *keytype* option specifies the key type of the master key to be entered manually as a password when **-m** is given;  
the default is "des-cbc-crc".

The **-M** *mkeyname* option specifies the principal name for the master key in the database (usually "K/M" in the KDC's realm).

The **-m** option specifies that the master database password should be fetched from the keyboard rather than from a file on disk.

The **-n** option specifies that the KDC does not put itself in the background and does not disassociate itself from the terminal.  
In normal operation, you should always allow the KDC to place itself in the background.
       
The **-P** *pid_file* option tells the KDC to write its PID (followed by a newline) into *pid_file* after it starts up.  
This can be used to identify whether the KDC is still running and to allow init scripts to stop the correct process.

The **-p** *portnum* option specifies the default UDP port number which the KDC should listen on for Kerberos version 5 requests.  
This value is used when no port is specified in the KDC profile and when no port is specified in the Kerberos configuration file.  
If no value is available, then the value in */etc/services* for service "kerberos" is used.

The **-w** *numworkers* option tells the KDC to fork *numworkers* processes to listen to the KDC ports and process requests in parallel.  
The top level KDC process (whose pid is recorded in the pid file if the **-P** option is also given) acts as a supervisor.  
The supervisor will relay SIGHUP signals to the worker subprocesses, and will terminate the worker subprocess if the it is itself terminated or 
if any other worker process exits.  

.. note:: on operating systems which do not have *pktinfo* support, using worker processes will prevent the KDC from listening for UDP packets on network interfaces created after the KDC starts.


EXAMPLE

The KDC may service requests for multiple realms (maximum 32 realms).  
The realms are listed on the command line.  Per-realm options that can be specified on the command line pertain for each realm
that follows it and are superceded by subsequent definitions of the same option. 
For example::

       krb5kdc -p 2001 -r REALM1 -p 2002 -r REALM2 -r REALM3

specifies that the KDC listen on port 2001 for REALM1 and on port 2002 for REALM2 and REALM3.  
Additionally, per-realm parameters may be specified in the :ref:`kdc.conf` file.  
The location of this file may be specified by the *KRB5_KDC_PROFILE* environment variable.  
Parameters specified in this file take precedence over options specified on the command line.  
See the :ref:`kdc.conf` description for further details.

SEE ALSO
-----------

krb5(3), kdb5_util(8), kdc.conf(5), kdb5_ldap_util(8)


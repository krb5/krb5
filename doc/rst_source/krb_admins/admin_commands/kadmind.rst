.. _kadmind(8):

kadmind
=======

SYNOPSIS
--------

**kadmind**
[**-x** *db_args*]
[**-r** *realm*]
[**-m**]
[**-nofork**]
[**-port** *port-number*]
[**-P** *pid_file*]

DESCRIPTION
-----------

kadmind starts the Kerberos administration server.  kadmind typically
runs on the master Kerberos server, which stores the KDC database.  If
the KDC database uses the LDAP module, the administration server and
the KDC server need not run on the same machine.  kadmind accepts
remote requests from programs such as :ref:`kadmin(1)` and
:ref:`kpasswd(1)` to administer the information in these database.

kadmind requires a number of configuration files to be set up in order
for it to work:

:ref:`kdc.conf(5)`
    The KDC configuration file contains configuration information for
    the KDC and admin servers.  kadmind uses settings in this file to
    locate the Kerberos database, and is also affected by the
    **acl_file**, **dict_file**, **kadmind_port**, and iprop-related
    settings.

ACL file
    kadmind's ACL (access control list) tells it which principals are
    allowed to perform administration actions.  The pathname to the
    ACL file can be specified with the **acl_file** kdc.conf variable;
    by default, it is ``/usr/local/var/krb5kdc/kadm5.acl``.  The
    syntax of the ACL file is specified in the ACL FILE SYNTAX section
    below.

    If the kadmind ACL file is modified, the kadmind daemon needs to
    be restarted for changes to take effect.

After the server begins running, it puts itself in the background and
disassociates itself from its controlling terminal.

kadmind can be configured for incremental database propagation.
Incremental propagation allows slave KDC servers to receive principal
and policy updates incrementally instead of receiving full dumps of
the database.  This facility can be enabled in the :ref:`kdc.conf(5)`
file with the **iprop_enable** option.  Incremental propagation
requires the principal ``kiprop/MASTER\@REALM`` (where MASTER is the
master KDC's canonical host name, and REALM the realm name) to be
registered in the database.


OPTIONS
-------

**-r** *realm*
    specifies the realm that kadmind will serve; if it is not
    specified, the default realm of the host is used.

**-m**
    causes the master database password to be fetched from the
    keyboard (before the server puts itself in the background, if not
    invoked with the **-nofork** option) rather than from a file on
    disk.

**-nofork**
    causes the server to remain in the foreground and remain
    associated to the terminal.  In normal operation, you should allow
    the server to place itself in the background.

**-port** *port-number*
    specifies the port on which the administration server listens for
    connections.  The default port is determined by the
    **kadmind_port** configuration variable in :ref:`kdc.conf(5)`.

**-P** *pid_file*
    specifies the file to which the PID of kadmind process should be
    written after it starts up.  This file can be used to identify
    whether kadmind is still running and to allow init scripts to stop
    the correct process.

**-x** *db_args*
    specifies database-specific arguments.

    Options supported for LDAP database are:

        **-x nconns=**\ *number_of_connections*
            specifies the number of connections to be maintained per
            LDAP server.

        **-x host=**\ *ldapuri*
            specifies the LDAP server to connect to by URI.

        **-x binddn=**\ *binddn*
            specifies the DN of the object used by the administration
            server to bind to the LDAP server.  This object should
            have read and write privileges on the realm container, the
            principal container, and the subtree that is referenced by
            the realm.

        **-x bindpwd=**\ *bind_password*
            specifies the password for the above mentioned binddn.
            Using this option may expose the password to other users
            on the system via the process list; to avoid this, instead
            stash the password using the **stashsrvpw** command of
            :ref:`kdb5_ldap_util(8)`.


ACL FILE SYNTAX
---------------

The ACL file controls which principals can or cannot perform which
administrative functions.  For operations that affect principals, the
ACL file also controls which principals can operate on which other
principals.  Empty lines and lines starting with the sharp sign
(``#``) are ignored.  Lines containing ACL entries have the format:

 ::

    principal operation-mask [operation-target]

Ordering is important.  The first matching entry will control access
for an actor principal on a target principal.

*principal*
    may specify a partially or fully qualified Kerberos version 5
    principal name.  Each component of the name may be wildcarded
    using the ``*`` character.

*operation-target*
    [Optional] may specify a partially or fully qualified Kerberos
    version 5 principal name.  Each component of the name may be
    wildcarded using the ``*`` character.

*operation-mask*
    Specifies what operations may or may not be performed by a
    principal matching a particular entry.  This is a string of one or
    more of the following list of characters or their upper-case
    counterparts.  If the character is upper-case, then the operation
    is disallowed.  If the character is lower-case, then the operation
    is permitted.

    == ======================================================
    a  [Dis]allows the addition of principals or policies
    d  [Dis]allows the deletion of principals or policies
    m  [Dis]allows the modification of principals or policies
    c  [Dis]allows the changing of passwords for principals
    i  [Dis]allows inquiries about principals or policies
    l  [Dis]allows the listing of principals or policies
    p  [Dis]allows the propagation of the principal database
    x  Short for admcil.
    \* Same as x.
    == ======================================================

    Some examples of valid entries here are:

    ``user/instance@realm adm``
        A standard fully qualified name.  The *operation-mask* only
        applies to this principal and specifies that [s]he may add,
        delete, or modify principals and policies, but not change
        anybody else's password.

    ``user/instance@realm cim service/instance@realm``
        A standard fully qualified name and a standard fully qualified
        target.  The *operation-mask* only applies to this principal
        operating on this target and specifies that [s]he may change
        the target's password, request information about the target,
        and modify it.

    ``user/*@realm ac``
        A wildcarded name.  The *operation-mask* applies to all
        principals in realm ``realm`` whose first component is
        ``user`` and specifies that [s]he may add principals and
        change anybody's password.

    ``user/*@realm i */instance@realm``
        A wildcarded name and target.  The *operation-mask* applies to
        all principals in realm ``realm`` whose first component is
        ``user`` and specifies that [s]he may perform inquiries on
        principals whose second component is ``instance`` and realm is
        ``realm``.


SEE ALSO
--------

:ref:`kpasswd(1)`, :ref:`kadmin(1)`, :ref:`kdb5_util(8)`,
:ref:`kdb5_ldap_util(8)`

.. _kerberos(7):

kerberos
========

DESCRIPTION
-----------

The Kerberos system authenticates individual users in a network
environment.  After authenticating yourself to Kerberos, you can use
Kerberos-enabled programs without having to present passwords.

If you enter your username and :ref:`kinit(1)` responds with this
message:

kinit(v5): Client not found in Kerberos database while getting initial
credentials

you haven't been registered as a Kerberos user.  See your system
administrator.

A Kerberos name usually contains three parts.  The first is the
**primary**, which is usually a user's or service's name.  The second
is the **instance**, which in the case of a user is usually null.
Some users may have privileged instances, however, such as ``root`` or
``admin``.  In the case of a service, the instance is the fully
qualified name of the machine on which it runs; i.e. there can be an
rlogin service running on the machine ABC, which is different from the
rlogin service running on the machine XYZ.  The third part of a
Kerberos name is the **realm**.  The realm corresponds to the Kerberos
service providing authentication for the principal.

When writing a Kerberos name, the principal name is separated from the
instance (if not null) by a slash, and the realm (if not the local
realm) follows, preceded by an "@" sign.  The following are examples
of valid Kerberos names::

    david
    jennifer/admin
    joeuser@BLEEP.COM
    cbrown/root@FUBAR.ORG

When you authenticate yourself with Kerberos you get an initial
Kerberos **ticket**.  (A Kerberos ticket is an encrypted protocol
message that provides authentication.)  Kerberos uses this ticket for
network utilities such as rlogin and rcp.  The ticket transactions are
done transparently, so you don't have to worry about their management.

Note, however, that tickets expire.  Privileged tickets, such as those
with the instance ``root``, expire in a few minutes, while tickets
that carry more ordinary privileges may be good for several hours or a
day, depending on the installation's policy.  If your login session
extends beyond the time limit, you will have to re-authenticate
yourself to Kerberos to get new tickets.  Use the :ref:`kinit(1)`
command to re-authenticate yourself.

If you use the kinit command to get your tickets, make sure you use
the kdestroy command to destroy your tickets before you end your login
session.  You should put the kdestroy command in your ``.logout`` file
so that your tickets will be destroyed automatically when you logout.
For more information about the kinit and kdestroy commands, see the
:ref:`kinit(1)` and :ref:`kdestroy(1)` manual pages.

Kerberos tickets can be forwarded.  In order to forward tickets, you
must request **forwardable** tickets when you kinit.  Once you have
forwardable tickets, most Kerberos programs have a command line option
to forward them to the remote host.

ENVIRONMENT VARIABLES
---------------------

Several environment variables affect the operation of Kerberos-enabled
programs.  These inclide:

**KRB5CCNAME**
    Specifies the location of the credential cache, in the form
    *TYPE*:*residual*.  If no *type* prefix is present, the **FILE**
    type is assumed and *residual* is the pathname of the cache file.
    A collection of multiple caches may be used by specifying the
    **dir** type and the pathname of a private directory (which must
    already exist).  The default cache file is /tmp/krb5cc_*uid*,
    where *uid* is the decimal user ID of the user.

**KRB5_KTNAME**
    Specifies the location of the keytab file, in the form
    *TYPE*:*residual*.  If no *type* is present, the **FILE** type is
    assumed and *residual* is the pathname of the keytab file.  The
    default keytab file is ``/etc/krb5.keytab``.

**KRB5_CONFIG**
    Specifies the location of the Kerberos configuration file.  The
    default is ``/etc/krb5.conf``.

**KRB5_KDC_PROFILE**
    Specifies the location of the KDC configuration file, which
    contains additional configuration directives for the Key
    Distribution Center daemon and associated programs.  The default
    is ``/usr/local/var/krb5kdc/kdc.conf``.

**KRB5RCACHETYPE**
    Specifies the default type of replay cache to use for servers.
    Valid types include **dfl** for the normal file type and **none**
    for no replay cache.

**KRB5RCACHEDIR**
    Specifies the default directory for replay caches used by servers.
    The default is the value of the **TMPDIR** environment variable,
    or ``/var/tmp`` if **TMPDIR** is not set.

**KRB5_TRACE**
    Specifies a filename to write trace log output to.  Trace logs can
    help illuminate decisions made internally by the Kerberos
    libraries.  The default is not to write trace log output anywhere.

Most environment variables are disabled for certain programs, such as
login system programs and setuid programs, which are designed to be
secure when run within an untrusted process environment.

SEE ALSO
--------

:ref:`kdestroy(1)`, :ref:`kinit(1)`, :ref:`klist(1)`,
:ref:`kswitch(1)`, :ref:`kpasswd(1)`, :ref:`ksu(1)`,
:ref:`krb5.conf(5)`, :ref:`kdc.conf(5)`, :ref:`kadmin(1)`,
:ref:`kadmind(8)`, :ref:`kdb5_util(8)`, :ref:`krb5kdc(8)`

BUGS
----

AUTHORS
-------

| Steve Miller, MIT Project Athena/Digital Equipment Corporation
| Clifford Neuman, MIT Project Athena
| Greg Hudson, MIT Kerberos Consortium

HISTORY
-------

The MIT Kerberos 5 implementation was developed at MIT, with
contributions from many outside parties.  It is currently maintained
by the MIT Kerberos Consortium.

RESTRICTIONS
------------

Copyright 1985, 1986, 1989-1996, 2002, 2011 Masachusetts Institute of
Technology

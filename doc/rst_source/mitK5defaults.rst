.. _mitK5defaults:

MIT Kerberos defaults
=====================

General defaults
----------------

==========================  =============================  ====================
Description                 Default                        Environment
==========================  =============================  ====================
Keytab file                 ``FILE:``\ |keytab|            **KRB5_KTNAME**
Kerberos config file        |krb5conf|\ ``:``\             **KRB5_CONFIG**
                            |sysconfdir|\ ``/krb5.conf``
KDC config file             |kdcdir|\ ``/kdc.conf``        **KRB5_KDC_PROFILE**
KDC database path (DB2)     |kdcdir|\ ``/principal``
Master key stash file       |kdcdir|\ ``/.k5.``\ *realm*
Admin server ACL file       |kdcdir|\ ``/kadm5.acl``
Plugin base directory       |libdir|\ ``/krb5/plugins``
Replay cache directory      ``/var/tmp``                   **KRB5RCACHEDIR**
Master key default enctype  |defmkey|
Supported enc/salt types    |defkeysalts|
Permitted enctypes          |defetypes|
KDC default port            88
Second KDC default port     750
Admin server port           749
Password change port        464
==========================  =============================  ====================


Slave KDC propagation defaults
------------------------------

This table shows defaults used by the :ref:`kprop(8)` and
:ref:`kpropd(8)` programs.

==========================  ==============================  ===========
Description                 Default                         Environment
==========================  ==============================  ===========
kprop database dump file    |kdcdir|\ ``/slave_datatrans``
kpropd temporary dump file  |kdcdir|\ ``/from_master``
kdb5_util location          |sbindir|\ ``/kdb5_util``
kprop location              |sbindir|\ ``/kprop``
kpropd ACL file             |kdcdir|\ ``/kpropd.acl``
kprop port                  754                             KPROP_PORT
==========================  ==============================  ===========


.. _paths:

Default paths for Unix-like systems
-----------------------------------

On Unix-like systems, some paths used by MIT krb5 depend on parameters
chosen at build time.  For a custom build, these paths default to
subdirectories of ``/usr/local``.  When MIT krb5 is integrated into an
operating system, the paths are generally chosen to match the
operating system's filesystem layout.

=======================  ===============  ===================  ===============
Description	         Symbolic name    Custom build path    Typical OS path
=======================  ===============  ===================  ===============
User programs	         BINDIR           ``/usr/local/bin``   ``/usr/bin``
Libraries and plugins    LIBDIR           ``/usr/local/lib``   ``/usr/lib``
Parent of KDC state dir  LOCALSTATEDIR    ``/usr/local/var``   ``/var``
Administrative programs  SBINDIR          ``/usr/local/sbin``  ``/usr/sbin``
Alternate krb5.conf dir  SYSCONFDIR       ``/usr/local/etc``   ``/etc``
=======================  ===============  ===================  ===============

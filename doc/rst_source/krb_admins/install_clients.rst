Installing and configuring UNIX client machines
===============================================

The Kerberized client programs are :ref:`kinit(1)`, :ref:`klist(1)`,
:ref:`kdestroy(1)`, :ref:`kpasswd(1)`, and :ref:`ksu(1)`.  All of
these programs are in the directory ``/usr/local/bin``.  MIT
recommends that you use login.krb5 in place of ``/bin/login`` to give
your users a single-sign-on system. You will need to make sure your
users know to use their Kerberos passwords when they log in.

You will also need to educate your users to use the ticket management
programs kinit, klist, kdestroy, and to use the Kerberos programs ksu
and kpasswd in place of their non-Kerberos counterparts su and passwd.


Client machine configuration files
----------------------------------

Each machine running Kerberos must have a :ref:`krb5.conf(5)` file.

Also, for most UNIX systems, you must add the appropriate Kerberos
services to each client machine's ``/etc/services`` file.  If you are
using the default configuration for Kerberos V5, you should be able to
just insert the following code::

    kerberos      88/udp    kdc    # Kerberos V5 KDC
    kerberos      88/tcp    kdc    # Kerberos V5 KDC
    kerberos-adm  749/tcp          # Kerberos 5 admin/changepw
    kerberos-adm  749/udp          # Kerberos 5 admin/changepw
    krb5_prop     754/tcp          # Kerberos slave propagation
    krb524        4444/tcp         # Kerberos 5 to 4 ticket translator


Mac OS X configuration
----------------------

To install Kerberos V5 on Mac OS X and Mac OS X Server, follow the
directions for generic Unix-based OS's, except for the
``/etc/services`` updates described above.

Mac OS X and Mac OS X Server use a database called NetInfo to store
the contents of files normally found in ``/etc``.  Instead of
modifying ``/etc/services``, you should run the following commands to
add the Kerberos service entries to NetInfo::

    $ niutil -create . /services/kerberos
    $ niutil -createprop . /services/kerberos name kerberos kdc
    $ niutil -createprop . /services/kerberos port 750
    $ niutil -createprop . /services/kerberos protocol tcp udp
    $ niutil -create . /services/krbupdate
    $ niutil -createprop . /services/krbupdate name krbupdate kreg
    $ niutil -createprop . /services/krbupdate port 760
    $ niutil -createprop . /services/krbupdate protocol tcp
    $ niutil -create . /services/kpasswd
    $ niutil -createprop . /services/kpasswd name kpasswd kpwd
    $ niutil -createprop . /services/kpasswd port 761
    $ niutil -createprop . /services/kpasswd protocol tcp
    $ niutil -create . /services/klogin
    $ niutil -createprop . /services/klogin port 543
    $ niutil -createprop . /services/klogin protocol tcp
    $ niutil -create . /services/eklogin
    $ niutil -createprop . /services/eklogin port 2105
    $ niutil -createprop . /services/eklogin protocol tcp
    $ niutil -create . /services/kshell
    $ niutil -createprop . /services/kshell name kshell krcmd
    $ niutil -createprop . /services/kshell port 544
    $ niutil -createprop . /services/kshell protocol tcp

In addition to adding services to NetInfo, you must also modify the
resolver configuration in NetInfo so that the machine resolves its own
hostname as a FQDN (fully qualified domain name).  By default, Mac OS
X and Mac OS X Server machines query NetInfo to resolve hostnames
before falling back to DNS.  Because NetInfo has an unqualified name
for all the machines in the NetInfo database, the machine's own
hostname will resolve to an unqualified name.  Kerberos needs a FQDN
to look up keys in the machine's keytab file.

Fortunately, you can change the lookupd caching order to query DNS
first.  Run the following NetInfo commands and reboot the machine::

    $ niutil -create . /locations/lookupd/hosts
    $ niutil -createprop . /locations/lookupd/hosts LookupOrder CacheAgent DNSAgent NIAgent NILAgent

Once you have rebooted, you can verify that the resolver now behaves
correctly.  Compile the Kerberos 5 distribution and run::

    $ cd .../src/tests/resolve
    $ ./resolve

This will tell you whether or not your machine returns FQDNs on name
lookups.  If the test still fails, you can also try turning off DNS
caching.  Run the following commands and reboot::

    $ niutil -create . /locations/lookupd/hosts
    $ niutil -createprop . /locations/lookupd/hosts LookupOrder DNSAgent CacheAgent NIAgent NILAgent

The remainder of the setup of a Mac OS X client machine or application
server should be the same as for other UNIX-based systems.


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___cl_install

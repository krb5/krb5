.. _slave_host_key:

Setting up slave KDCs
=====================

Prep work on the master side
----------------------------

Each KDC needs a ``host`` key in the Kerberos database.  These keys
are used for mutual authentication when propagating the database dump
file from the master KDC to the secondary KDC servers.

On the master KDC, connect to administrative interface and create the
host principal for each of the KDCs' ``host`` services.  For example,
if the master KDC were called ``kerberos.mit.edu``, and you had a
slave KDC named ``kerberos-1.mit.edu``, you would type the following::

    shell% /usr/local/bin/kadmin
    kadmin: addprinc -randkey host/kerberos.mit.edu
    NOTICE: no policy specified for "host/kerberos.mit.edu@ATHENA.MIT.EDU"; assigning "default"
    Principal "host/kerberos.mit.edu@ATHENA.MIT.EDU" created.

    kadmin: addprinc -randkey host/kerberos-1.mit.edu
    NOTICE: no policy specified for "host/kerberos-1.mit.edu@ATHENA.MIT.EDU"; assigning "default"
    Principal "host/kerberos-1.mit.edu@ATHENA.MIT.EDU" created.

It is not strictly necessary to have the master KDC server in the
Kerberos database, but it can be handy if you want to be able to swap
the master KDC with one of the slaves.

Next, extract ``host`` random keys for all participating KDCs and
store them in each host's default keytab file.  Ideally, you should
extract each keytab locally on its own KDC.  If this is not feasible,
you should use an encrypted session to send them across the network.
To extract a keytab on a slave KDC called ``kerberos-1.mit.edu``, you
would execute the following command::

    kadmin: ktadd host/kerberos-1.mit.edu
    Entry for principal host/kerberos-1.mit.edu with kvno 2, encryption
        type aes256-cts-hmac-sha1-96 added to keytab FILE:/etc/krb5.keytab.
    Entry for principal host/kerberos-1.mit.edu with kvno 2, encryption
        type aes128-cts-hmac-sha1-96 added to keytab FILE:/etc/krb5.keytab.
    Entry for principal host/kerberos-1.mit.edu with kvno 2, encryption
        type des3-cbc-sha1 added to keytab FILE:/etc/krb5.keytab.
    Entry for principal host/kerberos-1.mit.edu with kvno 2, encryption
        type arcfour-hmac added to keytab FILE:/etc/krb5.keytab.


Configuring the slave
---------------------

Database propagation copies the contents of the master's database, but
does not propagate configuration files, stash files, or the kadm5 ACL
file.  The following files must be copied by hand to each slave (see
:ref:`mitK5defaults` for the default locations for these files):

* krb5.conf
* kdc.conf
* kadm5.acl
* master key stash file

Move the copied files into their appropriate directories, exactly as
on the master KDC.  kadm5.acl is only needed to allow a slave to swap
with the master KDC.

The database is propagated from the master KDC to the slave KDCs via
the :ref:`kpropd(8)` daemon.  You must explicitly specify the
principals which are allowed to provide Kerberos dump updates on the
slave machine with a new database.  Create a file named kpropd.acl in
the KDC state directory containing the ``host`` principals for each of
the KDCs:

    host/kerberos.mit.edu@ATHENA.MIT.EDU
    host/kerberos-1.mit.edu@ATHENA.MIT.EDU

.. note:: If you expect that the master and slave KDCs will be
          switched at some point of time, list the host principals
          from all participating KDC servers in kpropd.acl files on
          all of the KDCs.  Otherwise, you only need to list the
          master KDC's host principal in the kpropd.acl files of the
          slave KDCs.

Then, add the following line to ``/etc/inetd.conf`` on each KDC
(Adjust the path to kpropd)::

    krb5_prop stream tcp nowait root /usr/local/sbin/kpropd kpropd

You also need to add the following line to ``/etc/services`` on each
KDC, if it is not already present (assuming that the default port is
used)::

    krb5_prop       754/tcp               # Kerberos slave propagation

Restart inetd daemon.

Alternatively, start :ref:`kpropd(8)` as a stand-alone daemon with
``kpropd -S``.

Now that the slave KDC is able to accept database propagation, you’ll
need to propagate the database from the master server.

NOTE: Do not start the slave KDC yet; you still do not have a copy of
the master's database.


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc

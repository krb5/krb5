.. _kprop_to_slaves:

Propagate the database to each slave KDC
========================================

First, create a dump file of the database on the master KDC, as
follows::

    shell% /usr/local/sbin/kdb5_util dump /usr/local/var/krb5kdc/slave_datatrans

Then, manually propagate the database to each slave KDC, as in the
following example::

    shell% /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans kerberos-1.mit.edu

    Database propagation to kerberos-1.mit.edu: SUCCEEDED

You will need a script to dump and propagate the database. The
following is an example of a Bourne shell script that will do this.

.. note:: Remember that you need to replace ``/usr/local/var/krb5kdc``
          with the name of the KDC state directory.

::

    #!/bin/sh

    kdclist = "kerberos-1.mit.edu kerberos-2.mit.edu"

    /usr/local/sbin/kdb5_util dump /usr/local/var/krb5kdc/slave_datatrans

    for kdc in $kdclist
    do
        /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans $kdc
    done

You will need to set up a cron job to run this script at the intervals
you decided on earlier (see :ref:`db_prop`).

Now that the slave KDC has a copy of the Kerberos database, you can
start the krb5kdc daemon::

    shell% /usr/local/sbin/krb5kdc

As with the master KDC, you will probably want to add this command to
the KDCs' ``/etc/rc`` or ``/etc/inittab`` files, so they will start
the krb5kdc daemon automatically at boot time.


Propagation failed?
-------------------

.. _prop_failed_start:

.. error:: kprop: No route to host while connecting to server

Make sure that the hostname of the slave (as given to kprop) is
correct, and that any firewalls beween the master and the slave allow
a connection on port 754.

.. error:: kprop: Connection refused in call to connect while opening
           connection

If the slave is intended to run kpropd out of inetd, make sure that
inetd is configured to accept krb5_prop connections.  inetd may need
to be restarted or sent a SIGHUP to recognize the new configuration.
If the slave is intended to run kpropd in standalone mode, make sure
that it is running.

.. error:: kprop: Server rejected authentication while authenticating
           to server

Make sure that:

#. The time is syncronized between the master and slave KDCs.
#. The master stash file was copied from the master to the expected
   location on the slave.
#. The slave has a keytab file in the default location containing a
   ``host`` principal for the slave's hostname.

.. _prop_failed_end:


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc

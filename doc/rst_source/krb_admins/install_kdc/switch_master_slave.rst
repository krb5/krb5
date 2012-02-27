.. _switch_master_slave:

Switching Master and Slave KDCs
===============================

You may occasionally want to use one of your slave KDCs as the master.
This might happen if you are upgrading the master KDC, or if your
master KDC has a disk crash.

Assuming you have configured all of your KDCs to be able to function
as either the master KDC or a slave KDC (as this document recommends),
all you need to do to make the changeover is:

If the master KDC is still running, do the following on the *old*
master KDC:

#. Kill the kadmind process.
#. Disable the cron job that propagates the database.
#. Run your database propagation script manually, to ensure that the
   slaves all have the latest copy of the database (see
   :ref:`kprop_to_slaves`).

On the *new* master KDC:

#. Start the :ref:`kadmind(8)` daemon (see :ref:`start_kdc_daemons`).
#. Set up the cron job to propagate the database (see
   :ref:`kprop_to_slaves`).
#. Switch the CNAMEs of the old and new master KDCs.  If you can't do
   this, you'll need to change the :ref:`krb5.conf(5)` file on every
   client machine in your Kerberos realm.


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc

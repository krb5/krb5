.. _switch_master_slave:

Switching Master and Slave KDCs
=========================================

You may occasionally want to use one of your slave KDCs as the master. This might happen if you are upgrading the master KDC, or if your master KDC has a disk crash.

Assuming you have configured all of your KDCs to be able to function as either the master KDC or a slave KDC (as this document recommends), all you need to do to make the changeover is:

If the master KDC is still running, do the following on the *old* master KDC:

#. Kill the kadmind process.
#. Disable the cron job that propagates the database.
#. Run your database propagation script manually, to ensure that the slaves all have the latest copy of the database. (See Propagate the Database to Each Slave KDC.) If there is a need to preserve per-principal policy information from the database, you should do a "kdb5_util dump -ov" in order to preserve that information and propogate that dump file securely by some means to the slave so that its database has the correct state of the per-principal policy information. 

On the *new* master KDC:

#. Create a database keytab. (See Create a kadmind Keytab (optional).)
#. Start the kadmind daemon. (See Start the Kerberos Daemons.)
#. Set up the cron job to propagate the database. (See Propagate the Database to Each Slave KDC.)
#. Switch the CNAMEs of the old and new master KDCs. (If you don't do this, you'll need to change the krb5.conf file on every client machine in your Kerberos realm.) 


------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


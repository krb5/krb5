Propagate the database to each Slave KDC
===========================================

First, create a dump of the database on the master KDC, as follows::

     shell% /usr/local/sbin/kdb5_util dump /usr/local/var/krb5kdc/slave_datatrans
     shell%
     

Next, you need to manually propagate the database to each slave KDC, as in the following example. (The lines beginning with => are continuations of the previous line.)::

     /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans
     => kerberos-1.mit.edu
     /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans
     => kerberos-2.mit.edu
     

You will need a script to dump and propagate the database. The following is an example of a bourne shell script that will do this. (Note that the line that begins with => is a continuation of the previous line.) 

.. note:: Remember that you need to replace */usr/local* with the name of the directory in which you installed Kerberos V5.

::

     #!/bin/sh
     
     kdclist = "kerberos-1.mit.edu kerberos-2.mit.edu"
     
     /usr/local/sbin/kdb5_util "dump
     => /usr/local/var/krb5kdc/slave_datatrans"
     
     for kdc in $kdclist
     do
     /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans $kdc
     done
     

You will need to set up a cron job to run this script at the intervals you decided on earlier (See :ref:`db_prop_label` and :ref:`incr_db_prop_label`.) 

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


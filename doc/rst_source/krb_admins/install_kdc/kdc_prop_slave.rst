Propagate the database to each slave KDC
===========================================

First, create a dump of the database on the master KDC, as follows::

     shell% /usr/local/sbin/kdb5_util dump /usr/local/var/krb5kdc/slave_datatrans
     shell%
     

Next, you need to manually propagate the database to each slave KDC, as in the following example::

     shell% /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans kerberos-1.mit.edu
     Database propagation to kerberos-1.mit.edu: SUCCEEDED

     shell% /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans kerberos-2.mit.edu
     Database propagation to kerberos-2.mit.edu: SUCCEEDED
     

You will need a script to dump and propagate the database. The following is an example of a bourne shell script that will do this. 

.. note:: Remember that you need to replace */usr/local* with the name of the directory in which you installed Kerberos V5.

::

     #!/bin/sh
     
     kdclist = "kerberos-1.mit.edu kerberos-2.mit.edu"
     
     /usr/local/sbin/kdb5_util "dump /usr/local/var/krb5kdc/slave_datatrans"
     
     for kdc in $kdclist
     do
     /usr/local/sbin/kprop -f /usr/local/var/krb5kdc/slave_datatrans $kdc
     done
     

You will need to set up a cron job to run this script at the intervals you decided on earlier (See :ref:`db_prop_label` and :ref:`incr_db_prop_label`.) 
The dump can also be used as a save file. 
Once the operation succeeded, connect to slaves and start thier KDCs.



Propagation failed?
------------------------


If propagation failed with a loud::
   
     kprop: Connection refused in call to connect while opening connection

it means that *kprop* did not manage to contact *kpropd* on the remote slave KDC.

This will occur if you set restrictive access rules with a firewall, or if *kpropd* did not start upon connection.

The propagation is done through a tcp stream on port 754. Usually, *kpropd* is not a daemon running on its own: 
it is started by *inetd* (or its equivalent *xinetd*). However, many systems do not register *kpropd* as a service in their *inetd* database.

You can launch *kpropd* by two different means: either by starting it during boot up with the **-S** argument (see :ref:`kpropd(8)` for details), 
or register *kprop* as a potential services to *inetd*.

To register *kpropd*, it depends on whether your are using inetd or its more sophisticated equivalent *xinetd*.
First, edit */etc/services*, and look for *kprop* service; the line should look like this::

   /etc/services

   kprop 754/tcp

If you did not find it, please add it to the bottom of the file. Save and close.


inetd.conf
~~~~~~~~~~~~~~~

Now we should edit *inetd.conf* (see below for *xinetd*), and add this line::

    /etc/inetd.conf

    kprop stream tcp nowait root /usr/sbin/kpropd kpropd

Please note that the path to executable may vary from one system to another. Save and close *inetd.conf*, and restart *inetd*::


    # /etc/rc.d/inetd restart

xinetd.conf
~~~~~~~~~~~~~~~~~

All config file for *xinetd* resides in the */etc/xinetd.d* directory. We must add the *kprop* config file, so that *xinetd* knows its existence::

Create and edit the *kpropd* file */etc/xinetd.d/kpropd* ::

    /etc/xinetd.d/kpropd

    service kprop
    {
    socket_type = stream
    wait = no
    user = root
    server = /usr/sbin/kpropd
    only_from = 0.0.0.0 # Allow anybody to connect to it. Restrictions may apply here.
    log_on_success = PID HOST EXIT DURATION
    log_on_failure = PID HOST
    }

Save and close the file, and restart *xinetd*::

    # /etc/init.d/xinetd restart

You should now be able to propagate the dumps from master to slave.




------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


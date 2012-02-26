Start the Kerberos daemons on the master KDC
===============================================

At this point, you are ready to start the Kerberos KDC
(:ref:`krb5kdc(8)`) and administrative daemons on the Master KDC. To
do so, type::

    shell% /usr/local/sbin/krb5kdc
    shell% /usr/local/sbin/kadmind

Each server daemon will fork and run in the background.

.. note:: Assuming you want these daemons to start up automatically at
          boot time, you can add them to the KDC's ``/etc/rc`` or
          ``/etc/inittab`` file.  You need to have a
          :ref:`stash_definition` in order to do this.

You can verify that they started properly by checking for their
startup messages in the logging locations you defined in
krb5.conf. (See :ref:`logging`).  For example::

    shell% tail /var/log/krb5kdc.log
    Dec 02 12:35:47 beeblebrox krb5kdc[3187](info): commencing operation
    shell% tail /var/log/kadmin.log
    Dec 02 12:35:52 beeblebrox kadmind[3189](info): starting

Any errors the daemons encounter while starting will also be listed in
the logging output.

As an additional verification, check if kinit succeeds against the
principals that you have created on the previous step
(:ref:`addadmin_kdb`). Run::

    shell% /usr/local/bin/kinit admin/admin@ATHENA.MIT.EDU

You are now ready to start configuring the slave KDCs.

.. note:: Assuming you are setting the KDCs up so that you can easily
          switch the master KDC with one of the slaves, you should
          perform each of these steps on the master KDC as well as the
          slave KDCs, unless these instructions specify otherwise.


Feedback
--------

Please, provide your feedback or suggest a new topic at
krb5-bugs@mit.edu?subject=Documentation___install_kdc

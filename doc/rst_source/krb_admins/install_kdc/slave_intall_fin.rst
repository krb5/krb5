Create stash files on the Slave KDCs
======================================

Create stash files, by issuing the following commands on each slave KDC::

     shell% kdb5_util stash
     kdb5_util: Cannot find/read stored master key while reading master key
     kdb5_util: Warning: proceeding without master key
     Enter KDC database master key:  <= Enter the database master key.
     shell%
     

As mentioned above, the stash file is necessary for your KDCs to be able authenticate to themselves, such as when they reboot. You could run your KDCs without stash files, but you would then need to type in the Kerberos database master key by hand every time you start a KDC daemon.

Start the *krb5kdc* daemon on each KDC
=========================================

The final step in configuing your slave KDCs is to run the KDC daemon::

     shell% /usr/local/sbin/krb5kdc
     

As with the master KDC, you will probably want to add this command to the KDCs' */etc/rc* or */etc/inittab* files, so they will start the *krb5kdc* daemon automatically at boot time. 

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___install_kdc


Changing the *krbtgt* key
=============================

A Kerberos Ticket Granting Ticket (TGT) is a service ticket for the principal *krbtgt\/REALM*. The key for this principal is created when the Kerberos database is initialized and need not be changed. However, it will only have the encryption types supported by the KDC at the time of the initial database creation. To allow use of newer encryption types for the TGT, this key has to be changed.


Changing this key using the normal kadmin *change_password* command would invalidate any previously issued TGTs. Therefore, when changing this key, normally one should use the *-keepold* flag to change_password to retain the previous key in the database as well as the new key. For example::

     kadmin: change_password -randkey -keepold krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     

.. warning:: After issuing this command, the old key is still valid and is still vulnerable to (for instance) brute force attacks. To completely retire an old key or encryption type, run the *purgekeys* command to delete keys with older kvnos, ideally first making sure that all tickets issued with the old keys have expired. 


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db


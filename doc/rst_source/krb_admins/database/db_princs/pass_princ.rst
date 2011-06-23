Changing passwords
============================

To change a principal's password use the kadmin change_password command, which requires the "modify" administrative privilege (unless the principal is changing his/her own password). The syntax is::

     change_password [options] principal
     
The *change_password* option has the alias cpw. *change_password* takes the following options

========================= ============================================================
 -randkey                  Sets the key of the principal to a random value. 
 -pw *password*              Sets the password to the string password. MIT does not recommend using this option. 
 -e *enc:salt...*          Uses the specified list of enctype-salttype pairs for setting the key of the principal. The quotes are necessary if there are multiple enctype-salttype pairs. This will not function against kadmin daemons earlier than krb5-1.2. See :ref:`senct_label` and :ref:`salts_label` for possible values. 
 -keepold                  Keeps the previous kvno's keys around. This flag is usually not necessary except perhaps for TGS keys. Don't use this flag unless you know what you're doing. This option is not supported for the LDAP database
========================= ============================================================


For example::

     kadmin: cpw david
     Enter password for principal david@ATHENA.MIT.EDU:  <= Type the new password.
     Re-enter password for principal david@ATHENA.MIT.EDU:  <= Type it again.
     Password for david@ATHENA.MIT.EDU changed.
     kadmin:
     
.. note::  *change_password* will not let you change the password to one that is in the principal's password history.


------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_princs



Differences between Heimdal and MIT Kerberos API
==================================================================================

.. note:: :c:func:`krb5_auth_con_getaddrs()`

Heimdal: If either of the pointers to local_addr and remote_addr is not NULL,
         it is freed first and then reallocated before being populated with
         the content of corresponding address from authentication context.

.. note:: :c:func:`krb5_auth_con_setaddrs()`

Heimdal: If either address is NULL, the previous address remains in place 

.. note:: :c:func:`krb5_auth_con_setports()`

Heimdal: Not implemented as of version 1.3.3

.. note:: :c:func:`krb5_auth_con_setrecvsubkey()`

Heimdal: If either port is NULL, the previous port remains in place 

.. note:: :c:func:`krb5_auth_con_setsendsubkey()`

Heimdal: Not implemented as of version 1.3.3

.. note:: :c:func:`krb5_cc_set_config()`

MIT: Before version 1.10 it was assumed that the last arguments *data* is ALWAYS non-zero.

.. note:: :c:func:`krb5_cccol_last_change_time ()`

Prototype difference.

Heimdal takes three arguments:

   |   krb5_context context,
   |   const char type,
   |   krb5_timestamp \* change_time

MIT takes two arguments: 

   |   krb5_context context, 
   |   krb5_timestamp * change_time 

.. note:: :c:func:`krb5_set_default_realm()`

Heimdal: Caches the computed default realm context field.
         If the second argument is NULL, it tries to retrieve it from libdefaults or DNS.

MIT: Computes the default realm each time if it wasn't explicitly set in the context

..

------------------

Feedback


Please, provide your feedback on this document at krb5-bugs@mit.edu?subject=Documentation___h5lMITdiff
 


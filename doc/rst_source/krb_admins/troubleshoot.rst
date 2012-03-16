Troubleshooting
===============

List
----

.. error:: KDC has no support for encryption type while getting
           initial credentials

.. error:: credential verification failed: KDC has no support for
           encryption type

This most commonly happens when trying to use a principal with only
DES keys, in a release (MIT krb5 1.7 or later) which disables DES by
default.  DES encryption is considered weak due to its inadequate key
size.  If you cannot migrate away from its use, you can re-enable DES
by adding ``allow_weak_crypto = true`` to the :ref:`libdefaults`
section of :ref:`krb5.conf(5)`.

Seen in: clients

----

.. include:: ./install_kdc.rst
   :start-after:  _prop_failed_start:
   :end-before: _prop_failed_end:

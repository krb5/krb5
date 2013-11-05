Troubleshooting
===============

.. _trace_logging:

Trace logging
-------------

Most programs using MIT krb5 1.9 or later can be made to provide
information about internal krb5 library operations using trace
logging.  To enable this, set the **KRB5_TRACE** environment variable
to a filename before running the program.  On many operating systems,
the filename ``/dev/stdout`` can be used to send trace logging output
to standard output.

Some programs do not honor **KRB5_TRACE**, either because they use
secure library contexts (this generally applies to setuid programs and
parts of the login system) or because they take direct control of the
trace logging system using the API.

Here is a short example showing trace logging output for an invocation
of the :ref:`kvno(1)` command::

    shell% env KRB5_TRACE=/dev/stdout kvno krbtgt/KRBTEST.COM
    [9138] 1332348778.823276: Getting credentials user@KRBTEST.COM ->
        krbtgt/KRBTEST.COM@KRBTEST.COM using ccache
        FILE:/me/krb5/build/testdir/ccache
    [9138] 1332348778.823381: Retrieving user@KRBTEST.COM ->
        krbtgt/KRBTEST.COM@KRBTEST.COM from
        FILE:/me/krb5/build/testdir/ccache with result: 0/Unknown code 0
    krbtgt/KRBTEST.COM@KRBTEST.COM: kvno = 1

List
----

.. error::

           KDC has no support for encryption type while getting
           initial credentials

.. error::

           credential verification failed: KDC has no support for
           encryption type

This most commonly happens when trying to use a principal with only
DES keys, in a release (MIT krb5 1.7 or later) which disables DES by
default.  DES encryption is considered weak due to its inadequate key
size.  If you cannot migrate away from its use, you can re-enable DES
by adding ``allow_weak_crypto = true`` to the :ref:`libdefaults`
section of :ref:`krb5.conf(5)`.

Seen in: clients

.. error::

    Cannot create cert chain: certificate has expired

This error message indicates that PKINIT authentication failed because
the client certificate, KDC certificate, or one of the certificates in
the signing chain above them has expired.

If the KDC certificate has expired, this message appears in the KDC
log file, and the client will receive a "Preauthentication failed"
error.  (Prior to release 1.11, the KDC log file message erroneously
appears as "Out of memory".  Prior to release 1.12, the client will
receive a "Generic error".)

If the client or a signing certificate has expired, this message may
appear in trace_logging_ output from :ref:`kinit(1)` or, starting in
release 1.12, as an error message from kinit or another program which
gets initial tickets.  The error message is more likely to appear
properly on the client if the principal entry has no long-term keys.

----

.. include:: ./install_kdc.rst
   :start-after:  _prop_failed_start:
   :end-before: _prop_failed_end:

.. _retiring-des:

Retiring DES
=======================

Version 5 of the Kerberos protocol was originally implemented using
the Data Encryption Standard (DES) as a block cipher for encryption.
While it was considered secure at the time, advancements in computational
ability have rendered it vulnerable to brute force attacks on its 56-bit
keyspace.  As such, it is now considered insecure and should not be
used (:rfc:`6649`).

History
-------

DES was used in the original Kerberos implementation, and was the
only cryptosystem in krb5 1.0.  Partial support for triple-DES (3DES) was
added in version 1.1, with full support following in version 1.2.
The Advanced Encryption Standard (AES), which supersedes DES, gained
partial support in version 1.3.0 of krb5 and full support in version 1.3.2.
However, deployments of krb5 using Kerberos databases created with older
versions of krb5 will not necessarily start using strong crypto for
ordinary operation without administrator intervention.

Types of keys
-------------

The entire Kerberos database is encrypted using the database master
key, presently stored as ``K/M`` by default.  Each entry in the
Kerberos database has a set of keys with different encryption types,
corresponding to that principal's current key version number.
For a user principal, these keys are derived from the user's password
via the various string2key functions for those encryption types;
for a service principal with keys stored in a keytab, the keys of
different encryption types are all stored in the keytab.
When a new principal is added or a principal's key is updated (for
example, due to a user password change), new keys are generated for
that principal with all of the different encryption types that the
KDC is configured to use (the **supported_enctypes** variable in kdc.conf).
This list can be overridden on a case-by-case basis using arguments
to :ref:`kadmin(1)`.

When a Kerberos client initiates a Kerberos transaction, the client
requests a service ticket for a given service from the KDC; this service
ticket will contain only a single key, of a particular encryption type.
When sending its request to the KDC, the client can request a particular
list of encryption types, as controlled by the client machine's
:ref:`krb5.conf(5)` configuration file or specific API calls in the
client software.
To choose the encryption type for the service ticket's key, the KDC
must accomodate the client's preference and also confirm that the service
principal has a key in the Kerberos database of that encryption type.
Note that the encryption types supported by the krb5 installation on
the server that will receive the service ticket is not a factor in
the KDC's choice of encryption type; this information is not available
in the Kerberos protocol.  In order to allow uninterrupted operation to
clients while migrating away from DES, care must be taken to ensure that
the krb5 installation on server machines is configured to support newer
encryption types before keys of those new encryption types are created
in the Kerberos database for those server principals.

Upgrade procedure
-----------------

This procedure assumes that the KDC software has already been upgraded
to a modern version of krb5 that supports non-DES keys, so that the
only remaining task is to update the actual keys used to service requests.

While it is possible to upgrade individual service principals to non-DES
keys before transitioning the entire realm, it is probably best to
start with upgrading the key for the ticket-granting service principal,
``krbtgt/REALM``.  Since the server that will handle service tickets
for this principal is the KDC itself, it is easy to guarantee that it
will be configured to support any encryption types which might be
selected.  However, just creating a new key version (and new keys) for
that principal will invalidate all existing tickets issued against that
principal, which in practice means all tickets obtained by clients.
Instead, a new key can be created with the old key retained, so that
existing tickets will still function until their scheduled expiry
(see :ref:`changing_krbtgt_key`).

Once the krbtgt key is updated, users will get non-DES (usually AES in
modern releases) session keys for their TGT, but subsequent requests
for service tickets will still get DES keys, because the database
entry for the service principal still only has DES keys.  Application service
remains uninterrupted due to the key-selection procedure on the KDC.

At this point, service administrators can update their services and the
servers behind them.  If necessary, the krb5 installation should be
upgraded to a version supporting non-DES keys, and :ref:`krb5.conf(5)`
edited so that the default enctype list includes the additional enctypes
needed.  Only when the service is configured to accept non-DES keys should
the key version number be incremented and new keys generated.
Until the KDC's configuration is changed to generate non-DES keys by
default, it is necessary to use :ref:`kadmin(1)` to produce new keys
with the desired enctypes; the ``-keepold`` functionality may also be
desired in some cases.  When a single service principal is shared by
multiple backend servers in a load-balanced environment, it may be
necessary to schedule downtime or adjust the population in the load-balanced
pool in order to propagate the updated keytab to all hosts in the pool
with minimal service interruption.

Once the high-visibility services have been rekeyed, it is probably
appropriate to change :ref:`kdc.conf(5)` to generate keys with the new
encryption types by default.  This enables server administrators to generate
new keys with :ref:`k5srvutil(1)` ``change``, and causes user password
changes to add new encryption types for their entries.  It will probably
be necessary to implement administrative controls to cause all user
principal keys to be updated in a reasonable period of time, whether
by forcing password changes or a password synchronization service that
has access to the current password and can add the new keys.

Once all principals have been re-keyed, DES support can be disabled on the
KDC, and client machines can remove **allow_weak_crypto = true** from
their :ref:`krb5.conf(5)` configuration files, completing the migration.
For completeness, the kadmin **purgekeys** command should be used to
remove the old keylist for ``krbtgt/REALM`` which includes the single-DES
key(s), though the KDC will only issue new tickets using the highest
available kvno, which at this point does not have single-DES keys available.

This procedure does not alter ``K/M@REALM``, the key used to encrypt the
Kerberos database itself.  (This is the key stored in the stash file
on the KDC if stash files are used.)  However, the security risk of
a single-DES key for ``K/M`` is minimal, given that access to material
encrypted in ``K/M`` (the Kerberos database) is generally tightly controlled.
If an attacker can gain access to the encrypted database, they likely
have access to the stash file as well, rendering the weak cryptography
broken by non-cryptographic means.  As such, upgrading ``K/M`` to a stronger
encryption type is unlikely to be a high-priority task.

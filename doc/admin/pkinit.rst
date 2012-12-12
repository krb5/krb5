PKINIT configuration
====================

PKINIT is a preauthentication mechanism for Kerberos 5 which uses
X.509 certificates to authenticate the KDC to clients and vice versa.
PKINIT can also be used to enable anonymity support, allowing clients
to communicate securely with the KDC or with application servers
without authenticating as a particular client principal.

Configuring PKINIT requires establishing a certificate authority (or
using an existing one), and using the authority to sign certificates
for the KDC and for each client principal.  These instructions will
describe how to generate the necessary certificates using OpenSSL, and
then explain how to configure the KDC and clients once the
certificates are in hand.


Generating a certificate authority certificate
----------------------------------------------

You can establish a new certificate authority (CA) for use with a
PKINIT deployment with the commands::

    openssl genrsa -out cakey.pem 2048
    openssl req -key cakey.pem -new -x509 -out cacert.pem

The second command will ask for the values of several certificate
fields.  These fields can be set to any values.

The result of these commands will be two files, cakey.pem and
cacert.pem.  cakey.pem will contain a 2048-bit RSA private key, which
must be carefully protected.  cacert.pem will contain the CA
certificate, which must be placed in the filesytems of the KDC and
each client host.  cakey.pem will be required to create KDC and client
certificates.


Generating a KDC certificate
----------------------------

A KDC certificate for use with PKINIT is required to have some unusual
fields, which makes generating them with OpenSSL somewhat complicated.
First, you will need a file containing the following::

    [kdc_cert]
    basicConstraints=CA:FALSE
    keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
    extendedKeyUsage=1.3.6.1.5.2.3.5
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer
    issuerAltName=issuer:copy
    subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name

    [kdc_princ_name]
    realm=EXP:0,GeneralString:${ENV::REALM}
    principal_name=EXP:1,SEQUENCE:kdc_principal_seq

    [kdc_principal_seq]
    name_type=EXP:0,INTEGER:1
    name_string=EXP:1,SEQUENCE:kdc_principals

    [kdc_principals]
    princ1=GeneralString:krbtgt
    princ2=GeneralString:${ENV::REALM}

If the above contents are placed in extensions.kdc, you can generate
and sign a KDC certificate with the following commands::

    openssl genrsa -out kdckey.pem 2048
    openssl req -new -out kdc.req -key kdckey.pem
    env REALM=YOUR_REALMNAME openssl x509 -req -in kdc.req \
        -CAkey cakey.pem -CA cacert.pem -out kdc.pem \
        -extfile extensions.kdc -extensions kdc_cert -CAcreateserial
    rm kdc.req

The second command will ask for the values of certificate fields,
which can be set to any values.  In the third command, substitute your
KDC's realm name for YOUR_REALMNAME.

The result of this operation will be in two files, kdckey.pem and
kdc.pem.  Both files must be placed in the KDC's filesystem.
kdckey.pem, which contains the KDC's private key, must be carefully
protected.


Generating client certificates
------------------------------

PKINIT client certificates also must have some unusual certificate
fields.  To generate a client certificate with OpenSSL, you will need
an extensions file (different from the KDC extensions file above)
containing::

    [client_cert]
    basicConstraints=CA:FALSE
    keyUsage=digitalSignature,keyEncipherment,keyAgreement
    extendedKeyUsage=1.3.6.1.5.2.3.4
    subjectKeyIdentifier=hash
    authorityKeyIdentifier=keyid,issuer
    issuerAltName=issuer:copy
    subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:princ_name

    [princ_name]
    realm=EXP:0,GeneralString:${ENV::REALM}
    principal_name=EXP:1,SEQUENCE:principal_seq

    [principal_seq]
    name_type=EXP:0,INTEGER:1
    name_string=EXP:1,SEQUENCE:principals

    [principals]
    princ1=GeneralString:${ENV::CLIENT}

If the above contents are placed in extensions.client, you can
generate and sign a client certificate with the following commands::

    openssl genrsa -out clientkey.pem 2048
    openssl req -new -key clientkey.pem -out client.req
    env REALM=YOUR_REALMNAME CLIENT=YOUR_PRINCNAME openssl x509 \
        -CAkey cakey.pem -CA cacert.pem -req -in client.req \
        -extensions client_cert -extfile extensions.client \
        -out client.pem
    rm client.req

Normally, the first two commands should be run on the client host, and
the resulting client.req file transferred to the certificate authority
host for the third command.  As in the previous steps, the second
command will ask for the values of certificate fields, which can be
set to any values.  In the third command, substitute your realm's name
for YOUR_REALMNAME and the client's principal name (without realm) for
YOUR_PRINCNAME.

The result of this operation will be two files, clientkey.pem and
client.pem.  Both files must be present on the client's host;
clientkey.pem, which contains the client's private key, must be
protected from access by others.


Configuring the KDC
-------------------

The KDC must have filesystem access to the CA certificate
(cacert.pem), the KDC certificate (kdc.pem), and the KDC private key
(kdckey.pem).  Configure the following relations in the KDC's
:ref:`kdc.conf(5)` file, either in the :ref:`kdcdefaults` section or
in a :ref:`kdc_realms` subsection::

    pkinit_identity = FILE:/var/lib/krb5kdc/kdc.pem,/var/lib/krb5kdc/kdckey.pem
    pkinit_anchors = FILE:/var/lib/krb5kdc/cacert.pem

Adjust the pathnames to match the paths of the three files.  Because
of the larger size of requests and responses using PKINIT, you may
also need to allow TCP access to the KDC::

    kdc_tcp_ports = 88

Restart the :ref:`krb5kdc(8)` daemon to pick up the configuration
changes.

The principal entry for each PKINIT-using client must be configured to
require preauthentication.  Ensure this with the command::

    kadmin -q 'modprinc +requires_preauth YOUR_PRINCNAME'


Configuring the clients
-----------------------

To perform PKINIT authentication, a client host must have filesystem
access to the CA certificate (cacert.pem), the client certificate
(client.pem), and the client private key (clientkey.pem).  Configure
the following relations in the client host's :ref:`krb5.conf(5)` file
in the appropriate :ref:`realms` subsection::

    pkinit_anchors = FILE:/etc/krb5/cacert.pem
    pkinit_identities = FILE:/etc/krb5/client.pem,/etc/krb5/clientkey.pem

Adjust the pathnames to match the paths of the three files.

If the KDC and client are properly configured, it should now be
possible to run ``kinit username`` without entering a password.


.. _anonymous_pkinit:

Anonymous PKINIT
----------------

Anonymity support in Kerberos allows a client to obtain a ticket
without authenticating as any particular principal.  Such a ticket can
be used as a FAST armor ticket, or to securely communicate with an
application server anonymously.

To configure anonymity support, you must follow the steps above for
generating a KDC certificate and configuring the KDC host, but you do
not need to generate any client certificates.  On the KDC, you must
set the **pkinit_identity** variable to provide the KDC certificate,
but do not need to set the **pkinit_anchors** variable or store the
cacert.pem file if you won't have any client certificates to verify.
On client hosts, you must store the cacert.pem file and set the
**pkinit_anchors** variable in order to verify the KDC certificate,
but do not need to set the **pkinit_identities** variable.

Anonymity support is not enabled by default.  To enable it, you must
create the principal ``WELLKNOWN/ANONYMOUS`` using the command::

    kadmin -q 'addprinc -randkey WELLKNOWN/ANONYMOUS'

Some Kerberos deployments include application servers which lack
proper access control, and grant some level of access to any user who
can authenticate.  In such an environment, enabling anonymity support
on the KDC would present a security issue.  If you need to enable
anonymity support for TGTs (for use as FAST armor tickets) without
enabling anonymous authentication to application servers, you can set
the variable **restrict_anonymous_to_tgt** to ``true`` in the
appropriate :ref:`kdc_realms` subsection of the KDC's
:ref:`kdc.conf(5)` file.

To obtain anonymous credentials on a client, run ``kinit -n``, or
``kinit -n @REALMNAME`` to specify a realm.  The resulting tickets
will have the client name ``WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS``.

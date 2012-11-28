Developing with GSSAPI
======================

The GSSAPI (Generic Security Services API) allows applications to
communicate securely using Kerberos 5 or other security mechanisms.
We recommend using the GSSAPI (or a higher-level framework which
encompasses GSSAPI, such as SASL) for secure network communication
over using the libkrb5 API directly.

GSSAPIv2 is specified in :rfc:`2743` and :rfc:`2744`.  This
documentation will describe how various ways of using GSSAPI will
behave with the krb5 mechanism as implemented in MIT krb5, as well as
krb5-specific extensions to the GSSAPI.


Name types
----------

A GSSAPI application can name a local or remote entity by calling
gss_import_name_, specifying a name type and a value.  The following
name types are supported by the krb5 mechanism:

* **GSS_C_NT_HOSTBASED_SERVICE**: The value should be a string of the
  form ``service`` or ``service@hostname``.  This is the most common
  way to name target services when initiating a security context, and
  is the most likely name type to work across multiple mechanisms.

* **GSS_KRB5_NT_PRINCIPAL_NAME**: The value should be a principal name
  string.  This name type only works with the krb5 mechanism, and is
  defined in the ``<gssapi_krb5.h>`` header.

* **GSS_C_NT_USER_NAME** or **GSS_C_NULL_OID**: The value is treated
  as an unparsed principal name string, as above.  These name types
  may work with mechanisms other than krb5, but will have different
  interpretations in those mechanisms.  **GSS_C_NT_USER_NAME** is
  intended to be used with a local username, which will parse into a
  single-component principal in the default realm.

* **GSS_C_NT_ANONYMOUS**: The value is ignored.  The anonymous
  principal is used, allowing a client to authenticate to a server
  without asserting a particular identity (which may or may not be
  allowed by a particular server or Kerberos realm).

* **GSS_C_NT_MACHINE_UID_NAME**: The value is uid_t object.  On
  Unix-like systems, the username of the uid is looked up in the
  system user database and the resulting username is parsed as a
  principal name.

* **GSS_C_NT_STRING_UID_NAME**: As above, but the value is a decimal
  string representation of the uid.

* **GSS_C_NT_EXPORT_NAME**: The value must be the result of a
  gss_export_name_ call.


Initiator credentials
---------------------

A GSSAPI client application uses gss_init_sec_context_ to establish a
security context.  The *initiator_cred_handle* parameter determines
what tickets are used to establish the connection.  An application can
either pass **GSS_C_NO_CREDENTIAL** to use the default client
credential, or it can use gss_acquire_cred_ beforehand to acquire an
initiator credential.  The call to gss_acquire_cred_ may include a
*desired_name* parameter, or it may pass **GSS_C_NO_NAME** if it does
not have a specific name preference.

If the desired name for a krb5 initiator credential is a host-based
name, it is converted to a principal name of the form
``service/hostname`` in the local realm, where *hostname* is the local
hostname if not specified.  The hostname will be canonicalized using
forward name resolution, and possibly also using reverse name
resolution depending on the value of the **rdns** variable in
:ref:`libdefaults`.

If a desired name is specified in the call to gss_acquire_cred_, the
krb5 mechanism will attempt to find existing tickets for that client
principal name in the default credential cache or collection.  If the
default cache type does not support a collection, and the default
cache contains credentials for a different principal than the desired
name, a **GSS_S_CRED_UNAVAIL** error will be returned with a minor
code indicating a mismatch.

If no existing tickets are available for the desired name, but the
name has an entry in the default client :ref:`keytab_definition`, the
krb5 mechanism will acquire initial tickets for the name using the
default client keytab.

If no desired name is specified, credential acquisition will be
deferred until the credential is used in a call to
gss_init_sec_context_ or gss_inquire_cred_.  If the call is to
gss_init_sec_context_, the target name will be used to choose a client
principal name using the credential cache selection facility.  (This
facility might, for instance, try to choose existing tickets for a
client principal in the same realm as the target service).  If there
are no existing tickets for the chosen principal, but it is present in
the default client keytab, the krb5 mechanism will acquire initial
tickets using the keytab.

If the target name cannot be used to select a client principal
(because the credentials are used in a call to gss_inquire_cred_), or
if the credential cache selection facility cannot choose a principal
for it, the default credential cache will be selected if it exists and
contains tickets.

If the default credential cache does not exist, but the default client
keytab does, the krb5 mechanism will try to acquire initial tickets
for the first principal in the default client keytab.

If the krb5 mechanism acquires initial tickets using the default
client keytab, the resulting tickets will be stored in the default
cache or collection, and will be refreshed by future calls to
gss_acquire_cred_ as they approach their expire time.


Acceptor names
--------------

A GSSAPI server application uses gss_accept_sec_context_ to establish
a security context based on tokens provided by the client.  The
*acceptor_cred_handle* parameter determines what
:ref:`keytab_definition` entries may be authenticated to by the
client, if the krb5 mechanism is used.

The simplest choice is to pass **GSS_C_NO_CREDENTIAL** as the acceptor
credential.  In this case, clients may authenticate to any service
principal in the default keytab (typically |keytab|, or the value of
the **KRB5_KTNAME** environment variable).  This is the recommended
approach if the server application has no specific requirements to the
contrary.

A server may acquire an acceptor credential with gss_acquire_cred_ and
a *cred_usage* of **GSS_C_ACCEPT** or **GSS_C_BOTH**.  If the
*desired_name* parameter is **GSS_C_NO_NAME**, then clients will be
allowed to authenticate to any service principal in the default
keytab, just as if no acceptor credential was supplied.

If a server wishes to specify a *desired_name* to gss_acquire_cred_,
the most common choice is a host-based name.  If the host-based
*desired_name* contains just a *service*, then clients will be allowed
to authenticate to any host-based service principal (that is, a
principal of the form ``service/hostname@REALM``) for the named
service, regardless of hostname or realm, as long as it is present in
the default keytab.  If the input name contains both a *service* and a
*hostname*, clients will be allowed to authenticate to any host-based
principal for the named service and hostname, regardless of realm.

.. note::

          If a *hostname* is specified, it will be canonicalized
          using forward name resolution, and possibly also using
          reverse name resolution depending on the value of the
          **rdns** variable in :ref:`libdefaults`.

.. note::

          If the **ignore_acceptor_hostname** variable in
          :ref:`libdefaults` is enabled, then *hostname* will be
          ignored even if one is specified in the input name.

.. note::

          In MIT krb5 versions prior to 1.10, and in Heimdal's
          implementation of the krb5 mechanism, an input name with
          just a *service* is treated like an input name of
          ``service@localhostname``, where *localhostname* is the
          string returned by gethostname().

If the *desired_name* is a krb5 principal name or a local system name
type which is mapped to a krb5 principal name, clients will only be
allowed to authenticate to that principal in the default keytab.


Importing and exporting credentials
-----------------------------------

The following GSSAPI extensions can be used to import and export
credentials (declared in ``<gssapi/gssapi_ext.h>``)::

    OM_uint32 gss_export_cred(OM_uint32 *minor_status,
                              gss_cred_id_t cred_handle,
                              gss_buffer_t token);

    OM_uint32 gss_import_cred(OM_uint32 *minor_status,
                              gss_buffer_t token,
                              gss_cred_id_t *cred_handle);

The first function serializes a GSSAPI credential handle into a
buffer; the second unseralizes a buffer into a GSSAPI credential
handle.  Serializing a credential does not destroy it.  If any of the
mechanisms used in *cred_handle* do not support serialization,
gss_export_cred will return **GSS_S_UNAVAILABLE**.  As with other
GSSAPI serialization functions, these extensions are only intended to
work with a matching implementation on the other side; they do not
serialize credentials in a standardized format.

A serialized credential may contain secret information such as ticket
session keys.  The serialization format does not protect this
information from eavesdropping or tampering.  The calling application
must take care to protect the serialized credential when communicating
it over an insecure channel or to an untrusted party.

A krb5 GSSAPI credential may contain references to a credential cache,
a client keytab, an acceptor keytab, and a replay cache.  These
resources are normally serialized as references to their external
locations (such as the filename of the credential cache).  Because of
this, a serialized krb5 credential can only be imported by a process
with similar privileges to the exporter.  A serialized credential
should not be trusted if it originates from a source with lower
privileges than the importer, as it may contain references to external
credential cache, keytab, or replay cache resources not accessible to
the originator.

An exception to the above rule applies when a krb5 GSSAPI credential
refers to a memory credential cache, as is normally the case for
delegated credentials received by gss_accept_sec_context_.  In this
case, the contents of the credential cache are serialized, so that the
resulting token may be imported even if the original memory credential
cache no longer exists.

.. _gss_accept_sec_context: http://tools.ietf.org/html/rfc2744.html#section-5.1
.. _gss_acquire_cred: http://tools.ietf.org/html/rfc2744.html#section-5.2
.. _gss_export_name: http://tools.ietf.org/html/rfc2744.html#section-5.13
.. _gss_import_name: http://tools.ietf.org/html/rfc2744.html#section-5.16
.. _gss_init_sec_context: http://tools.ietf.org/html/rfc2744.html#section-5.19
.. _gss_inquire_cred: http://tools.ietf.org/html/rfc2744.html#section-5.21

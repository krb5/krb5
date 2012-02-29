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


Acceptor names
--------------

A GSSAPI server uses gss_accept_sec_context_ to establish a security
context based on tokens provided by the client.  The
*acceptor_cred_handle* parameter determines what keytab entries may be
authenticated to by the client, if the krb5 mechanism is used.

The simplest choice is to pass **GSS_C_NO_CREDENTIAL** as the acceptor
credential.  In this case, clients may authenticate to any service
principal in the default keytab (typically ``/etc/krb5.keytab``, or
the value of the **KRB5_KTNAME** environment variable).  This is the
recommended approach if the server application has no specific
requirements to the contrary.

A server may acquire an acceptor credential with gss_acquire_cred_ and
a *cred_usage* of **GSS_C_ACCEPT** or **GSS_C_BOTH**.  If the
*desired_name* parameter is **GSS_C_NO_NAME**, clients, as above, be
allowed to authenticate to any service principal in the default
keytab.

If a server wishes to specify a *desired_name* to gss_acquire_cred_,
the most common method is to call gss_import_name_ with an
*input_name_type* of **GSS_C_NT_HOSTBASED_SERVCE** and an
*input_name_buffer* containing a string of the form ``service`` or
``service@hostname``.  If the input name contains just a *service*,
then clients will be allowed to authenticate to any host-based service
principal (that is, a principal of the form
``service/hostname@REALM``) for the named service, regardless of
hostname or realm, as long as it is present in the default keytab.  If
the input name contains both a *service* and a *hostname*, clients
will be allowed to authenticate to any host-based principal for the
named service and hostname, regardless of realm.

.. note:: If a *hostname* is specified, it will be canonicalized
          using forward name resolution, and possibly also using
          reverse name resolution depending on the value of the
          **rdns** variable in :ref:`libdefaults`.

.. note:: If the **ignore_acceptor_hostname** variable in
          :ref:`libdefaults` is enabled, then *hostname* will be
          ignored even if one is specified in the input name.

.. note:: In MIT krb5 versions prior to 1.10, and in Heimdal's
          implementation of the krb5 mechanism, an input name with
          just a *service* is treated like an input name of
          ``service@localhostname``, where *localhostname* is the
          string returned by gethostname().

It is also possible to directly specify a service principal name using
the *input_name_type* value **GSS_KRB5_NT_PRINCIPAL_NAME** (defined in
``<gssapi_krb5.h>``), and an *input_name_buffer* containing an
unparsed principal name.  Doing so will prevent the server application
from working with mechanisms other than krb5.  If the a service
principal name is specified, clients will only be allowed to
authenticate to that principal in the default keytab.

.. _gss_accept_sec_context: http://tools.ietf.org/html/rfc2744.html#section-5.1
.. _gss_acquire_cred: http://tools.ietf.org/html/rfc2744.html#section-5.2
.. _gss_import_name: http://tools.ietf.org/html/rfc2744.html#section-5.16

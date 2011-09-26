.. _kinit(1):

kinit - obtain and cache Kerberos ticket-granting ticket
=========================================================

SYNOPSIS
~~~~~~~~

**kinit**      
    [**-V**]
    [**-l** *lifetime*]
    [**-s** *start_time*]
    [**-r** *renewable_life*]
    [**-p** | -**P**] 
    [**-f** | -**F**]
    [**-a**]
    [**-A**]
    [**-C**]
    [**-E**]
    [**-v**]
    [**-R**]
    [**-k** [-**t** *keytab_file*]]
    [**-c** *cache_name*]
    [**-n**]
    [**-S** *service_name*]
    [**-T** *armor_ccache*]
    [**-X** *attribute[=value]*]
    [*principal*]


DESCRIPTION
~~~~~~~~~~~~~

*kinit* obtains and caches an initial  ticket-granting  ticket for principal.


OPTIONS
~~~~~~~

     **-V**   display verbose output.

     **-l** *lifetime*
          requests a ticket  with  the  lifetime  lifetime.   The
          value  for lifetime must be followed immediately by one
          of the following delimiters::

             s  seconds
             m  minutes
             h  hours
             d  days

          as in "kinit -l 90m".  You cannot mix units; a value of "3h30m" will result in an error.

          If the **-l** option is not specified, the  default  ticket lifetime
          (configured by each site) is used.  Specifying a ticket lifetime longer than the maximum
          ticket  lifetime (configured by each site) results in a ticket with the maximum lifetime.

     **-s** *start_time*
          requests  a  postdated  ticket,   valid   starting   at
          *start_time*.   Postdated  tickets  are  issued  with the
          *invalid* flag set, and need to be fed back  to  the  kdc
          before use.

     **-r** *renewable_life*
          requests renewable tickets, with a  total  lifetime  of
          *renewable_life*.   The duration is in the same format as
          the **-l** option, with the same delimiters.

     **-f**   request forwardable tickets.

     **-F**   do not request forwardable tickets.

     **-p**   request proxiable tickets.

     **-P**   do not request proxiable tickets.

     **-a**   request tickets with the local address[es].

     **-A**   request address-less tickets.

     **-C**   requests canonicalization of the principal name.

     **-E**   treats the principal name as an enterprise name.

     **-v**    
          requests that the ticket granting ticket in  the  cache
          (with  the  *invalid*  flag set) be passed to the KDC for validation.
          If the ticket is within its requested time range,
          the cache is replaced with the validated ticket.

     **-R**
          requests renewal of the ticket-granting  ticket.
          Note that  an  expired ticket cannot be renewed, even if the ticket
          is still within its renewable life.

     **-k** [**-t** *keytab_file*]
          requests a ticket, obtained from a  key  in  the  local host's  *keytab* file.
          The name and location of the key tab file may be specified with the 
          **-t** *keytab_file* option; otherwise the default name and location will be used.
          By default a host ticket is  requested  but any principal may be specified.
          On a KDC, the special keytab location **KDB:** can be used to  indicate that kinit
          should  open the KDC database and look  up the key directly.
          This permits  an  administrator  to  obtain tickets  as  any principal that
          supports password-based authentication.

     **-n**
          Requests anonymous processing.
          Two types of  anonymous principals  are  supported.
        
          For  fully anonymous Kerberos,  configure  pkinit  on  the  KDC  and  configure
          *pkinit_anchors* in the client's krb5.conf.  Then use the **-n** option with
          a principal of the form *@REALM* (an empty principal  name  followed  by  the
          at-sign and a realm name).  If permitted by the KDC,  an  anonymous  ticket will  be  returned.
    
          A second form of anonymous tickets is supported;  these  realm-exposed  tickets
          hide the identity of the client but not the client's realm.
          For this mode, use **kinit -n** with a normal  principal  name.
          If  supported by the KDC, the principal (but not realm) will be replaced by the  anonymous  principal.

          As  of release  1.8,  the MIT Kerberos KDC only supports fully anonymous operation.

     **-T** *armor_ccache*
          Specifies the name of a credential cache  that  already contains  a  ticket.   If  supported  by  the KDC, This
          ccache will be used to armor the  request  so  that  an attacker  would  have to know both the key of the armor
          ticket and the key of the principal used for  authentication  in  order  to attack the request. Armoring also
          makes sure that the response from the KDC is not  modified in transit.

     **-c** *cache_name*
          use *cache_name* as the Kerberos 5  credentials  (ticket) cache  name  and  location;
          if this option is not used, the default cache name and location are used.

          The default credentials cache may vary between systems.  If
          the **KRB5CCNAME** environment variable is set, its value is
          used to name the default ticket cache.  If a principal name
          is specified and the type of the default credentials cache
          supports a collection (such as the DIR type), an existing
          cache containing credentials for the principal is selected
          or a new one is created and becomes the new primary cache.
          Otherwise, any existing contents of the default cache are
          destroyed by kinit.

     **-S** *service_name*
          specify an alternate service name to use  when  getting initial tickets.

     **-X** *attribute* [= *value* ]
          specify a pre-authentication *attribute* and *value* to  be passed  to  pre-authentication plugins.
          The acceptable attribute and value values vary from pre-authentication plugin  to plugin.
          This option may be specified multiple times to specify multiple attributes.
          If no  value is specified, it is assumed to be "yes".

          The following attributes are recognized by the OpenSSL pkinit pre-authentication mechanism:

              **X509_user_identity** = *value*

                   specify where to find user's X509 identity information

              **X509_anchors** = *value*

                   specify where to find trusted X509 anchor information

              **flag_RSA_PROTOCOL** [ = *yes* ]

                   specify use of RSA, rather than the default Diffie-Hellman protocol



ENVIRONMENT
~~~~~~~~~~~~~

*kinit* uses the following environment variables:

     **KRB5CCNAME**
          Location of the default Kerberos 5 credentials (ticket)
          cache, in the form *type*:*residual*.  If no type prefix is
          present, the **FILE** type is assumed.  The type of the
          default cache may determine the availability of a cache
          collection; for instance, a default cache of type **DIR**
          causes caches within the directory to be present in the
          collection.


FILES
~~~~~~~~

/tmp/krb5cc_[uid]  default location of Kerberos 5 credentials cache ([uid] is the decimal UID of the user).

/etc/krb5.keytab   default location for the local host's keytab file.


SEE ALSO
~~~~~~~~~~~

klist(1), kdestroy(1), kerberos(1)



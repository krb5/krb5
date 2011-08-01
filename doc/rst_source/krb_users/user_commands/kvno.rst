kvno - print key version numbers of Kerberos principals
===========================================================

SYNOPSIS
~~~~~~~~~~~~~~~

**kvno**
     [**-c** *ccache*] 
     [**-e** *etype*] 
     [**-q**] 
     [**-h**]
     [**-P**]
     [**-S** *sname*]
     [**-U** *for_user*]
     *service1 service2* ...

DESCRIPTION
~~~~~~~~~~~~~~~

*kvno* acquires a service ticket for the specified Kerberos principals and prints out the key version numbers of each.

OPTIONS
~~~~~~~~~~~~~~~

       **-c** *ccache*
              Specifies the name of a credentials cache to use (if not the default)

       **-e** *etype*
              Specifies the enctype which will be requested for the session key of all the services named on the command line.  This is useful in certain backward compatibility situations.

       **-q**
              Suppress printing

       **-h**     
              Prints a usage statement and exits

       **-P**     
              Specifies that the *service1 service2* ...  arguments are to be treated as services for which credentials should be acquired using constrained delegation. This option is only valid when used in conjunction with protocol transition.

       **-S** *sname*
              Specifies  that  krb5_sname_to_principal()  will be used to build principal names.  If this flag is specified, the *service1 service2* ...  arguments are interpreted as hostnames (rather than principal names), and sname is interpreted as the service name.

       **-U** *for_user*
              Specifies that protocol transition (S4U2Self) is to be used to acquire a ticket on behalf of for_user.  If  constrained  delegation is not requested, the service name must match the credentials cache client principal.

ENVIRONMENT
~~~~~~~~~~~~~~~

*kvno* uses the following environment variable:

       **KRB5CCNAME**  - Location of the credentials (ticket) cache.

FILES
~~~~~~~~~~~~~~~

/tmp/krb5cc_[uid]  default location of the credentials cache ([uid] is the decimal UID of the user).

SEE ALSO
~~~~~~~~~~~~~~~

kinit(1), kdestroy(1), krb5(3)



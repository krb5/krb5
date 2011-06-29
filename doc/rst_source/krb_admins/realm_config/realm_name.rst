Kerberos realms
==================

Although your Kerberos realm can be any ASCII string, convention is to make it the same as your domain name, in **upper-case** letters. 

For example, hosts in the domain *example.com* would be in the Kerberos realm::
        
     EXAMPLE.COM

If you need multiple Kerberos realms, MIT recommends that you use descriptive names which end with your domain name, such as::

      BOSTON.EXAMPLE.COM
      HOUSTON.EXAMPLE.COM 

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___realm_config



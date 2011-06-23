Troubleshooting
================

List
----


.. error:: KDC has no support for encryption type while getting initial credentials

.. error:: credential verification failed: KDC has no support for encryption type



Add **allow_weak_crypto = true** to the [libdefaults] section of krb5.conf

Version 1.7+

Seen in:  clients

--------------------------------------------------------------------------------------------

.. error:: Hostname cannot be canonicalized

The problem is that ssh is attempting to authenticate to the
canonicalization of inside-host in DNS, but since that's inside your
internal network, there is no DNS available to do the
canonicalization, so one needs to tell GSSAPI what the hostname is separately.  

|   Host inside-host
|       GSSAPITrustDns no
|       HostName inside-host.inside.domain
|       ProxyCommand ssh -t jump-box.example.com "nc -w2 %h %p"
 

GSSAPITrustDns yes is setting the exact opposite of rdns = false.  It's the equivalent of rdns = true.

External links: [http://www.mail-archive.com/kerberos@mit.edu/msg17101.html]

Seen in:  ssh


--------------------------------------------------------------------------------------------

.. error:: Wrong principal in request


If referrals are being used, specifying the host to realm mapping in the krb5 profile results 
in the referrals logic being disabled and may solve the problem.

External links: [http://www.mail-archive.com/kerberos@mit.edu/msg16257.html]

Seen in:  ssh

--------------------------------------------------------------------------------------------

..

------------------

Feedback


Please, provide your feedback on this document at krb5-bugs@mit.edu?subject=Documentation___errors


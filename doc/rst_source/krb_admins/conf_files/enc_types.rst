.. _senct_label:

Supported Encryption Types
===============================


Any tag in the configuration files which requires a list of encryption types can be set to some combination of the following strings. Encryption types marked as "weak" are available for compatibility but not recommended for use.

==================================================== =========================================================
des-cbc-crc                                          DES cbc mode with CRC-32 (weak)
des-cbc-md4                                          DES cbc mode with RSA-MD4 (weak)
des-cbc-md5                                          DES cbc mode with RSA-MD5 (weak)
des-cbc-raw                                          DES cbc mode raw (weak)
des3-cbc-raw                                         Triple DES cbc mode raw (weak)
des3-cbc-sha1 des3-hmac-sha1 des3-cbc-sha1-kd        Triple DES cbc mode with HMAC/sha1
des-hmac-sha1                                        DES with HMAC/sha1 (weak)
aes256-cts-hmac-sha1-96 aes256-cts AES-256           CTS mode with 96-bit SHA-1 HMAC 
aes128-cts-hmac-sha1-96 aes128-cts AES-128           CTS mode with 96-bit SHA-1 HMAC
arcfour-hmac rc4-hmac arcfour-hmac-md5               RC4 with HMAC/MD5
arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp   Exportable RC4 with HMAC/MD5 (weak)
des                                                  The DES family: des-cbc-crc, des-cbc-md5, and des-cbc-md4 (weak)
des3                                                 The triple DES family: des3-cbc-sha1
aes                                                  The AES family: aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96
rc4                                                  The RC4 family: arcfour-hmac 
==================================================== =========================================================

The string **DEFAULT** can be used to refer to the default set of types for the variable in question. Types or families can be removed from the current list by prefixing them with a minus sign ("-"). Types or families can be prefixed with a plus sign ("+") for symmetry; it has the same meaning as just listing the type or family. For example, **"DEFAULT -des"** would be the default set of encryption types with DES types removed, and **"des3 DEFAULT"** would be the default set of encryption types with triple DES types moved to the front.

While *aes128-cts* and *aes256-cts* are supported for all Kerberos operations, they are not supported by older versions of our GSSAPI implementation (krb5-1.3.1 and earlier).

By default, AES is enabled in 1.9 release. Sites wishing to use AES encryption types on their KDCs need to be careful not to give GSSAPI services AES keys if the servers have not been updated. If older GSSAPI services are given AES keys, then services may fail when clients supporting AES for GSSAPI are used. Sites may wish to use AES for user keys and for the ticket granting ticket key, although doing so requires specifying what encryption types are used as each principal is created.

If all GSSAPI-based services have been updated before or with the KDC, this is not an issue. 

--------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___conf_files



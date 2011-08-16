.. _Supported_Encryption_Types_and_Salts:

Supported encryption types and salts
======================================

Supported encryption types 
-------------------------------------

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

Salts
-------------

Your Kerberos key is derived from your password. To ensure that people who happen to pick the same password do not have the same key, Kerberos 5 incorporates more information into the key using something called a salt. The supported values for salts are as follows.

================= ============================================
normal            default for Kerberos Version 5
v4                the only type used by Kerberos Version 4, no salt
norealm           same as the default, without using realm information
onlyrealm         uses only realm information as the salt
afs3              AFS version 3, only used for compatibility with Kerberos 4 in AFS
special           only used in very special cases; not fully supported
================= ============================================


--------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___conf_files



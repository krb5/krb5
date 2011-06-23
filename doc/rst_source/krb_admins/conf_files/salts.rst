.. _salts_label:

Salts
=========

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



Password management
============================

.. note:: This document was copied from **Kerberos V5 UNIX User's Guide**. Currently it is under review. Please, send your feedback, corrections and additions to krb5-bugs@mit.edu. Your contribution is greatly appreciated.



Your password is the only way Kerberos has of verifying your identity. If someone finds out your password, that person can masquerade as you—send email that comes from you, read, edit, or delete your files, or log into other hosts as you—and no one will be able to tell the difference. For this reason, it is important that you choose a good password, and keep it secret. If you need to give access to your account to someone else, you can do so through Kerberos. (See :ref:`gatya_label`.) You should never tell your password to anyone, including your system administrator, for any reason. You should change your password frequently, particularly any time you think someone may have found out what it is.



.. toctree::
   :maxdepth: 1

   pwd_management.rst
   grant_access.rst
   pwd_quality.rst

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_pwd_mgmt



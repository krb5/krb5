Changing your password
==========================

To change your Kerberos password, use the *kpasswd* command. It will ask you for your old password (to prevent someone else from walking up to your computer when you're not there and changing your password), and then prompt you for the new one twice. (The reason you have to type it twice is to make sure you have typed it correctly.) For example, user *david* would do the following::

     shell% kpasswd
     Password for david:    <- Type your old password.
     Enter new password:    <- Type your new password.
     Enter it again:  <- Type the new password again.
     Password changed.
     shell%

If *david* typed the incorrect old password, he would get the following message::

     shell% kpasswd
     Password for david:  <- Type the incorrect old password.
     kpasswd: Password incorrect while getting initial ticket
     shell%

If you make a mistake and don't type the new password the same way twice, *kpasswd* will ask you to try again::

     shell% kpasswd
     Password for david:  <- Type the old password.
     Enter new password:  <- Type the new password.
     Enter it again: <- Type a different new password.
     kpasswd: Password mismatch while reading password
     shell%

Once you change your password, it takes some time for the change to propagate through the system. Depending on how your system is set up, this might be anywhere from a few minutes to an hour or more. If you need to get new Kerberos tickets shortly after changing your password, try the new password. If the new password doesn't work, try again using the old one.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_pwd_mgmt



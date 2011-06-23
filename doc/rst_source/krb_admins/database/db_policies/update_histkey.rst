Updating the history key
==================================

The following text is for release < 1.8.

If a policy specifies a number of old keys kept of two or more, the stored old keys are encrypted in a history key, which is found in the key data of the *kadmin/history* principal.

Currently there is no support for proper rollover of the history key, but you can change the history key (for example, to use a better encryption type) at the cost of invalidating currently stored old keys. To change the history key, run::

     kadmin: change_password -randkey kadmin/history
     

This command will fail if you specify the *-keepold* flag. Only one new history key will be created, even if you specify multiple key/salt combinations.

In the future, we plan to migrate towards encrypting old keys in the master key instead of the history key, and implementing proper rollover support for stored old keys. - implemented in 1.8+

------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___db_policies



Destroying tickets with *kdestroy*
=====================================

Your Kerberos tickets are proof that you are indeed yourself, and tickets can be stolen. If this happens, the person who has them can masquerade as you until they expire. For this reason, you should destroy your Kerberos tickets when you are away from your computer.

Destroying your tickets is easy. Simply type *kdestroy*::

     shell% kdestroy
     shell%

If *kdestroy* fails to destroy your tickets, it will beep and give an error message. For example, if *kdestroy* can't find any tickets to destroy, it will give the following message::

     shell% kdestroy
     kdestroy: No credentials cache file found while destroying cache
     shell%

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_tkt_mgmt




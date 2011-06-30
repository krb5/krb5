.. _db_prop_label:

Database propagation
=========================

The Kerberos database resides on the master KDC, and must be propagated regularly (usually by a cron job) to the slave KDCs. In deciding how frequently the propagation should happen, you will need to balance the amount of time the propagation takes against the maximum reasonable amount of time a user should have to wait for a password change to take effect.

If the propagation time is longer than this maximum reasonable time (e.g., you have a particularly large database, you have a lot of slaves, or you experience frequent network delays), you may wish to cut down on your propagation delay by performing the propagation in parallel. To do this, have the master KDC propagate the database to one set of slaves, and then have each of these slaves propagate the database to additional slaves. 

See also :ref:`incr_db_prop_label`

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___realm_config



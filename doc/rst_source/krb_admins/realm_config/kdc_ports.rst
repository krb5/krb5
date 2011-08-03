Ports for the KDC and admin services
======================================

The default ports used by Kerberos are port **88** for the KDC1 and port **749** for the admin server. You can, however, choose to run on other ports, as long as they are specified in each host's */etc/services* and :ref:`krb5.conf` files, and the :ref:`kdc.conf` file on each KDC. For a more thorough treatment of port numbers used by the Kerberos V5 programs, refer to the :ref:`conf_firewall_label`

------------

Feedback:

Please, provide your feedback or suggest a new topic at krb5-bugs@mit.edu?subject=Documentation___realm_config


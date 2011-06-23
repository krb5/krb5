.. _otwk_labal:

Obtaining tickets with *kinit*
==================================

If your site is using the Kerberos V5 login program, you will get Kerberos tickets automatically when you log in. If your site uses a different login program, you may need to explicitly obtain your Kerberos tickets, using the *kinit* program. Similarly, if your Kerberos tickets expire, use the *kinit* program to obtain new ones.

To use the *kinit* program, simply type *kinit* and then type your password at the prompt. For example, Jennifer (whose username is *jennifer*) works for Bleep, Inc. (a fictitious company with the domain name mit.edu and the Kerberos realm ATHENA.MIT.EDU). She would type::

     shell% kinit
     Password for jennifer@ATHENA.MIT.EDU: <-- [Type jennifer's password here.]
     shell%

If you type your password incorrectly, *kinit* will give you the following error message::

     shell% kinit
     Password for jennifer@ATHENA.MIT.EDU: <-- [Type the wrong password here.]
     kinit: Password incorrect
     shell%

and you won't get Kerberos tickets.

Notice that *kinit* assumes you want tickets for your own username in your default realm. Suppose Jennifer's friend David is visiting, and he wants to borrow a window to check his mail. David needs to get tickets for himself in his own realm, EXAMPLE.COM [1]_. He would type::

     shell% kinit david@EXAMPLE.COM
     Password for david@EXAMPLE.COM: <-- [Type david's password here.]
     shell%

David would then have tickets which he could use to log onto his own machine. Note that he typed his password locally on Jennifer's machine, but it never went over the network. Kerberos on the local host performed the authentication to the KDC in the other realm.

If you want to be able to forward your tickets to another host, you need to request forwardable tickets. You do this by specifying the **-f** option::

     shell% kinit -f
     Password for jennifer@ATHENA.MIT.EDU: <-- [Type your password here.]
     shell%

Note that *kinit* does not tell you that it obtained forwardable tickets; you can verify this using the *klist* command (see :ref:`vytwk_label`).

Normally, your tickets are good for your system's default ticket lifetime, which is ten hours on many systems. You can specify a different ticket lifetime with the **-l** option. Add the letter **s** to the value for seconds, **m** for minutes, **h** for hours, or **d** for days. For example, to obtain forwardable tickets for *david@EXAMPLE.COM* that would be good for *three hours*, you would type::

     shell% kinit -f -l 3h david@EXAMPLE.COM
     Password for david@EXAMPLE.COM: <-- [Type david's password here.]
     shell%

.. note::You cannot mix units; specifying a lifetime of 3h30m would result in an error. Note also that most systems specify a maximum ticket lifetime. If you request a longer ticket lifetime, it will be automatically truncated to the maximum lifetime.


.. [1] Note: the realm EXAMPLE.COM must be listed in your computer's Kerberos configuration file, */etc/krb5.conf*.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_tkt_mgmt



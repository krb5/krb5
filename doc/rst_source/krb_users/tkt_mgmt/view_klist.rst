.. _vytwk_label:

Viewing tickets with *klist*
================================


The klist command shows your tickets. When you first obtain tickets, you will have only the ticket-granting ticket. The listing would look like this::

     shell% klist
     Ticket cache: /tmp/krb5cc_ttypa
     Default principal: jennifer@ATHENA.MIT.EDU
     
     Valid starting     Expires            Service principal
     06/07/04 19:49:21  06/08/04 05:49:19  krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     shell%

The ticket cache is the location of your ticket file. In the above example, this file is named */tmp/krb5cc_ttypa*. The default principal is your kerberos principal.

The *valid starting* and *expires* fields describe the period of time during which the ticket is valid. The service principal describes each ticket. The ticket-granting ticket has the primary *krbtgt*, and the instance is the realm name.

Now, if *jennifer* connected to the machine *daffodil.mit.edu*, and then typed *klist* again, she would have gotten the following result::

     shell% klist
     Ticket cache: /tmp/krb5cc_ttypa
     Default principal: jennifer@ATHENA.MIT.EDU
     
     Valid starting     Expires            Service principal
     06/07/04 19:49:21  06/08/04 05:49:19  krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     06/07/04 20:22:30  06/08/04 05:49:19  host/daffodil.mit.edu@ATHENA.MIT.EDU
     shell%

Here's what happened: when *jennifer* used telnet to connect to the host *daffodil.mit.edu*, the telnet program presented her ticket-granting ticket to the KDC and requested a host ticket for the host *daffodil.mit.edu*. The KDC sent the host ticket, which telnet then presented to the host *daffodil.mit.edu*, and she was allowed to log in without typing her password.

Suppose your Kerberos tickets allow you to log into a host in another domain, such as *trillium.example.com*, which is also in another Kerberos realm, *EXAMPLE.COM*. If you telnet to this host, you will receive a ticket-granting ticket for the realm *EXAMPLE.COM*, plus the new host ticket for *trillium.example.com*. *klist* will now show::

     shell% klist
     Ticket cache: /tmp/krb5cc_ttypa
     Default principal: jennifer@ATHENA.MIT.EDU
     
     Valid starting     Expires            Service principal
     06/07/04 19:49:21  06/08/04 05:49:19  krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     06/07/04 20:22:30  06/08/04 05:49:19  host/daffodil.mit.edu@ATHENA.MIT.EDU
     06/07/04 20:24:18  06/08/04 05:49:19  krbtgt/EXAMPLE.COM@ATHENA.MIT.EDU
     06/07/04 20:24:18  06/08/04 05:49:19  host/trillium.example.com@EXAMPLE.COM
     shell%

You can use the **-f** option to view the flags that apply to your tickets. The flags are:

===== =========================
  F   Forwardable
  f   forwarded
  P   Proxiable
  p   proxy
  D   postDateable
  d   postdated
  R   Renewable
  I   Initial
  i   invalid
  H   Hardware authenticated
  A   preAuthenticated
  T   Transit policy checked
  O   Okay as delegate
  a   anonymous
===== =========================

Here is a sample listing. In this example, the user *jennifer* obtained her initial tickets (**I**), which are forwardable (**F**) and postdated (**d**) but not yet validated (**i**)::

     shell% klist -f
     Ticket cache: /tmp/krb5cc_320
     Default principal: jennifer@ATHENA.MIT.EDU
     
     Valid starting      Expires             Service principal
     31/07/05 19:06:25  31/07/05 19:16:25  krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
             Flags: FdiI
     shell%


In the following example, the user *david*'s tickets were forwarded (**f**) to this host from another host. The tickets are reforwardable (**F**)::

     shell% klist -f
     Ticket cache: /tmp/krb5cc_p11795
     Default principal: david@EXAMPLE.COM
     
     Valid starting     Expires            Service principal
     07/31/05 11:52:29  07/31/05 21:11:23  krbtgt/EXAMPLE.COM@EXAMPLE.COM
             Flags: Ff
     07/31/05 12:03:48  07/31/05 21:11:23  host/trillium.example.com@EXAMPLE.COM
             Flags: Ff
     shell%

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_tkt_mgmt



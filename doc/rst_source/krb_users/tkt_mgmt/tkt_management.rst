Kerberos ticket properties
===========================

There are various properties that Kerberos tickets can have:

If a ticket is **forwardable**, then the KDC can issue a new ticket with a different network address based on the forwardable ticket. This allows for authentication forwarding without requiring a password to be typed in again. For example, if a user with a forwardable TGT logs into a remote system, the KDC could issue a new TGT for that user with the netword address of the remote system, allowing authentication on that host to work as though the user were logged in locally.

When the KDC creates a new ticket based on a forwardable ticket, it sets the **forwarded** flag on that new ticket. Any tickets that are created based on a ticket with the forwarded flag set will also have their forwarded flags set.

A **proxiable** ticket is similar to a forwardable ticket in that it allows a service to take on the identity of the client. Unlike a forwardable ticket, however, a proxiable ticket is only issued for specific services. In other words, a ticket-granting ticket cannot be issued based on a ticket that is proxiable but not forwardable.

A **proxy** ticket is one that was issued based on a proxiable ticket.

A **postdated** ticket is issued with the invalid flag set. After the starting time listed on the ticket, it can be presented to the KDC to obtain valid tickets.

Tickets with the **postdateable** flag set can be used to issue postdated tickets.

**Renewable** tickets can be used to obtain new session keys without the user entering their password again. A renewable ticket has two expiration times. The first is the time at which this particular ticket expires. The second is the latest possible expiration time for any ticket issued based on this renewable ticket.

A ticket with the **initial flag** set was issued based on the authentication protocol, and not on a ticket-granting ticket. Clients that wish to ensure that the user's key has been recently presented for verification could specify that this flag must be set to accept the ticket.

An **invalid** ticket must be rejected by application servers. Postdated tickets are usually issued with this flag set, and must be validated by the KDC before they can be used.

A **preauthenticated** ticket is one that was only issued after the client requesting the ticket had authenticated itself to the KDC.

The **hardware authentication** flag is set on a ticket which required the use of hardware for authentication. The hardware is expected to be possessed only by the client which requested the tickets.

If a ticket has the **transit policy** checked flag set, then the KDC that issued this ticket implements the transited-realm check policy and checked the transited-realms list on the ticket. The transited-realms list contains a list of all intermediate realms between the realm of the KDC that issued the first ticket and that of the one that issued the current ticket. If this flag is not set, then the application server must check the transited realms itself or else reject the ticket.

The okay as **delegate** flag indicates that the server specified in the ticket is suitable as a delegate as determined by the policy of that realm. A server that is acting as a delegate has been granted a proxy or a forwarded TGT. This flag is a new addition to the Kerberos V5 protocol and is not yet implemented on MIT servers.

An **anonymous** ticket is one in which the named principal is a generic principal for that realm; it does not actually specify the individual that will be using the ticket. This ticket is meant only to securely distribute a session key. This is a new addition to the Kerberos V5 protocol and is not yet implemented on MIT servers.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_tkt_mgmt



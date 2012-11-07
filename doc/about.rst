The Kerberos Documentation Set
==============================

Background
----------

Starting with release 1.11, the Kerberos documentation set is
unified in a central form.  Man pages, HTML documentation, and PDF
documents are compiled from reStructuredText sources, and the application
developer documentation incorporates Doxygen markup from the source
tree.  This project was undertaken along the outline described at
http://k5wiki.kerberos.org/wiki/Projects/Kerberos_Documentation .

Previous versions of Kerberos 5 attempted to maintain separate documentation
in the texinfo format, with separate groff manual pages.  Having the API
documentation disjoint from the source code implementing that API
resulted in the documentation becoming stale, and over time the documentation
ceased to match reality.  With a fresh start and a source format that is
easier to use and maintain, reStructuredText-based documents should provide
an improved experience for the user.  Consolidating all the documentation
formats into a single source document makes the documentation set easier
to maintain.

Feedback and Comments
---------------------

At the moment, comments should be sent via email to
krb5-bugs@mit.edu.

The HTML version of this documentation has a "FEEDBACK" link
(at the bottom of every page) to the krb5-bugs@mit.edu email address
with a pre-constructed subject line.

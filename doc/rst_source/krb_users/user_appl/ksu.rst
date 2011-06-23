ksu
=============

The Kerberos V5 *ksu* program replaces the standard UNIX *su* program (See ksu_su_label_). *ksu* first authenticates you to Kerberos. Depending on the configuration of your system, *ksu* may ask for your Kerberos password if authentication fails. Note that you should never type your password if you are remotely logged in using an unencrypted connection.

Once *ksu* has authenticated you, if your Kerberos principal appears in the target's *.k5login* file (see Granting Access to Your Account) or in the target's *.k5users* file (see below), it switches your user ID to the target user ID.

For example, *david* has put *jennifer*'s Kerberos principal in his *.k5login* file. If *jennifer* uses *ksu* to become *david*, the exchange would look like this. (To differentiate between the two shells, *jennifer*'s prompt is represented as *jennifer* and *david*'s prompt is represented as *david*.)::

     jennifer% ksu david
     Account david: authorization for jennifer@ATHENA.MIT.EDU successful
     Changing uid to david (3382)
     david%

Note that the new shell has a copy of *jennifer*'s tickets. The ticket filename contains *david*'s UID with .1 appended to it::

     david% klist
     Ticket cache: /tmp/krb5cc_3382.1
     Default principal: jennifer@ATHENA.MIT.EDU
     
     Valid starting      Expires             Service principal
     07/31/04 21:53:01  08/01/04 07:52:53  krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU
     07/31/04 21:53:39  08/01/04 07:52:53  host/daffodil.mit.edu@ATHENA.MIT.EDU
     david%

If *jennifer* had not appeared in *david*'s *.k5login* file (and the system was configured to ask for a password), the exchange would have looked like this (assuming *david* has taken appropriate precautions in protecting his password)::

     jennifer% ksu david
     WARNING: Your password may be exposed if you enter it here and are logged
              in remotely using an unsecure (non-encrypted) channel.
     Kerberos password for david@ATHENA.MIT.EDU:  <-  jennifer types the wrong password here.
     ksu: Password incorrect
     Authentication failed.
     jennifer%

Now, suppose *david* did not want to give *jennifer* full access to his account, but wanted to give her permission to list his files and use the "more" command to view them. He could create a *.k5users* file giving her permission to run only those specific commands.

The *.k5users* file is like the *.k5login* file, except that each principal is optionally followed by a list of commands. *ksu* will let those principals execute only the commands listed, using the -e option. *david*'s *.k5users* file might look like the following::

     jennifer@ATHENA.MIT.EDU       /bin/ls /usr/bin/more
     joeadmin@ATHENA.MIT.EDU         /bin/ls
     joeadmin/admin@ATHENA.MIT.EDU   *
     david@EXAMPLE.COM

The above *.k5users* file would let *jennifer* run only the commands /bin/ls and /usr/bin/more. It would let joeadmin run only the command /bin/ls if he had regular tickets, but if he had tickets for his admin instance, joeadmin/admin@ATHENA.MIT.EDU, he would be able to execute any command. The last line gives *david* in the realm EXAMPLE.COM permission to execute any command. (I.e., having only a Kerberos principal on a line is equivalent to giving that principal permission to execute \*.) This is so that *david* can allow himself to execute commands when he logs in, using Kerberos, from a machine in the realm EXAMPLE.COM.

Then, when *jennifer* wanted to list his home directory, she would type::

     jennifer% ksu david -e ls ~david
     Authenticated jennifer@ATHENA.MIT.EDU
     Account david: authorization for jennifer@ATHENA.MIT.EDU for execution of
                    /bin/ls successful
     Changing uid to david (3382)
     Mail            News            Personal        misc            bin
     jennifer%

If *jennifer* had tried to give a different command to *ksu*, it would have prompted for a password as with the previous example.

Note that unless the *.k5users* file gives the target permission to run any command, the user must use *ksu* with the -e command option.

The *ksu* options you are most likely to use are:

=================== ====================================
-n *principal*      specifies which Kerberos principal you want to use for *ksu*. (e.g., the user *joeadmin* might want to use his admin instance.)
-c                  specifies the location of your Kerberos credentials cache (ticket file).
-k                  tells *ksu* not to destroy your Kerberos tickets when *ksu* is finished.
-f                  requests forwardable tickets. (See :ref:`otwk_labal`.) This is only applicable if *ksu* needs to obtain tickets.
-l *lifetime*       sets the ticket lifetime. (See :ref:`otwk_labal`.) This is only applicable if *ksu* needs to obtain tickets.
-z                  tells *ksu* to copy your Kerberos tickets only if the UID you are switching is the same as the Kerberos primary (either yours or the one specified by the **-n** option).
-Z                  tells *ksu* not to copy any Kerberos tickets to the new UID.
-e *command*        tells *ksu* to execute command and then exit. See the description of the *.k5users* file above.
-a *text*           (at the end of the command line) tells *ksu* to pass everything after **-a** to the target shell.
=================== ====================================

----------------------------------

.. _ksu_su_label:

*ksu* vs *su*
-----------------------

From from the discussion at [http://mailman.mit.edu/pipermail/kerberos/2011-January/016886.html]:

The main reason why we use *ksu* instead of *su* is because every person who
can *su* to root has their own separate */root* principal with a separate
password and we want them to use those passwords instead.  In many cases,
the set of people who know the actual root password is more limited than
the people who can *ksu* (perhaps because the formula for it is shared with
other systems those people should not be root on, for instance).

You can do this with *su* and an appropriate PAM configuration, or with *sudo*
and an appropriate PAM configuration, but it's fiddly and annoying and
it's often easier to just use *ksu*.  Plus, you'd probably have to use my
pam-krb5 module rather than whatever came with your system, since it would
be extremely difficult to set this up without the aid of the *alt_auth_map*
configuration option.

Don't need to leak my root password to client users

Client users shall use *ksu* under local machine, not remote machines:
Ideally in Kerberos you never enter your password into any remote
system, but always authenticate locally and then use Kerberos to
authenticate to remote systems.  We're moving in that way (by allowing
root logins only via *GSSAPI*), but the tradeoff is that you have to allow
remote direct root logins, which makes some a bit uncomfortable.

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl



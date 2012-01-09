.. _krb5-send-pr(1):


krb5-send-pr - send problem report (PR) to a central support site
=======================================================================

SYNOPSIS
-----------

**krb5-send-pr**
[ *site* ] 
[ **-f** *problem-report* ] 
[ **-t** *mail-address* ]
[ **-P** ] 
[ **-L** ] 
[ **-s** *severity* ] 
[ **-c** *address* ]
[ **--request-id** ] 
[ **-V** ]

DESCRIPTION
--------------

*krb5-send-pr* is a tool used to submit problem reports (PRs) to a central support site.  
In most cases the correct *site* will be the default.  
This argument indicates the support site which is responsible 
for the category of problem involved.  
Some sites may use a local address as a default.  
*site* values are defined by using the aliases(5).

*krb5-send-pr* invokes an editor on a problem report template 
(after trying to fill in some fields with reasonable default values).  
When you exit the editor, *krb5-send-pr* sends  the completed form 
to the *Problem Report Management System* (**GNATS**) at a central support site.  
At the support site, the PR is assigned a unique number and is stored 
in the GNATS database according to its category and submitter-id.  
GNATS automatically replies with an acknowledgement, 
citing the category and the PR number.

To ensure that a PR is handled promptly, it should contain your (unique) 
*submitter-id* and one of the available *categories* to identify the problem area.
(Use  `krb5-send-pr -L` to see a list of categories.)

The *krb5-send-pr* template at your site should already be customized 
with your *submitter-id* (running `install-sid submitter-id` to accomplish 
this is part of the installation procedures for *krb5-send-pr*).  
If this hasn't been done, see your system administrator for your *submitter-id*, 
or request one from your support site by invoking  `krb5-send-pr --request-id`.  
If your site does not distinguish between different user sites, 
or if you are not affiliated with the support site, use `net` for this field.

The more precise your problem description and the more complete your information, 
the faster your support team can solve your problems.


OPTIONS
---------

**-f** *problem-report*
       Specify a file  *problem-report* which already contains a complete problem report.  
       *krb5-send-pr sends* the contents of the file without invoking the editor.
       If the value for problem-report is "-", then *krb5-send-pr* reads from standard input.

**-s** *severity*
       Give the problem report the severity *severity*.

**-t** *mail-address*
       Change mail address at the support site for problem reports.
       The default mail-address is the address used for the default site.
       Use the site argument rather than this option in nearly all cases.

**-c** *address*
       Put *address* in the *Cc:* header of the message.

**-P**
       Print the form specified by the environment variable *PR_FORM* on standard output.
       If *PR_FORM* is not set, print the standard blank PR template.  No mail is sent.

**-L**
       Print the list of available categories.  No mail is sent.

**--request-id**
       Sends mail to the default support site, or site if specified,
       with a request for your *submitter-id*.
       If you are not affiliated with site, use a *submitter-id* of `net`.

**-V**
       Display the *krb5-send-pr* version number.


.. note:: Use *krb5-send-pr* to submit problem reports rather than mailing them directly.
          Using both the template and *krb5-send-pr* itself will help ensure all
          necessary information will reach the support site.

ENVIRONMENT
------------

The environment variable *EDITOR* specifies the editor to invoke on the template.
Default: *vi*.

If the environment variable *PR_FORM* is set, then its value is used as 
the file name of the template for your problem-report editing session.  
You can use this to start with a partially completed form 
(for example, a form with the identification fields already completed).


HOW TO FILL OUT A PROBLEM REPORT
---------------------------------

Problem reports have to be in a particular form so that a program can 
easily manage them.  Please remember the following guidelines:

    - Describe only one problem with each problem report.

    - For follow-up mail, use the same subject line as the one 
      in the automatic acknowledgent. 
      It consists of category, PR number and the original synopsis line.  
      This allows the support site to relate several mail messages 
      to a particular PR and to record them automatically.

    - Please try to be as accurate as possible in the subject and/or synopsis line.

    - The subject and the synopsis line are not confidential.  
      This is because open-bugs lists are compiled from them.  
      Avoid confidential information there.

See the GNU Info file *krb5-send-pr.info* or the document 
Reporting Problems With *krb5-send-pr* for detailed information on reporting problems.

HOW TO SUBMIT TEST CASES, CODE, ETC.
---------------------------------------

Submit small code samples with the PR.  
Contact the support site for instructions on submitting larger test cases 
and problematic source code.

FILES
----------

/tmp/p$$     copy of PR used in editing session

/tmp/pf$$    copy of empty PR form, for testing purposes

/tmp/pbad$$  file for rejected PRs

EMACS USER INTERFACE
---------------------

An Emacs user interface for *krb5-send-pr* with completion of field values 
is part of the *krb5-send-pr* distribution (invoked with `M-x krb5-send-pr`).  
See the file *krb5-send-pr.info* or the ASCII file INSTALL in the top level 
directory of the distribution for configuration and installation information.  
The Emacs LISP template file is *krb5-send-pr-el.in* and is installed as *krb5-send-pr.el*.


INSTALLATION AND CONFIGURATION
--------------------------------

See *krb5-send-pr.info* or INSTALL for installation instructions.

SEE ALSO
-----------

Reporting Problems Using *krb5-send-pr* (also installed as the GNU Info file *krb5-send-pr.info*).

gnats(l), query-pr(1), edit-pr(1), gnats(8), queue-pr(8), at-pr(8), mkcat(8), mkdist(8).

AUTHORS
-----------

Jeffrey Osier, Brendan Kehoe, Jason Merrill, Heinz G. Seidl (Cygnus Support)

COPYING
--------

Copyright (c) 1992, 1993 Free Software Foundation, Inc.

Permission is granted to make and distribute verbatim copies of this manual 
provided the copyright notice and this permission notice are preserved on all copies.

Permission is granted to copy and distribute modified versions of this manual 
under the conditions for verbatim copying, provided that the entire resulting
derived work is distributed under the terms of a permission notice identical to this one.

Permission  is granted to copy and distribute translations of this manual 
into another language, under the above conditions for modified versions, 
except that this permission notice may be included in translations approved 
by the Free Software Foundation instead of in the original English.


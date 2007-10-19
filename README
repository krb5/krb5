                  Kerberos Version 5, Release 1.6.3

                            Release Notes
                        The MIT Kerberos Team

Unpacking the Source Distribution
---------------------------------

The source distribution of Kerberos 5 comes in a gzipped tarfile,
krb5-1.6.3.tar.gz.  Instructions on how to extract the entire
distribution follow.

If you have the GNU tar program and gzip installed, you can simply do:

        gtar zxpf krb5-1.6.3.tar.gz

If you don't have GNU tar, you will need to get the FSF gzip
distribution and use gzcat:

        gzcat krb5-1.6.3.tar.gz | tar xpf -

Both of these methods will extract the sources into krb5-1.6.3/src and
the documentation into krb5-1.6.3/doc.

Building and Installing Kerberos 5
----------------------------------

The first file you should look at is doc/install-guide.ps; it contains
the notes for building and installing Kerberos 5.  The info file
krb5-install.info has the same information in info file format.  You
can view this using the GNU emacs info-mode, or by using the
standalone info file viewer from the Free Software Foundation.  This
is also available as an HTML file, install.html.

Other good files to look at are admin-guide.ps and user-guide.ps,
which contain the system administrator's guide, and the user's guide,
respectively.  They are also available as info files
kerberos-admin.info and krb5-user.info, respectively.  These files are
also available as HTML files.

If you are attempting to build under Windows, please see the
src/windows/README file.

Reporting Bugs
--------------

Please report any problems/bugs/comments using the krb5-send-pr
program.  The krb5-send-pr program will be installed in the sbin
directory once you have successfully compiled and installed Kerberos
V5 (or if you have installed one of our binary distributions).

If you are not able to use krb5-send-pr because you haven't been able
compile and install Kerberos V5 on any platform, you may send mail to
krb5-bugs@mit.edu.

You may view bug reports by visiting

http://krbdev.mit.edu/rt/

and logging in as "guest" with password "guest".

Major changes in krb5-1.6.3
---------------------------

[5706]  fix CVE-2007-3999, CVE-2007-4743 svc_auth_gss.c buffer overflow
[5707]  fix CVE-2007-4000 modify_policy vulnerability

    The above are two kadmind vulnerabilities described in
    MITKRB5-SA-2007-006.  CVE-2007-3999 is actually a vulnerability in
    the RPC library.

[5617]  Add PKINIT support

    At this point, PKINIT support should be considered to be ALPHA
    code.  APIs and configuration details may change in the future.
    We would greatly appreciate testing and feedback of PKINIT
    support.

krb5-1.6.3 changes by ticket ID
-------------------------------

3334    libkrb5 treats all KDC errors as terminal
4136    kadmin_unlock() calls kadm5_lock() instead of kadm5_unlock()
4950    gc_frm_kdc doesn't adjust use_conf_ktypes in referrals case
5471    krb5_ktfile_get_entry() can invalidate keytab file handle
5542    Optimize file/directory pruning in KfW build script
5548    Look for unix find command in multiple places in KfW build script
5577    MSI Deployment Guide
5581    Build fails in lib/gssapi/spnego
5584    NIM Changes Post KFW 3.2
5604    NIM credential display doesn't update when credential deleted
5607    NIM GUI: Default identity display should not have a background color
5609    NIM watermark does not track tray icon
5613    NIM GUI: views jump around on the screen
5617    Add PKINIT support
5623    NIM: apply does not update saved values of general identities cfg page
5624    krb5_fcc_generate_new() doesn't work with mkstemp()
5625    KRB5_CALLCONV must be specified inside parens
5629    gss_init_sec_context does not release output token buffer when
        used with spnego mech
5636    remove unused src/windows/identity/uilib/Makefile.w2k
5645    export krb5_get_profile
5653    compilation failure with IRIX native compiler
5666    read_entropy_from_device on partial read will not fill buffer
5673    NIM: resource leak in khui_action_trigger()
5674    NIM: Identity Configuration Panel Fixes
5675    NIM: New command-line options --hide and --show / new
        command-line help dialog
5676    NIM: APP: Redesigned Color Schemas
5677    NIM: BUG: APP: Identity right click selection failure and
        context menu keyboard events were ignored
5678    NIM: BUG: APP: WM_TIMER messages if received after timer event
        is canceled results in invalid data access
5679    NIM: BUG: APP: Filler columns should not be resizeable
5680    NIM: BUG: APP: WM_PAINT messages received without update
        regions results in incorrect window repainting behavior
5681    NIM: BUG: APP: Fix Cursor Position and Selection Usability Issues
5682    NIM: remove unused code from ui/credwnd.c
5683    NIM: support include files in schemas
5684    NIM: Keep API release documentation up to date
5685    NIM: FEATURE: API: Add Identity Provider Pre-Process Message
        to trigger immediate identity selection
5686    NIM: BUG: LIB: khcint_remove_space() frees memory too soon
        resulting in potential invalid memory access
5687    NIM: BUG: KRB5: External changes to default identity ccache
        are improperly reflected by krb5 provider
5688    NIM: Reposition New Credentials Dialog if necessary
5689    NIM: BUG: APP: Revert ticket 5604
5690    NIM: version update
5692    KFW: KFWLOGON: avoid missing symbol errors when building with
        VS 2005
5696    NIM: FEATURE: ALL: 64-bit Windows Support and Removal of
        Compile Time Warnings
5697    make ccache handle referrals better
5698    Windows: Add support for 64-bit CCAPI DLL name: krbcc64s.exe
5700    -S sname option for kvno
5701    NIM: APP: remove unused preprocessor symbols from resource files
5702    NIM: LIB: a small source code readability change
5703    NIM: BUG: KRB5: FILE ccache support did not make use of
        OPENCLOSE flags
5704    new warnings in pkinit code (patch needs review)
5705    GSS-API Win64 support: Access Leash API via leashw64.dll
5706    fix CVE-2007-3999, CVE-2007-4743 svc_auth_gss.c buffer overflow
5707    fix CVE-2007-4000 modify_policy vulnerability
5708    krb5_fcc_generate_new is non-functional
5710    Build 64-bit Windows gss.exe (gui version of gss-client.exe)
        now that 64-bit CCAPI is available
5711    KFW: Add MSI installer for 64-bit AMD64
5713    64-bit Windows krb5int_cc_default calls to Leash API must use
        leashw64.dll
5719    NIM: FEATURE: APP: Add View->All Identities
5724    NIM: FEATURE: APP: Add Notification Icon Default Identity Context Menu
5751    KFW: permit administrative installs using MSI installation package
5753    NIM: BUG: APP: Do not report errors for modules that are not installed
5756    NIM: BUG: SRC: Windows\Identity Makefile "clean" more
5759    NIM: APP: BUG: restore HideWatermark functionality
5763    NIM: BUG: khm_krb5_initialize() failed to return error code
5764    NIM: BUG: Restore Copyright removed in revision 19855
5766    MSLSA krb5_cc module fails to check success of UNICODE string
        conversions
5768    set svn:eol-style property on a bunch of files
5772    NIM: BUG: SRC: Increase size of max ccache name buffers and
        remove extraneous trailing path component separators
5773    NIM: BUG: KMM: Ensure proper buffer length for registry
        multi-string reads; avoid error reports for modules without
        config data; avoid race when sending thread quit message
5779    NIM: BUG: LIB: optimize khui_find_action()
5780    NIM: FEATURE: APP: Notification Icon Tooltip now includes
        default identity name
5782    NIM: APP: BUG: Initial cursor position does not track selected identity
5783    NIM: APP: BUG: Identities without identity credentials are
        listed as having credentials
5787    NIM: BUG: APP: Spell Check
5788    NIM: BUG: APP: Provide keyboard accelerator for switching
        between advanced and basic obtain new credentials dialog modes
5789    NIM: documentation updates for KFW 3.2.2
5790    NIM: SRC: disable potential uninitialized variable warning
5791    Add static ordinals to DLL exports
5792    NIM: BUG: LIB: deadlock in kmq
5793    NIM: BUG: APP: leaking prompts in obtain new credentials dialog
5794    NIM: BUG: APP: Change View->Choose Columns to View->Select
        Columns to match standard windows style
5795    NIM: BUG: APP: store credential type in the correct field of
        the khui_credwnd_identity structure
5796    NIM: BUG: APP: change notification icon state to track default
        identity only
5797    NIM: BUG: APP: notification icon tooltip wrong string
5798    NIM: BUG: APP: command-line options window doesn't process
        WM_CLOSE messages
5800    krb5_get_init_creds_opt_alloc needs to initialize the opt structure
5801    remove error tables by pointer
5802    libgssapi mechglue doesn't always store delegated credentials
5803    fix pkinit module deps for krb5-1.6.x
5808    KfW Build: add new installer build files to copyfiles.xml.
5809    NIM: BUG: APP: New edit controls should be marked ES_AUTOHSCROLL
5820    KFW: BUG: WIX: Improve Usability of multiple architecture MSI
        installations, remove non-unique GUID component identifiers,
        and include Beta ID in the package name
5823    KFW: BUG: WIX: Beta value hard coded

Major changes in krb5-1.6.2
---------------------------

[5585]  fix MITKRB5-SA-2007-004: kadmind affected by multiple RPC
        library vulnerabilities [CVE-2007-2442/VU#356961,
        CVE-2007-2443/VU#365313]
[5586]  fix MITKRB5-SA-2007-005: kadmind vulnerable to buffer overflow
         [CVE-2007-2798/VU#554257]

krb5-1.6.2 changes by ticket ID
-------------------------------

5541    remove debugging code accidentally left in ftp/cmds.c
5546    race condition in referrals fallback
5547    profile stores empty string values without double quotes
5551    rd_req_decoded needs to deal with referral realms
5552    minor incompatability krb5-1.6.1 and OpenSSH_4.6p1, OpenSSL 0.9.8e
5554    Modify WIX installer to better support upgrading betas
5573    Kfw 3.2.0.msi is missing a file krb5/krb5.h
5579    krb5_walk_realm_tree leaks in capaths case
5585    fix MITKRB5-SA-2007-004 [CVE-2007-2442/VU#356961,
        CVE-2007-2443/VU#365313]
5586    fix MITKRB5-SA-2007-005 [CVE-2007-2798/VU#554257]

Major changes in krb5-1.6.1
---------------------------

[5508]  Fix MITKRB5-SA-2007-001: telnetd allows login as arbitrary user
        [CVE-2007-0956, VU#220816]

[5507]  Fix MITKRB5-SA-2007-002: buffer overflow in krb5_klog_syslog
        [CVE-2007-0957, VU#704024]

[5445]  Fix MITKRB5-SA-2007-003: double-free in kadmind - the RPC
        library could perform a double-free due to a GSS-API library
        bug [CVE-2007-1216, VU#419344]

[5293]  fix crash creating db2 database in non-existent directory

krb5-1.6.1 changes by ticket ID
-------------------------------

Listed below are the RT tickets of bugs fixed in krb5-1.6.1.  Please see

http://krbdev.mit.edu/rt/NoAuth/krb5-1.6/fixed-1.6.1.html

for a current listing with links to the complete tickets.

2724    kdc.conf man page typo in v4_mode section
5233    Change in behaviour in gss_release_buffer() by mechtypes
        introduces memory leak
5238    fix leak in gss_krb5int_unseal_token_v3
5246    Memory leak in tests/gssapi/t_imp_name.c
5257    error on gethostbyname is tested on errno instead of h_errno
5293    crash creating db2 database in non-existent directory
5294    create KDC database directory
5343    updated Windows README
5344    Update to KFW NSIS installer
5349    Proposed implementation of krb5_server_decrypt_ticket_keyblock
        and krb5_server_decrypt_ticket_keytab
5353    kfw wix installer - memory overwrite error
5393    krb5-1.6: tcp kpasswd service required if only admin_server is
        specified in krb5.conf
5394    krb5-1.6: segfault on password change
5396    Master ticket for NetIdMgr 1.2 commits
5397    NIM string tables
5398    NIM Kerberos v4 configuration dialog
5399    NIM Correct Visual Identity Expiration Status
5400    NIM Kerberos 5 Provider corrections
5403    Add KDC timesyncing support to the CCAPI ccache backend
5408    NIM - Context sensitive system tray menu and more
5409    KFW MSI installer corrections
5410    kt_file.c memory leak on error in krb5_kt_resolve /
        krb5_kt_wresolve
5414    NIM Bug Fixes
5418    KFW: 32-bit builds use the pismere krbv4w32.dll library
5419    Microsoft Windows Visual Studio does not define ssize_t
5420    get_init_creds_opt extensibility
5437    hack to permit GetEnvironmentVariable usage without requiring
        getenv() conversion
5445    gsstest doesn't like krb5-1.6 GSSAPI library
        [also MITKRB5-SA-2007-003]
5446    KfW 3.1: stderr of kinit/klist/kdestroy cannot be re-directed
        to file
5447    tail portability bug in k5srvutil
5452    NIM Improved Alert Management
5453    Windows - some apps define ssize_t as a preprocessor symbol
5454    krb5_get_cred_from_kdc fails to null terminate the tgt list
5455    valgrind detects uninitialized (but really unused) bytes in
        'queue'
5457    More existence tests; path update
5458    osf1: get proper library dependencies installed
5461    reverting commit to windows WIX installer (revision 19207)
5469    KFW: Vista Integrated Logon
5476    Zero sockaddrs in fai_add_entry() so we can compare them with
        memcmp()
5477    Enable Vista support for MSLSA
5478    NIM: New Default View and miscellaneous fixes
5480    krb5 library uses kdc.conf when it shouldn't
5490    KfW build automation
5491    WIX installer stores WinLogon event handler under wrong
        registry value
5492    remove unwanted files from kfw build script
5493    KFW: problems with non-interactive logons
5495    NIM commits for KFW 3.2 Beta 1
5496    more bug fixes for NIM 1.2 (KFW 3.2)
5503    msi deployment guide updates for KFW 3.2
5504    Network Identity Manager 1.2 User Manual
5505    More commits for NIM 1.2 Beta 1
5507    MITKRB5-SA-2007-002: buffer overflow in krb5_klog_syslog
5508    MITKRB5-SA-2007-001: telnetd allows login as arbitrary user
5509    service location plugin returning no addresses handled
        incorrectly
5510    krb5int_open_plugin_dirs errors out if directory does not
        exist
5514    wix installer - modify file list
5515    KFW NSIS installer - copyright updates and aklog removal
5516    NIM 1.2.0.1 corrections
5518    EAI_NODATA deprecated, not always defined
5521    KfW build system (post kfw-3.2-beta1)
5522    NIM 3.2 documentation update
5523    KFW 3.2 Beta 2 commits
5524    NIM doxyfile.cfg - update to Doxygen 1.5.2
5525    NIM 1.2 HtmlHelp User Documentation
5526    NIM - Fix taskbar button visibility on Vista
5527    kfw build - include netidmgr_userdoc.pdf in zip file
5528    Add vertical scrollbars to realm fields in dialogs
5529    Missing version resource info on krb5 files
5530    KFW 3.2.0.7002 about dialogue will not respond to alt-f4
5532    KFW Network Provider Improvements
5533    updates for NIM developer documentation
5534    kfwlogon corrections for XP
5535    More NIM Developer documentation updates
5537    only check current dir for a.tmp
5539    add option to export instead of checkout, etc.

Major changes in krb5-1.6
-------------------------

* Partial client implementation to handle server name referrals.

* Pre-authentication plug-in framework, donated by Red Hat.

* LDAP KDB plug-in, donated by Novell.

* Fix for MITKRB5-SA-2006-002: the RPC library could call an
  uninitialized function pointer, which created a security
  vulnerability for kadmind.

* Fix for MITKRB5-SA-2006-003: the GSS-API mechglue layer could fail
  to initialize some output pointers, causing callers to attempt to
  free uninitialized pointers.  This caused a security vulnerability
  in kadmind.

Note that the implementation of referral handling involves a change to
the behavior of krb5_sname_to_principal() to return a zero-length
realm name if it is unable to find the realm corresponding to the
hostname.  This special realm name signals the ticket-acquisition code
to request KDC canonicalization of service principal names.  Other
library code has changed to accommodate this new behavior.  This
particular method of implementing service principal name referral
handling may change in the future; we invite discussion on this
subject.

Major known bugs in krb5-1.6
----------------------------

5293    crash creating db2 database in non-existent directory

  Attempting to create a KDB in a non-existent directory using the
  Berkeley DB back end may cause a crash resulting from a null pointer
  dereference.  If a core dump occurs, this may cause a local exposure
  of sensitive information such a master key password.  This will be
  fixed in an upcoming patch release.

krb5-1.6 changes by ticket ID
-----------------------------

Listed below are the RT tickets of bugs fixed in krb5-1.6.  Please see

http://krbdev.mit.edu/rt/NoAuth/krb5-1.6/fixed-1.6.html

for a current listing with links to the complete tickets.

1204    Unable to get a TGT cross-realm referral
2087    undocumented options for kpropd
2240    krb5-config --cflags gssapi when used by OpenSSH-snap-20040212
2579    kdc: add_to_transited may reference off end of array...
2652    Add support for referrals
2876    Tree does not compile with GCC 4.0
2935    KDB/LDAP backend
3089    krb5_verify_init_creds() is not thread safe
3091    add krb5_cc_new_unique()
3218    kdb5_util load requires that the dumpfile be writable.
3276    local array of structures not declared static
3288    NetIdMgr cannot obtain Kerberos 5 tickets containing addresses
3322    get_cred_via_tkt() checks too strict on server principal
3522    Error code definitions are outside macros to prevent multiple
        inclusion in public headers
3642    changes for embedding manifest into dlls and exes
3735    Add TCP change/set password support
3947    allow multiple calls to krb5_get_error_message to retrieve message
3955    check calling conventions specified for Windows
3961    fix stdcc.c to build without USE_CCAPI_V3
4021    use GSS_C_NO_CHANNEL_BINDINGS not NULL in lib/rpc/auth_gss.c
4023    Turn off KLL automatic prompting support in kadmin
4024    gss_acquire_cred auto prompt support shouldn't break
        gss_krb5_ccache_name()
4025    need to look harder for tclConfig.sh
4055    remove unused Metrowerks support from yarrow
4056    g_canon_name.c if-statement warning cleanup
4057    GSSAPI opaque types should be pointers to opaque structs, not void*
4256    Make process error
4292    LDAP error prevents KfM 6.0 from building on Tiger
4294    Bad loop logic in krb5_mcc_generate_new
4304    audit referrals merge (R18598)
4327    doc/krb5-protocol out of date
4389    cursor for iterating over ccaches
4412    Don't segfault if a preauth plugin module fails to load
4453    krb5-1.6-pre: fix warnings/ improve 64bit compatibility in the
        ldap plugin
4454    krb5-1.6-pre: kdb5_ldap_util stashsrvpw does not work
4455    IRIX build fails w/ GCC 4.0 (really GNU ld)
4482    enabling LDAP mix-in support for kdb5_util load
4488    osf1 -oldstyle_liblookup typo
4495    Avoid segfault in krb5_do_preauth_tryagain
4496    fix invalid access found by valgrind
4501    fix krb5_ldap_iterate to handle NULL match_expr and
        open_db_and_mkey to use KRB5_KDB_SRV_TYPE_ADMIN
4534    don't confuse profile iterator in 425 princ conversion
4561    UC Berkeley BSD license change
4562    latest Novell ldap patches and kdb5_util dump support for ldap
4566    leaks in preauth plugin support
4567    KDC can crash for certain client requests when preauth plugins
        are used
4587    Change preauth plugin context scope and lifetimes
4624    remove t_prf and t_prf.o on make clean
4625    Make clean in lib/kdb leaves error table files
4657    krb5.h not C++-safe due to "struct krb5_cccol_cursor"
4683    Remove obsolete/conflicting prototype for krb524_convert_princs
4688    Add public function to get keylength associated with an enctype
4689    Update minor version numbers for 1.6
4690    Add "get_data" function to the client preauth plugin interface
4692    Document changing the krbtgt key
4693    Delay kadmind random number initialization until after fork
4735    more Novell ldap patches from Nov 6 and Fix for wrong password
        policy reference count
4737    correct client preauth plugin request_context
4738    allow server preauth plugin verify_padata function to return e-data
4739    cccursor backend for CCAPI
4755    update copyrights and acknowledgments
4770    Add macros for __attribute__((deprecated)) for krb4 and des APIs
4771    LDAP patch from Novell, 2006-10-13
4772    fix some warnings in ldap code
4773    fix warning in preauth_plugin.h header
4774    avoid double frees in ccache manipulation around gen_new
4775    include realm in "can't resolve KDC" error message
4784    krb5_stdccv3_generate_new returns NULL ccache
4788    ccache double free in krb5_fcc_read_addrs().
4799    krb5_c_keylength -> krb5_c_keylengths; add krb5_c_random_to_key
4805    replace existing calls of cc_gen_new()
4841    free error message when freeing context
4846    clean up preauth2 salt debug code
4860    fix LDAP plugin Makefile.in lib frag substitutions
4928    krb5int_copy_data_contents shouldn't free memory it didn't allocate
4941    referrals changes to telnet have unconditional debugging printfs
4942    skip all modules in plugin if init function fails
4955    Referrals code breaks krb5_set_password_using_ccache to Active
        Directory
4967    referrals support assumes all rewrites produce TGS principals
4972    return edata from non-PA_REQUIRED preauth types
4973    send a new request with the new padata returned by
        krb5_do_preauth_tryagain()
4980    Remove unused prototype for krb5_find_config_files
4981    Make clean in lib/krb5/os does not clean test objs
4991    fix for kdb5_util load bug with dumps from a LDAP KDB
4994    minor update to kdb5_util man page for LDAP plugin
5003    krb5_cc_remove should work for the CCAPI
5005    Reading maxlife, maxrenewlife and ticket flags from conf file
        in LDAP plugin
5009    kadmin.local with LDAP backend fails to start when master key
        enctype is not default enctype
5022    build the trunk on Windows (again)
5027    admin guide changes for the LDAP backend
5032    Don't leak padata when looping for krb5_do_preauth_tryagain()
5090    krb5_get_init_creds_opt_set_change_password_prompt
5115    krb5_rc_io_open_internal on error will call close(-1)
5116    minor ldap specific changes in man page
5121    keytab code can't match principals with realms not yet determined
5123    don't pass null pointer to krb5_do_preauth_tryagain()
5124    use KRB5KRB_ERR_GENERIC, not KRB_ERR_GENERIC in preauth2.c
5125    Add -clearpolicy to kadmin addprinc usage
5152    misc cleanups in admin guide ldap sections
5159    don't split HTML output from makeinfo
5223    Fix typo in user-guide.texinfo
5245    Repair broken links in NetIdMgr Help
5260    Deletion of principal fails
5265    update ldap/Makefile.in for newer autoconf substitution requirements
5271    Document KDC behavior without stash file
5279    Document what the kadmind ACL is for
5301    MITKRB5-SA-2006-002: svctcp_destroy() can call uninitialized function pointer
5302    MITKRB5-SA-2006-003: mechglue argument handling too lax

Copyright and Other Legal Notices
---------------------------------

Copyright (C) 1985-2007 by the Massachusetts Institute of Technology.

All rights reserved.

Export of this software from the United States of America may require
a specific license from the United States Government.  It is the
responsibility of any person or organization contemplating export to
obtain such a license before exporting.

WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
distribute this software and its documentation for any purpose and
without fee is hereby granted, provided that the above copyright
notice appear in all copies and that both that copyright notice and
this permission notice appear in supporting documentation, and that
the name of M.I.T. not be used in advertising or publicity pertaining
to distribution of the software without specific, written prior
permission.  Furthermore if you modify this software you must label
your software as modified software and not distribute it in such a
fashion that it might be confused with the original MIT software.
M.I.T. makes no representations about the suitability of this software
for any purpose.  It is provided "as is" without express or implied
warranty.

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.

Individual source code files are copyright MIT, Cygnus Support,
Novell, OpenVision Technologies, Oracle, Red Hat, Sun Microsystems,
FundsXpress, and others.

Project Athena, Athena, Athena MUSE, Discuss, Hesiod, Kerberos, Moira,
and Zephyr are trademarks of the Massachusetts Institute of Technology
(MIT).  No commercial use of these trademarks may be made without
prior written permission of MIT.

"Commercial use" means use of a name in a product or other for-profit
manner.  It does NOT prevent a commercial firm from referring to the
MIT trademarks in order to convey information (although in doing so,
recognition of their trademark status should be given).

                         --------------------

Portions of src/lib/crypto have the following copyright:

  Copyright (C) 1998 by the FundsXpress, INC.

  All rights reserved.

  Export of this software from the United States of America may require
  a specific license from the United States Government.  It is the
  responsibility of any person or organization contemplating export to
  obtain such a license before exporting.

  WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
  distribute this software and its documentation for any purpose and
  without fee is hereby granted, provided that the above copyright
  notice appear in all copies and that both that copyright notice and
  this permission notice appear in supporting documentation, and that
  the name of FundsXpress. not be used in advertising or publicity pertaining
  to distribution of the software without specific, written prior
  permission.  FundsXpress makes no representations about the suitability of
  this software for any purpose.  It is provided "as is" without express
  or implied warranty.

  THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
  WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.


                         --------------------

The following copyright and permission notice applies to the
OpenVision Kerberos Administration system located in kadmin/create,
kadmin/dbutil, kadmin/passwd, kadmin/server, lib/kadm5, and portions
of lib/rpc:

  Copyright, OpenVision Technologies, Inc., 1996, All Rights Reserved

  WARNING: Retrieving the OpenVision Kerberos Administration system 
  source code, as described below, indicates your acceptance of the 
  following terms.  If you do not agree to the following terms, do not 
  retrieve the OpenVision Kerberos administration system.

  You may freely use and distribute the Source Code and Object Code
  compiled from it, with or without modification, but this Source
  Code is provided to you "AS IS" EXCLUSIVE OF ANY WARRANTY,
  INCLUDING, WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY OR
  FITNESS FOR A PARTICULAR PURPOSE, OR ANY OTHER WARRANTY, WHETHER
  EXPRESS OR IMPLIED.  IN NO EVENT WILL OPENVISION HAVE ANY LIABILITY
  FOR ANY LOST PROFITS, LOSS OF DATA OR COSTS OF PROCUREMENT OF 
  SUBSTITUTE GOODS OR SERVICES, OR FOR ANY SPECIAL, INDIRECT, OR
  CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, INCLUDING, 
  WITHOUT LIMITATION, THOSE RESULTING FROM THE USE OF THE SOURCE 
  CODE, OR THE FAILURE OF THE SOURCE CODE TO PERFORM, OR FOR ANY 
  OTHER REASON.

  OpenVision retains all copyrights in the donated Source Code. OpenVision
  also retains copyright to derivative works of the Source Code, whether
  created by OpenVision or by a third party. The OpenVision copyright 
  notice must be preserved if derivative works are made based on the 
  donated Source Code.

  OpenVision Technologies, Inc. has donated this Kerberos 
  Administration system to MIT for inclusion in the standard 
  Kerberos 5 distribution.  This donation underscores our 
  commitment to continuing Kerberos technology development 
  and our gratitude for the valuable work which has been 
  performed by MIT and the Kerberos community.

                         --------------------

  Portions contributed by Matt Crawford <crawdad@fnal.gov> were
  work performed at Fermi National Accelerator Laboratory, which is
  operated by Universities Research Association, Inc., under
  contract DE-AC02-76CHO3000 with the U.S. Department of Energy.

                         --------------------

The implementation of the Yarrow pseudo-random number generator in
src/lib/crypto/yarrow has the following copyright:

  Copyright 2000 by Zero-Knowledge Systems, Inc.

  Permission to use, copy, modify, distribute, and sell this software
  and its documentation for any purpose is hereby granted without fee,
  provided that the above copyright notice appear in all copies and that
  both that copyright notice and this permission notice appear in
  supporting documentation, and that the name of Zero-Knowledge Systems,
  Inc. not be used in advertising or publicity pertaining to
  distribution of the software without specific, written prior
  permission.  Zero-Knowledge Systems, Inc. makes no representations
  about the suitability of this software for any purpose.  It is
  provided "as is" without express or implied warranty.

  ZERO-KNOWLEDGE SYSTEMS, INC. DISCLAIMS ALL WARRANTIES WITH REGARD TO
  THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
  FITNESS, IN NO EVENT SHALL ZERO-KNOWLEDGE SYSTEMS, INC. BE LIABLE FOR
  ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT
  OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

                         --------------------

The implementation of the AES encryption algorithm in
src/lib/crypto/aes has the following copyright:

  Copyright (c) 2001, Dr Brian Gladman <brg@gladman.uk.net>, Worcester, UK.
  All rights reserved.

  LICENSE TERMS

  The free distribution and use of this software in both source and binary 
  form is allowed (with or without changes) provided that:

    1. distributions of this source code include the above copyright 
       notice, this list of conditions and the following disclaimer;

    2. distributions in binary form include the above copyright
       notice, this list of conditions and the following disclaimer
       in the documentation and/or other associated materials;

    3. the copyright holder's name is not used to endorse products 
       built using this software without specific written permission. 

  DISCLAIMER

  This software is provided 'as is' with no explcit or implied warranties
  in respect of any properties, including, but not limited to, correctness 
  and fitness for purpose.

                         --------------------

Portions contributed by Red Hat, including the pre-authentication
plug-ins framework, contain the following copyright:

  Copyright (c) 2006 Red Hat, Inc.
  Portions copyright (c) 2006 Massachusetts Institute of Technology
  All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  * Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials provided
    with the distribution.

  * Neither the name of Red Hat, Inc., nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

                         --------------------

The implementations of GSSAPI mechglue in GSSAPI-SPNEGO in
src/lib/gssapi, including the following files:

  lib/gssapi/generic/gssapi_err_generic.et
  lib/gssapi/mechglue/g_accept_sec_context.c
  lib/gssapi/mechglue/g_acquire_cred.c
  lib/gssapi/mechglue/g_canon_name.c
  lib/gssapi/mechglue/g_compare_name.c
  lib/gssapi/mechglue/g_context_time.c
  lib/gssapi/mechglue/g_delete_sec_context.c
  lib/gssapi/mechglue/g_dsp_name.c
  lib/gssapi/mechglue/g_dsp_status.c
  lib/gssapi/mechglue/g_dup_name.c
  lib/gssapi/mechglue/g_exp_sec_context.c
  lib/gssapi/mechglue/g_export_name.c
  lib/gssapi/mechglue/g_glue.c
  lib/gssapi/mechglue/g_imp_name.c
  lib/gssapi/mechglue/g_imp_sec_context.c
  lib/gssapi/mechglue/g_init_sec_context.c
  lib/gssapi/mechglue/g_initialize.c
  lib/gssapi/mechglue/g_inquire_context.c
  lib/gssapi/mechglue/g_inquire_cred.c
  lib/gssapi/mechglue/g_inquire_names.c
  lib/gssapi/mechglue/g_process_context.c
  lib/gssapi/mechglue/g_rel_buffer.c
  lib/gssapi/mechglue/g_rel_cred.c
  lib/gssapi/mechglue/g_rel_name.c
  lib/gssapi/mechglue/g_rel_oid_set.c
  lib/gssapi/mechglue/g_seal.c
  lib/gssapi/mechglue/g_sign.c
  lib/gssapi/mechglue/g_store_cred.c
  lib/gssapi/mechglue/g_unseal.c
  lib/gssapi/mechglue/g_userok.c
  lib/gssapi/mechglue/g_utils.c
  lib/gssapi/mechglue/g_verify.c
  lib/gssapi/mechglue/gssd_pname_to_uid.c
  lib/gssapi/mechglue/mglueP.h
  lib/gssapi/mechglue/oid_ops.c
  lib/gssapi/spnego/gssapiP_spnego.h
  lib/gssapi/spnego/spnego_mech.c

are subject to the following license:

  Copyright (c) 2004 Sun Microsystems, Inc.

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

                         --------------------

MIT Kerberos includes documentation and software developed at the
University of California at Berkeley, which includes this copyright
notice:

  Copyright (C) 1983 Regents of the University of California.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS "AS IS" AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGE.

                         --------------------

Portions contributed by Novell, Inc., including the LDAP database
backend, are subject to the following license:

  Copyright (c) 2004-2005, Novell, Inc.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.
    * The copyright holder's name is not used to endorse or promote products
        derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

                         --------------------

Portions funded by Sandia National Laboratory and developed by the
University of Michigan's Center for Information Technology
Integration, including the PKINIT implementation, are subject to the
following license:

  COPYRIGHT (C) 2006-2007
  THE REGENTS OF THE UNIVERSITY OF MICHIGAN
  ALL RIGHTS RESERVED

  Permission is granted to use, copy, create derivative works
  and redistribute this software and such derivative works
  for any purpose, so long as the name of The University of
  Michigan is not used in any advertising or publicity
  pertaining to the use of distribution of this software
  without specific, written prior authorization.  If the
  above copyright notice or any other identification of the
  University of Michigan is included in any copy of any
  portion of this software, then the disclaimer below must
  also be included.

  THIS SOFTWARE IS PROVIDED AS IS, WITHOUT REPRESENTATION
  FROM THE UNIVERSITY OF MICHIGAN AS TO ITS FITNESS FOR ANY
  PURPOSE, AND WITHOUT WARRANTY BY THE UNIVERSITY OF
  MICHIGAN OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING
  WITHOUT LIMITATION THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
  REGENTS OF THE UNIVERSITY OF MICHIGAN SHALL NOT BE LIABLE
  FOR ANY DAMAGES, INCLUDING SPECIAL, INDIRECT, INCIDENTAL, OR
  CONSEQUENTIAL DAMAGES, WITH RESPECT TO ANY CLAIM ARISING
  OUT OF OR IN CONNECTION WITH THE USE OF THE SOFTWARE, EVEN
  IF IT HAS BEEN OR IS HEREAFTER ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGES.

                         --------------------

The pkcs11.h file included in the PKINIT code has the following
license:

  Copyright 2006 g10 Code GmbH
  Copyright 2006 Andreas Jellinghaus

  This file is free software; as a special exception the author gives
  unlimited permission to copy and/or distribute it, with or without
  modifications, as long as this notice is preserved.

  This file is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY, to the extent permitted by law; without even
  the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
  PURPOSE.

Acknowledgments
---------------

Thanks to Red Hat for donating the pre-authentication plug-in
framework.

Thanks to Novell for donating the KDB abstraction layer and the LDAP
database plug-in.

Thanks to Sun Microsystems for donating their implementations of
mechglue and SPNEGO.

Thanks to iDefense for notifying us about the vulnerability in
MITKRB5-SA-2007-002.

Thanks to the CITI group at the University of Michigan for
contributing the implementation of PKINIT.

Thanks to Tenable Network Security and 3Com's Zero Day Initiative for
discovering CVE-2007-3999.  Thanks to Kevin Coffman (UMich), Will
Fiveash (Sun), and Nico Williams (Sun) for help with developing the
revised patch.

Thanks to Garrett Wollman of MIT CSAIL for discovering CVE-2007-4000.

Thanks to the members of the Kerberos V5 development team at MIT, both
past and present: Danilo Almeida, Jeffrey Altman, Justin Anderson,
Richard Basch, Jay Berkenbilt, Mitch Berger, Andrew Boardman, Joe
Calzaretta, John Carr, Don Davis, Alexandra Ellwood, Nancy Gilman,
Matt Hancher, Sam Hartman, Paul Hill, Marc Horowitz, Eva Jacobus,
Miroslav Jurisic, Barry Jaspan, Geoffrey King, Kevin Koch, John Kohl,
Peter Litwack, Scott McGuire, Kevin Mitchell, Cliff Neuman, Paul Park,
Ezra Peisach, Chris Provenzano, Ken Raeburn, Jon Rochlis, Jeff
Schiller, Jen Selby, Brad Thompson, Harry Tsai, Ted Ts'o, Marshall
Vale, Tom Yu.

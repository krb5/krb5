Subject: Kerberos file renaming for short DOS names
Date: Tue, 19 Apr 1994 13:34:28 -0700
From: John Gilmore <gnu@cygnus.com>

[edited since sending, to bring it up to date with what actually happened.]

I'd like to come up with some file naming and configuration
conventions that will work in DOS, Unix, and Mac environments.  At
Cygnus, we are creating a single freely available K4 source tree that
works on many Unixes, Windows, and Mac.  It currently works on Unixes.
(To get a copy, send mail to info@cygnus.com requesting our Kerberos
release.  It's in a hidden FTP location due to export control.)

I diffed the current MIT release of Kerberos for PC and Windows
against the V4 patchlevel 10 release, and identified some 30 files in
lib/krb that have been renamed between Unix and PC.  Comparing source
trees becomes much more painful when files are renamed.  If we don't
come to sync on the file names, it will be very hard to collaborate,
which would make more work for all of us.

My plan, which we have used successfully in the GNU software, is to
make sure that all filenames are unique if you take the first 8 chars
and the first 3 after the dot.  No files have more than a single dot
in them.  We don't restrict file names to just 8.3 characters, since
doing so would impact readability for the (99.9%) of the developers
who are on Unix or Mac, where long file names are fine.

There's an additional complication that names longer than 14
characters present problems to old System V Unix and to `ar' on Unix.
DJ Delorie's excellent `doschk' program points out all these problems.
(prep.ai.mit.edu:/pub/gnu/doschk-1.1.tar.gz).

Here's my proposal for the lib/krb directory.  In general, I tried to
regularize the names, turning get_ into g_, removing krb_, turning
reply into repl, turning ticket into tkt, keeping all file names
unique across the various libraries, and making a file name more like
the function name contained in it when there were conflicts.  Some
resulting truncated names are more readable than in the current MIT K4
PC, some are less readable -- but the overall advantage is that the
new names should be acceptable to Unix/Mac developers, while the old
ones weren't.

  MIT K4 patch10	MIT K4 PC	PROPOSED NAME	(trunc to 8.3)	old Cyg
$1     $2		$3		$4		$5		$6

@ add_ticket.c		(gone)		add_tkt.c	add_tkt.c	
@ -			-		ChangeLog	changelo
@ cr_err_reply.c	crerrep.c	cr_err_repl.c	cr_err_r.c
@ create_auth_reply.c	crauthre.c	cr_auth_repl.c	cr_auth_.c	cr_auth_reply.c
@ create_ciph.c		cr_ciph.c	cr_ciph.c	cr_ciph.c
@ create_death_packet.c	cr_death.c	cr_death_pkt.c	cr_death.c	cr_death_pkt.c
@ create_ticket.c	crticket.c	cr_tkt.c	cr_tkt.c
@ debug_decl.c		debug.c		debug.c		debug.c
@ decomp_ticket.c	decomtkt.c	decomp_tkt.c	decomp_t.c
@ -			-		DNR.c		dnr.c
@ extract_ticket.c	ext_tkt.c	ext_tkt.c	ext_tkt.c	extract_tkt.c
@ -			-		g_cnffile.c	g_cnffil.c
@ get_ad_tkt.c		getadtkt.c	g_ad_tkt.c	g_ad_tkt.c
@ get_admhst.c		getadmhs.c	g_admhst.c	g_admhst.c
@ get_cred.c		get_cred.c	g_cred.c	g_cred.c
@ get_in_tkt.c		getintkt.c	g_pw_in_tkt.c	g_pw_in_.c
@ get_krbhst.c		getkrbhs.c	g_krbhst.c	g_krbhst.c
@ get_krbrlm.c		g_krbrlm.c	g_krbrlm.c	g_krbrlm.c
@ get_phost.c		getphost.c	g_phost.c	g_phost.c
@ get_pw_tkt.c		getpwtkt.c	g_pw_tkt.c	g_pw_tkt.c
@ get_request.c		get_req.c	(gone)		(gone)
@ get_svc_in_tkt.c	g_svctkt.c	g_svc_in_tkt.c	g_svc_in.c	get_svc_in.c
@ get_tf_fullname.c	gettfnam.c	g_tf_fname.c	g_tf_fna.c	get_tf_fname.c
@ get_tf_realm.c	gettfrlm.c	g_tf_realm.c	g_tf_rea.c
@ -			-		g_tkt_svc.c	g_tkt_sv.c
@ getrealm.c		getrealm.c	realmofhost.c	realmofh.c
@ k_gethostname.c	k_gethst.c	gethostname.c	gethostn.c
@ kname_parse.c		knm_pars.c	kname_parse.c	kname_pa.c
@ krb_err_txt.c		k_errtxt.c	err_txt.c	err_txt.c
@ krb_get_in_tkt.c	k_gettkt.c	g_in_tkt.c	g_in_tkt.c	krb_get_in.c
@ -			-		mac_store.c	mac_stor.c
@ -			-		mac_store.h	mac_stor.h
@ -			-		mac_stubs.c	mac_stub.c
@ -			-		Makefile.in	makefile.in
@ -			-		mk_preauth.c	mk_preau.c
@ month_sname.c		mth_snam.c	month_sname.c	month_sn.c
@ pkt_cipher.c		pkt_ciph.c	pkt_cipher.c	pkt_ciph.c
@ -			-		Password.c	password.c
@ -			-		rd_preauth.c	rd_preau.c
@ -			-		put_svc_key.c	put_svc_.c
@ read_service_key.c	rdservky.c	rd_svc_key.c	rd_svc_k.c	read_svc_key.c
@ save_credentials.c	savecred.c	save_creds.c	save_cre.c	save_creds.c
@ send_to_kdc.c		send_kdc.c	send_to_kdc.c	send_to_.c
@ strcasecmp.c		s_cascmp.c	strcasecmp.c	strcasec.c
@ tkt_string.c		tkt_strg.c	tkt_string.c	tkt_stri.c
@ -			-		unix_glue.c	unix_glu.c
@ util.c		util.c		ad_print.c	ad_print.c
@ -			-		win_store.c	win_stor.c
# Cleanup for simplified sed scripts that use this table
@sed s/tf_ad_print\./tf_util\./g

I've supplied Unix shell scripts in the distribution for moving:
ren-pl10.sh	V4 pl10 filenames to proposed names	for converting old trees
ren-pc.sh	V4 MIT PC names to proposed names	for converting old trees
ren2long.sh	truncated names to proposed names	for moving DOS->unix
ren2dos.sh	proposed names to truncated names	for unix->DOS names

There's also shell scripts to produce sed scripts for converting Makefiles
and documentation.  You use them like:
	./sed-pl10.sh >/tmp/sed
	sed -f /tmp/sed <Makefile >newMakefile
sed-pl10.sh	V4 pl10 filenames to proposed names	for converting old trees
sed-pc.sh	V4 MIT PC names to proposed names	for converting old trees

I'll also supply a DOS script for moving:
ren-pc.bat	V4 MIT PC names to proposed names	for converting old trees

And an MPW script for moving
ren-pl10.mpw	V4 pl10 filenames to proposed names	for converting old trees

	John Gilmore
	Cygnus Support

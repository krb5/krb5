$ write sys$output "start of run"
$ cc /decc /inc=inc /debug=all des.c
$ cc /decc /inc=inc /debug=all d3des.c
$ cc /decc /inc=inc /debug=all cbc.c
$ cc /decc /inc=([],inc) /debug=all qcksum.c
$ cc /decc /inc=([],inc) /debug=all str2key.c
$ cc /decc /inc=([],inc) /debug=all parity.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all ad_print.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all add_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all cr_auth_repl.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all cr_ciph.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all cr_death_pkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all cr_err_repl.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all cr_tkt.c
$ write sys$output "begin d"
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all debug.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all decomp_tkt.c
stat $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all dest_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all err_txt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all ext_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all fakeenv.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all fgetst.c
$ write sys$output "begin g"
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_ad_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_admhst.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_cnffile.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_cred.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_in_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_krbhst.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_krbrlm.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_phost.c
sgtty $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_pw_in_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_pw_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_request.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_svc_in_tkt.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_tf_fname.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all g_tf_realm.c
$ write sys$output "end g_"
$ cc/decc/inc=inc /define=("HOST_BYTE_ORDER=1",BSD42) /debug=all gethostname.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all getst.c
stat $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all in_tkt.c
$ cc/decc/inc=inc /define=("HOST_BYTE_ORDER=1",NEED_TIME_H) /debug=all klog.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all kname_parse.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all kntoln.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all kparse.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all krbglue.c
stat $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all kuserok.c
$ write sys$output "end k"
$ cc/decc/inc=inc /define=("HOST_BYTE_ORDER=1",NEED_TIME_H) /debug=all log.c 
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all mk_err.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all mk_preauth.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all mk_priv.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all mk_req.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all mk_safe.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all month_sname.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all netread.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all netwrite.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all pkt_cipher.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all pkt_clen.c
$ write sys$output "begin rd"
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_err.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_preauth.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_priv.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_req.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_safe.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all rd_svc_key.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all realmofhost.c
$ write sys$output "begin recv"
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all recvauth.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all save_creds.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all send_to_kdc.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all sendauth.c
$ cc/decc/inc=inc /define=("HOST_BYTE_ORDER=1",NEED_TIME_H) /debug=all stime.c 
stat $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all tf_shm.c
stat $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all tf_util.c
MAXPATHLEN $ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all tkt_string.c
$ cc/decc/inc=inc /define="HOST_BYTE_ORDER=1" /debug=all vmsswab.c
$ library /create /list libkrb *.obj


.\" $Source$
.\" $Author$
.\" $Id$
.\" Copyright 1995 by the Massachusetts Institute of Technology.
.\"
.\" Export of this software from the United States of America may
.\"   require a specific license from the United States Government.
.\"   It is the responsibility of any person or organization contemplating
.\"   export to obtain such a license before exporting.
.\" 
.\" WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
.\" distribute this software and its documentation for any purpose and
.\" without fee is hereby granted, provided that the above copyright
.\" notice appear in all copies and that both that copyright notice and
.\" this permission notice appear in supporting documentation, and that
.\" the name of M.I.T. not be used in advertising or publicity pertaining
.\" to distribution of the software without specific, written prior
.\" permission.  M.I.T. makes no representations about the suitability of
.\" this software for any purpose.  It is provided "as is" without express
.\" or implied warranty.
.\" 
.\"
.TH KRB5STRINGS 3 "Kerberos Version 5.0" "MIT Project Athena"
.SH NAME
krb5strings \- String representations of Kerberos V5 internal data.
.SH KEY TYPES
The following strings specify valid key types for use by Kerberos V5.
.TP 2i
.I null
Specifies KEYTYPE_NULL.
.TP 2i
.I des
Specifies KEYTYPE_DES.

.SH SALT TYPES
The following strings specify valid salt types for use by Kerberos V5.
.TP 2i
.I normal
Specifies KRB5_KDB_SALTTYPE_NORMAL.
.TP 2i
.I v4
Specifies KRB5_KDB_SALTTYPE_V4.
.TP 2i
.I norealm
Specifies KRB5_KDB_SALTTYPE_NOREALM.
.TP 2i
.I onlyrealm
Specifies KRB5_KDB_SALTTYPE_ONLYREALM.
.TP 2i
.I special
Specifies KRB5_KDB_SALTTYPE_SPECIAL.

.SH ENCRYPTION TYPES
The following strings specify valid encryption types for use by Kerberos V5.
.TP 2i
.I null
Specifies ETYPE_NULL.
.TP 2i
.I des-cbc-crc
Specifies ETYPE_DES_CBC_CRC.
.TP 2i
.I des-cbc-md4
Specifies ETYPE_DES_CBC_MD4.
.TP 2i
.I des-cbc-md5
Specifies ETYPE_DES_CBC_MD5.
.TP 2i
.I raw-des-cbc
Specifies ETYPE_RAW_DES_CBC.

.SH CHECKSUM TYPES
The following strings specify valid checksum types for use by Kerberos V5.
.TP 2i
.I crc32
Specifies CKSUMTYPE_CRC32.
.TP 2i
.I md4
Specifies CKSUMTYPE_RSA_MD4.
.TP 2i
.I md4-des
Specifies CKSUMTYPE_RSA_MD4_DES.
.TP 2i
.I des-cbc
Specifies CKSUMTYPE_DESCBC.
.TP 2i
.I md5
Specifies CKSUMTYPE_RSA_MD5.
.TP 2i
.I md5-des
Specifies CKSUMTYPE_RSA_MD5_DES.

.SH PRINCIPAL FLAGS
The following strings specify particular principal attributes for use by
Kerberos V5.
.TP 2i
.I postdateable
In the negative sense, specifies KRB5_KDB_DISALLOW_POSTDATED.
.TP 2i
.I forwardable
In the negative sense, specifies KRB5_KDB_DISALLOW_FORWARDABLE.
.TP 2i
.I tgt-based
In the negative sense, specifies KRB5_KDB_DISALLOW_TGT_BASED.
.TP 2i
.I renewable
In the negative sense, specifies KRB5_KDB_DISALLOW_RENEWABLE.
.TP 2i
.I proxiable
In the negative sense, specifies KRB5_KDB_DISALLOW_PROXIABLE.
.TP 2i
.I dup-skey
In the negative sense, specifies KRB5_KDB_DISALLOW_DUP_SKEY.
.TP 2i
.I allow-tickets
In the negative sense, specifies KRB5_KDB_DISALLOW_ALL_TIX.
.TP 2i
.I preauth
Specifies KRB5_KDB_REQUIRES_PRE_AUTH.
.TP 2i
.I hwauth
Specifies KRB5_KDB_REQUIRES_HW_AUTH.
.TP 2i
.I pwchange
Specifies KRB5_KDB_REQUIRES_PWCHANGE.
.TP 2i
.I service
In the negative sense, specifies KRB5_KDB_DISALLOW_SVR.
.TP 2i
.I pwservice
Specifies KRB5_KDB_PWCHANGE_SERVICE.
.TP 2i
.I md5
Specifies KRB5_KDB_SUPPORT_DESMD5.

.SH ABSOLUTE TIME
The following formats specify valid absolute time strings for use by Kerberos
V5.  In the description the following abbreviations are used:
.in +1i
.B yy
denotes the last two digits of the year.

.B mm
denotes the two digits representing the month (01 = January, 12 = December).

.B dd
denotes the two digits representing the day of the month.

.B HH
denotes the two digits representing the hour of the day (24-hour format).

.B MM
denotes the two digits representing the minute of the hour.

.B SS
denotes the two digits representing the second of the minute.
.in -1i

.TP 2i
.I yymmddHHMMSS
e.g. 951225093023 specifies 9:30:23 a.m. on 25 December 1995.
.TP 2i
.I yy.mm.dd.HH.MM.SS
e.g. 95.12.25.09.30.23 specifies 9:30:23 a.m. on 25 December 1995.
.TP 2i
.I yymmddHHMM
e.g. 9512250930 specifies 9:30 a.m. on 25 December 1995.
.TP 2i
.I HHMMSS
e.g. 123056 specifies 12:30:56 p.m. today.
.TP 2i
.I HHMM
e.g. 2130 specifies 9:30 p.m. today.
.TP 2i
.I HH:MM:SS
e.g. 12:30:56 specifies 12:30:56 p.m. today.
.TP 2i
.I HH:MM
e.g. 21:30 specifies 9:30 p.m. today.
.PP
The following formats are recognized if the target operating system supports
the
.B strptime(3)
function.  See the
.B strptime(3)
manual page for a description of the format fields:
.TP 2i
.I %x:%X
Specifies the locale-dependent short date format concatenated by a colon with
the locale-dependent short time format.
.TP 2i
.I %d-%b-%Y:%T
e.g. 10-January-1995:16:42:23 in U.S. locales.
.TP 2i
.I %d-%b-%Y:%R
e.g. 10-January-1995:16:42 in U.S. locales.

.SH DELTA TIME
The following formats specify valid delta time strings for use by Kerberos
V5.  In the description the following abbreviations are used:
.in +1i
.B d
denotes a number of days.

.B h[h]
denotes one or two digits representing a number of hours.

.B m[m]
denotes one or two digits representing a number of minutes.

.B s[s]
denotes one or two digits representing a number of seconds.
.in -1i
.TP 2i
.I d-hh:mm:ss
e.g. 7-04:30:01 specifies seven days, four hours 30 minutes and one second.
.TP 2i
.I ddhhmmss
e.g. 7d4h30m1s specifies seven days, four hours 30 minutes and one second.
.TP 2i
.I h:mm:ss
e.g. 6:23:16 specifies six hours, 23 minutes and 16 seconds.
.TP 2i
.I hhmmss
e.g. 6h23m16s specifies six hours 23 minutes and 16 seconds.
.TP 2i
.I h:mm
e.g. 2:30 specifies two hours and 30 minutes.
.TP 2i
.I hhmm
e.g. 2h30m specifies two hours and 30 minutes.
.TP 2i
.I dd
e.g. 2d specifies two days.
.TP 2i
.I hh
e.g. 4h specifies four hours.
.TP 2i
.I mm
e.g. 30m specifies 30 minutes.
.TP 2i
.I ss
e.g. 3600s specifies 3600 seconds.

.SH SEE ALSO
kdc.conf(5), krb5kdc(8), kdb5_edit(8), kadmin5(8), strptime(3)

 



define([K5_TOPDIR],[.])dnl
dnl
pushdef([x],esyscmd([sed -n 's/#define \([A-Z0-9_]*\)[ \t]*\(.*\)/\1=\2/p' < ]K5_TOPDIR/patchlevel.h))
define([PL_KRB5_MAJOR_RELEASE],regexp(x,[KRB5_MAJOR_RELEASE=\(.*\)],[\1]))
ifelse(PL_KRB5_MAJOR_RELEASE,,[errprint([Can't determine KRB5_MAJOR_RELEASE value from patchlevel.h.
]) m4exit(1) dnl sometimes that does not work?
builtin(m4exit,1)])
define([PL_KRB5_MINOR_RELEASE],regexp(x,[KRB5_MINOR_RELEASE=\(.*\)],[\1]))
ifelse(PL_KRB5_MINOR_RELEASE,,[errprint([Can't determine KRB5_MINOR_RELEASE value from patchlevel.h.
]) m4exit(1) dnl sometimes that does not work?
builtin(m4exit,1)])
define([PL_KRB5_PATCHLEVEL],regexp(x,[KRB5_PATCHLEVEL=\(.*\)],[\1]))
ifelse(PL_KRB5_PATCHLEVEL,,[errprint([Can't determine KRB5_PATCHLEVEL value from patchlevel.h.
]) m4exit(1) dnl sometimes that does not work?
builtin(m4exit,1)])
define([PL_KRB5_RELTAIL],regexp(x,[KRB5_RELTAIL="\(.*\)"],[\1]))
dnl RELTAIL is allowed to not be defined.
popdef([x])
m4_define([K5_VERSION],PL_KRB5_MAJOR_RELEASE.PL_KRB5_MINOR_RELEASE[]ifelse(PL_KRB5_PATCHLEVEL,0,,.PL_KRB5_PATCHLEVEL)ifelse(PL_KRB5_RELTAIL,,,-PL_KRB5_RELTAIL))
m4_define([K5_BUGADDR],krb5-bugs@mit.edu)

##############################################################################################################
###			Important global constants
##############################################################################################################

root-folder											= ::
mitsupportlib-root-folder							= {root-folder}:::MITSupportLib:
mitkerberoslib-root-folder							= {root-folder}:
makefile-name										= {root-folder}mac:Makefile
makefile-dependency									= #{root-folder}mac:Makefile

library-output-folder								= {root-folder}bin:

library-target-macos9					= .9
library-target-carbon					= .CB

library-kind-debug						= d
library-kind-final						=

fragment-name-macos9					=
fragment-name-carbon					= ";Carbon"
fragment-name-debug-macos9				= ".debug"
fragment-name-debug-carbon				= ";Debug"
fragment-name-final-macos9				= 
fragment-name-final-carbon				= 

##############################################################################################################
###			Top-level targets -- abstract targets for convenient grouping
##############################################################################################################

#	Everything
all Ä unset-echo all-debug all-final

#	Debugging versions
all-debug Ä unset-echo macos9-debug-build carbon-debug-build
carbon-debug Ä unset-echo carbon-debug-build
macos9-debug Ä unset-echo macos9-debug-build

#	Final versions
all-final Ä unset-echo macos9-final-build carbon-final-build
carbon-final Ä unset-echo carbon-final-build
macos9-final Ä unset-echo macos9-final-build

#	Clasic 69K glue
glue Ä unset-echo glue-gss glue-krb5

unset-echo Ä
	If ({MacdevScriptDebug})
		Set Echo 1
	Else
		Unset Echo
	End

##############################################################################################################
###			More global constants
##############################################################################################################

gss-library-output-folder							= {root-folder}:GSSLib:Binaries:
privatekrb5-library-output-folder					= {root-folder}:Kerberos5Lib:Binaries:
krb5-library-output-folder							= {root-folder}:Kerberos5Lib:Binaries:
profile-library-output-folder						= {root-folder}:KerberosProfileLib:Binaries:
comerr-library-output-folder						= {root-folder}:ComErrLib:Binaries:

gss-library-name									= GSSLib
privatekrb5-library-name							= PrivateKrb5Lib
krb5-library-name									= Kerberos5Lib
profile-library-name								= KrbProfileLib
comerr-library-name									= ComErrLib

gss-library-export									= {root-folder}mac:GSSLibrary.exp
privatekrb5-library-export							= {root-folder}mac:PrivateKerberos5Lib.exp
krb5-library-export									= {root-folder}mac:Kerberos5Lib.exp
profile-library-export								= {root-folder}util:profile:profile.exp
comerr-library-export								= {root-folder}util:et:et.exp

gss-library-fragment-name							= "GSSLibrary"
gss-library-fragment-name-carbon					= "GSSLibrary"
privatekrb5-library-fragment-name					= "MIT Kerberos¥PrivateKerberos5Lib"
privatekrb5-library-fragment-name-carbon			= "MIT Kerberos;PrivateKerberos5Lib"
krb5-library-fragment-name							= "MIT Kerberos¥Kerberos5Lib"
krb5-library-fragment-name-carbon					= "MIT Kerberos;Kerberos5Lib"
profile-library-fragment-name						= "MIT Kerberos¥KerberosProfileLib"
profile-library-fragment-name-carbon				= "MIT Kerberos;KerberosProfileLib"
comerr-library-fragment-name						= "MIT Kerberos¥ComErrLib"
comerr-library-fragment-name-carbon					= "MIT Kerberos;ComErrLib"

gss-library-main									= ¶"¶"
privatekrb5-library-main							= ¶"¶"
krb5-library-main									= ¶"¶"
profile-library-main								= ¶"¶"
comerr-library-main									= ¶"¶"

gss-library-init									= __initializeGSS
privatekrb5-library-init							= __initializeK5
krb5-library-init									= ¶"¶"
profile-library-init								= InitializeProfileLib
comerr-library-init									= __initialize
	
gss-library-term 									= __terminateGSS
privatekrb5-library-term							= __terminateK5
krb5-library-term									= ¶"¶"
profile-library-term								= TerminateProfileLib
comerr-library-term									= __terminate

gss-library-current-version							= 1
gss-library-definition-version						= 0
gss-library-implementation-version					= 1

privatekrb5-library-current-version					= 5
privatekrb5-library-definition-version				= 5
privatekrb5-library-implementation-version			= 5

krb5-library-current-version						= 6
krb5-library-definition-version						= 5
krb5-library-implementation-version					= 5

profile-library-current-version						= 0
profile-library-definition-version					= 0
profile-library-implementation-version				= 0

comerr-library-current-version						= 0
comerr-library-definition-version					= 0
comerr-library-implementation-version				= 0

##############################################################################################################
###			Generation of file lists
##############################################################################################################

list-generation-script-working-folder = "{root-folder}mac:"
list-generation-script-folder = "{root-folder}mac:"
list-generation-script = "{list-generation-script-folder}macfile_gen.macpl"
list-generation-script-source = "{list-generation-script-folder}macfile_gen.pl"
list-generation-script-root = ".."

all-files-list									= {root-folder}"All files.list"
all-sources-list								= {root-folder}"All sources.list"
all-folders-list								= {root-folder}"All folders.list"
include-folders-list							= {root-folder}"Include folders.list"

gss-sources-list								= {root-folder}"GSS sources.list"
krb5-sources-list								= {root-folder}"Krb5 sources.list"
profile-sources-list							= {root-folder}"Profile sources.list"

gss-objects-macos9-debug-list					= {root-folder}"GSS objects 9 debug.list"
gss-objects-macos9-final-list					= {root-folder}"GSS objects 9 final.list"
gss-objects-carbon-debug-list					= {root-folder}"GSS objects CB debug.list"
gss-objects-carbon-final-list					= {root-folder}"GSS objects CB final.list"

krb5-objects-macos9-debug-list					= {root-folder}"Krb5 objects 9 debug.list"
krb5-objects-macos9-final-list					= {root-folder}"Krb5 objects 9 final.list"
krb5-objects-carbon-debug-list					= {root-folder}"Krb5 objects CB debug.list"
krb5-objects-carbon-final-list					= {root-folder}"Krb5 objects CB final.list"

profile-objects-macos9-debug-list				= {root-folder}"Profile objects 9 debug.list"
profile-objects-macos9-final-list				= {root-folder}"Profile objects 9 final.list"
profile-objects-carbon-debug-list				= {root-folder}"Profile objects CB debug.list"
profile-objects-carbon-final-list				= {root-folder}"Profile objects CB final.list"

comerr-objects-macos9-debug-list				= {root-folder}"ComErr objects 9 debug.list"
comerr-objects-macos9-final-list				= {root-folder}"ComErr objects 9 final.list"
comerr-objects-carbon-debug-list				= {root-folder}"ComErr objects CB debug.list"
comerr-objects-carbon-final-list				= {root-folder}"ComErr objects CB final.list"

all-lists = ¶
	{all-files-list} ¶
	{all-sources-list} ¶
	{all-folders-list} ¶
	{include-folders-list} ¶
	{gss-sources-list} ¶
	{krb5-sources-list} ¶
	{gss-objects-macos9-debug-list} ¶
	{gss-objects-macos9-final-list} ¶
	{gss-objects-carbon-debug-list} ¶
	{gss-objects-carbon-final-list} ¶
	{krb5-objects-macos9-debug-list} ¶
	{krb5-objects-macos9-final-list} ¶
	{krb5-objects-carbon-debug-list} ¶
	{krb5-objects-carbon-final-list} ¶
	{profile-objects-macos9-debug-list} ¶
	{profile-objects-macos9-final-list} ¶
	{profile-objects-carbon-debug-list} ¶
	{profile-objects-carbon-final-list} ¶
	{comerr-objects-macos9-debug-list} ¶
	{comerr-objects-macos9-final-list} ¶
	{comerr-objects-carbon-debug-list} ¶
	{comerr-objects-carbon-final-list}

file-lists Ä {all-lists}

{list-generation-script} Ä {list-generation-script-source}
	perl -p -e 's/\r/\n/g;' < {list-generation-script-source} > {list-generation-script}

# Note that even though the list generation script tries to have a mechanism allowing you to run it
# in different directories, it actually doesn't work too well because it wants a UNIX-style relative
# path to root Makefile.in. This is why we run it with -x to specify the root.

{all-files-list} Ä {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-files {list-generation-script-root} ¶
 > {Targ}

{all-sources-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{all-folders-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-folders {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{include-folders-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} include-folders {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-sources-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-sources-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-macos9-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-macos9-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-macos9-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-macos9-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-carbon-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-carbon-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-carbon-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-carbon-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-macos9-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-macos9-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-macos9-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-macos9-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-carbon-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-carbon-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-carbon-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-carbon-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-macos9-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-macos9-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-macos9-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-macos9-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-carbon-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-carbon-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-carbon-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-carbon-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-macos9-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-macos9-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-macos9-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-macos9-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-carbon-debug-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-carbon-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-carbon-final-list} Ä {all-files-list} {list-generation-script} {makefile-dependency}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-carbon-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

##############################################################################################################
###			Autogenerated files
##############################################################################################################

autogeneration-h-script = {root-folder}util:et:et_h.macpl
autogeneration-h-script-source = {root-folder}util:et:et_h.pl
autogeneration-c-script = {root-folder}util:et:et_c.macpl
autogeneration-c-script-source = {root-folder}util:et:et_c.pl

autogenerated-files = ¶
	{root-folder}include:asn1_err.h ¶
	{root-folder}include:kdb5_err.h ¶
	{root-folder}include:krb5_err.h ¶
	{root-folder}include:kv5m_err.h ¶
	{root-folder}include:adm_err.h ¶
	{root-folder}lib:gssapi:generic:gssapi_err_generic.h ¶
	{root-folder}lib:gssapi:krb5:gssapi_err_krb5.h ¶
	{root-folder}util:profile:prof_err.c ¶
	{root-folder}lib:krb5:error_tables:asn1_err.c ¶
	{root-folder}lib:krb5:error_tables:kdb5_err.c ¶
	{root-folder}lib:krb5:error_tables:krb5_err.c ¶
	{root-folder}lib:krb5:error_tables:kv5m_err.c ¶
	{root-folder}lib:krb5:error_tables:adm_err.c ¶
	{root-folder}lib:gssapi:generic:gssapi_err_generic.c ¶
	{root-folder}lib:gssapi:krb5:gssapi_err_krb5.c ¶
	{root-folder}util:profile:prof_err.h ¶
	{root-folder}include:krb5.h ¶
	{root-folder}util:profile:profile.h ¶
	{root-folder}include:profile.h ¶
	{root-folder}include:krb5:osconf.h ¶
	{root-folder}lib:gssapi:generic:gssapi.h

###			error table headers

{autogeneration-h-script} Ä {autogeneration-h-script-source}
	perl -p -e 's/\r/\n/g;' < {autogeneration-h-script-source} > {autogeneration-h-script}

{root-folder}include:asn1_err.h Ä {root-folder}lib:krb5:error_tables:asn1_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:krb5:error_tables:asn1_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}include:asn1_err.h"

{root-folder}include:kdb5_err.h Ä {root-folder}lib:krb5:error_tables:kdb5_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:krb5:error_tables:kdb5_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}include:kdb5_err.h"

{root-folder}include:krb5_err.h Ä {root-folder}lib:krb5:error_tables:krb5_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:krb5:error_tables:krb5_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}include:krb5_err.h"

{root-folder}include:kv5m_err.h Ä {root-folder}lib:krb5:error_tables:kv5m_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:krb5:error_tables:kv5m_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}include:kv5m_err.h"

{root-folder}include:adm_err.h Ä {root-folder}lib:krb5:error_tables:adm_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:krb5:error_tables:adm_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}include:adm_err.h" 
	
{root-folder}lib:gssapi:generic:gssapi_err_generic.h Ä {root-folder}lib:gssapi:generic:gssapi_err_generic.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:gssapi:generic:gssapi_err_generic.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}lib:gssapi:generic:gssapi_err_generic.h"
	
{root-folder}lib:gssapi:krb5:gssapi_err_krb5.h Ä {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}lib:gssapi:krb5:gssapi_err_krb5.h"

{root-folder}util:profile:prof_err.h Ä {root-folder}util:profile:prof_err.et {makefile-dependency} {autogeneration-h-script}
	Catenate {root-folder}util:profile:prof_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-h-script} outfile="{root-folder}util:profile:prof_err.h"

###			error table sources

{autogeneration-c-script} Ä {autogeneration-c-script-source}
	perl -p -e 's/\r/\n/g;' < {autogeneration-c-script-source} > {autogeneration-c-script}

{root-folder}lib:krb5:error_tables:asn1_err.c Ä {root-folder}lib:krb5:error_tables:asn1_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:krb5:error_tables:asn1_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:asn1_err.c"

{root-folder}lib:krb5:error_tables:kdb5_err.c Ä {root-folder}lib:krb5:error_tables:kdb5_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:krb5:error_tables:kdb5_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:kdb5_err.c"

{root-folder}lib:krb5:error_tables:krb5_err.c Ä {root-folder}lib:krb5:error_tables:krb5_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:krb5:error_tables:krb5_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:krb5_err.c"

{root-folder}lib:krb5:error_tables:kv5m_err.c Ä {root-folder}lib:krb5:error_tables:kv5m_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:krb5:error_tables:kv5m_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:kv5m_err.c"

{root-folder}lib:krb5:error_tables:adm_err.c Ä {root-folder}lib:krb5:error_tables:adm_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:krb5:error_tables:adm_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:adm_err.c"

{root-folder}lib:gssapi:generic:gssapi_err_generic.c Ä {root-folder}lib:gssapi:generic:gssapi_err_generic.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:gssapi:generic:gssapi_err_generic.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:gssapi:generic:gssapi_err_generic.c"

{root-folder}lib:gssapi:krb5:gssapi_err_krb5.c Ä {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}lib:gssapi:krb5:gssapi_err_krb5.c"

{root-folder}util:profile:prof_err.c Ä {root-folder}util:profile:prof_err.et {makefile-dependency} {autogeneration-c-script}
	Catenate {root-folder}util:profile:prof_err.et | perl -p -e 's/\r/\n/g;' | Catenate | ¶
		perl {autogeneration-c-script} outfile="{root-folder}util:profile:prof_err.c"

###			other autogenerated files

{root-folder}include:krb5.h Ä {root-folder}include:krb5.hin {root-folder}include:krb5_err.h ¶
	{root-folder}include:kdb5_err.h {root-folder}include:kv5m_err.h {root-folder}include:asn1_err.h
	Catenate {root-folder}include:krb5.hin {root-folder}include:krb5_err.h {root-folder}include:kdb5_err.h ¶
	{root-folder}include:kv5m_err.h {root-folder}include:asn1_err.h > {root-folder}include:krb5.h
	Catenate {root-folder}include:krb5.h | perl -p -e 's/\n/\r/g;' | Catenate > {root-folder}include:krb5.h
	
{root-folder}util:profile:profile.h Ä {root-folder}util:profile:profile.hin {root-folder}util:profile:prof_err.h
	Catenate {root-folder}util:profile:profile.hin {root-folder}util:profile:prof_err.h > {root-folder}util:profile:profile.h
	Catenate {root-folder}util:profile:profile.h | perl -p -e 's/\n/\r/g;' | Catenate > {root-folder}util:profile:profile.h
	
{root-folder}include:profile.h Ä {root-folder}util:profile:profile.h
	Catenate {root-folder}util:profile:profile.h > {root-folder}include:profile.h
	Catenate {root-folder}include:profile.h | perl -p -e 's/\n/\r/g;' | Catenate > {root-folder}include:profile.h
	SetFile -a l "{Targ}"

{root-folder}include:krb5:osconf.h Ä {root-folder}include:krb5:stock:osconf.h
	Catenate {root-folder}include:krb5:stock:osconf.h > {root-folder}include:krb5:osconf.h
	Catenate {root-folder}include:krb5:osconf.h | perl -p -e 's/\n/\r/g;' | Catenate > {root-folder}include:krb5:osconf.h
	SetFile -a l "{Targ}"

{root-folder}lib:gssapi:generic:gssapi.h Ä {root-folder}lib:gssapi:generic:gssapi.hin
	Catenate {root-folder}lib:gssapi:generic:gssapi.hin > {root-folder}lib:gssapi:generic:gssapi.h
	Catenate {root-folder}lib:gssapi:generic:gssapi.h | perl -p -e 's/\n/\r/g;' | Catenate > {root-folder}lib:gssapi:generic:gssapi.h
	SetFile -a l "{Targ}"
	
##############################################################################################################
###			High-level abstract targets -- this is where we decide on options
##############################################################################################################
###	We need to generate the following Make variables to pass to the Makefile:
###		For GSS library
###			gss-library-output-folder						-- destination of GSS library output
###			gss-library-name								-- name of the GSS library
###			gss-library-export								-- name of gss GSS library export file
###			gss-library-libraries							-- list of libraries GSS library links against
###			gss-library-objects								-- list of object files GSS library links
###			gss-library-fragment-name						-- name of GSS library fragment
###			gss-library-main								-- name of GSS library main entry point
###			gss-library-init								-- name of GSS library initialization routine
###			gss-library-term								-- name of GSS library termination routine
###			gss-library-linker-options						-- all other GSS library linker options
###		For Krb5 library
###			krb5-library-output-folder						-- destination of Krb5 library output
###			krb5-library-name								-- name of the Krb5 library
###			krb5-library-export								-- name of gss Krb5 library export file
###			krb5-library-libraries							-- list of libraries Krb5 library links against
###			krb5-library-objects							-- list of object files Krb5 library links
###			krb5-library-fragment-name						-- name of Krb5 library fragment
###			krb5-library-main								-- name of Krb5 library main entry point
###			krb5-library-init								-- name of Krb5 library initialization routine
###			krb5-library-term								-- name of Krb5 library termination routine
###			krb5-library-linker-options						-- all other Krb5 library linker options
###		For profile library
###			profile-library-output-folder					-- destination of profile library output
###			profile-library-name							-- name of the profile library
###			profile-library-export							-- name of gss profile library export file
###			profile-library-libraries						-- list of libraries profile library links against
###			profile-library-objects							-- list of object files profile library links
###			profile-library-fragment-name					-- name of profile library fragment
###			profile-library-main							-- name of profile library main entry point
###			profile-library-init							-- name of profile library initialization routine
###			profile-library-term							-- name of profile library termination routine
###			profile-library-linker-options					-- all other profile library linker options
###		For comerr library
###			comerr-library-output-folder					-- destination of comerr library output
###			comerr-library-name								-- name of the comerr library
###			comerr-library-export							-- name of gss comerr library export file
###			comerr-library-libraries						-- list of libraries comerr library links against
###			comerr-library-objects							-- list of object files comerr library links
###			comerr-library-fragment-name					-- name of comerr library fragment
###			comerr-library-main								-- name of comerr library main entry point
###			comerr-library-init								-- name of comerr library initialization routine
###			comerr-library-term								-- name of comerr library termination routine
###			comerr-library-linker-options					-- all other comerr library linker options
###		General
###			library-linker									-- linker to use
###			autogenerated-files								-- list of autogenerated files
###			library-target									-- platform name (Mac OS 9 or Carbon)
###			library-kind									-- library kind (debug on non-debug)
###			object-suffix									-- object file suffix (.9d.o, .CBd.o, .9.o, .CB.o)
###			object-suffix-data								-- object file suffix for data libraries (.9.o, .CB.o)


### The following variables are platform- or kind-specific, but constant

clib-macos9-debug					= {mitsupportlib-root-folder}CLib:Binaries:CLib.9d
clib-macos9-final					= {mitsupportlib-root-folder}CLib:Binaries:CLib.9
clib-carbon-debug					= {mitsupportlib-root-folder}CLib:Binaries:CLib.CBd
clib-carbon-final					= {mitsupportlib-root-folder}CLib:Binaries:CLib.CB

runtimelib-macos9-debug				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.9d
runtimelib-macos9-final				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.9
runtimelib-carbon-debug				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.CBd
runtimelib-carbon-final				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.CB

runtimelib-static-macos9-debug		= {mitsupportlib-root-folder}"RuntimeLib:Binaries:Runtime.9d.lib"
runtimelib-static-macos9-final		= {mitsupportlib-root-folder}"RuntimeLib:Binaries:Runtime.9.lib"
runtimelib-static-carbon-debug		= {mitsupportlib-root-folder}"RuntimeLib:Binaries:Runtime.CBd.lib"
runtimelib-static-carbon-final		= {mitsupportlib-root-folder}"RuntimeLib:Binaries:Runtime.CB.lib"

standard-libraries-macos9-debug			= ¶
	"{clib-macos9-debug}" ¶
	"{runtimelib-macos9-debug}" ¶
	"{runtimelib-static-macos9-debug}" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}OpenTptInternetLib¶" ¶
	¶"{SharedLibraries}MathLib¶"
standard-libraries-macos9-final			= ¶
	"{clib-macos9-final}" ¶
	"{runtimelib-macos9-final}" ¶
	"{runtimelib-static-macos9-final}" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}OpenTptInternetLib¶" ¶
	¶"{SharedLibraries}MathLib¶"
standard-libraries-carbon-debug			= ¶
	"{clib-carbon-debug}" ¶
	"{runtimelib-carbon-debug}" ¶
	"{runtimelib-static-carbon-debug}" ¶
	¶"{SharedLibraries}CarbonLib¶"
standard-libraries-carbon-final			= ¶
	"{clib-carbon-final}" ¶
	"{runtimelib-carbon-final}" ¶
	"{runtimelib-static-carbon-final}" ¶
	¶"{SharedLibraries}CarbonLib¶"

ccachelib-macos9-debug					= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.9d
ccachelib-macos9-final					= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.9
ccachelib-carbon-debug					= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.CBd
ccachelib-carbon-final					= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.CB

loginlib-macos9-debug					= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.9d
loginlib-macos9-final					= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.9
loginlib-carbon-debug					= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.CBd
loginlib-carbon-final					= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.CB

preferenceslib-macos9-debug				= {mitkerberoslib-root-folder}PreferencesLib:Binaries:PreferencesLib.9d
preferenceslib-macos9-final				= {mitkerberoslib-root-folder}PreferencesLib:Binaries:PreferencesLib.9
preferenceslib-carbon-debug				= {mitkerberoslib-root-folder}PreferencesLib:Binaries:PreferencesLib.CBd
preferenceslib-carbon-final				= {mitkerberoslib-root-folder}PreferencesLib:Binaries:PreferencesLib.CB

socketslib-macos9-debug					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.9d
socketslib-macos9-final					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.9
socketslib-carbon-debug					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.CBd
socketslib-carbon-final					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.CB

errorlib-macos9-debug					= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.9d
errorlib-macos9-final					= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.9
errorlib-carbon-debug					= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.CBd
errorlib-carbon-final					= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.CB

utilitieslib-macos9-debug				= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.9d
utilitieslib-macos9-final				= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.9
utilitieslib-carbon-debug				= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.CBd
utilitieslib-carbon-final				= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.CB

morefileslib-macos9-debug				= {mitsupportlib-root-folder}MoreFilesLib:Binaries:MoreFilesLib.9d
morefileslib-macos9-final				= {mitsupportlib-root-folder}MoreFilesLib:Binaries:MoreFilesLib.9
morefileslib-carbon-debug				= {mitsupportlib-root-folder}MoreFilesLib:Binaries:MoreFilesLib.CBd
morefileslib-carbon-final				= {mitsupportlib-root-folder}MoreFilesLib:Binaries:MoreFilesLib.CB

object-suffix-macos9-debug				= .9d.o
object-suffix-macos9-final				= .9.o
object-suffix-macos9-data				= .9.o
object-suffix-carbon-debug				= .CBd.o
object-suffix-carbon-final				= .CB.o
object-suffix-carbon-data				= .CB.o

gss-library-libraries-macos9-debug = ¶
	{standard-libraries-macos9-debug} ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-macos9}{library-kind-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-macos9}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-debug}
gss-library-libraries-macos9-final = ¶
	{standard-libraries-macos9-final} ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-macos9}{library-kind-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-macos9}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-final}
gss-library-libraries-carbon-debug = ¶
	{standard-libraries-carbon-debug} ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-carbon}{library-kind-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-carbon}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-debug}
gss-library-libraries-carbon-final = ¶
	{standard-libraries-carbon-final} ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-carbon}{library-kind-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-carbon}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-final}

krb5-library-libraries-macos9-debug = ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-macos9}{library-kind-debug}
krb5-library-libraries-macos9-final = ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-macos9}{library-kind-final}
krb5-library-libraries-carbon-debug = ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-carbon}{library-kind-debug}
krb5-library-libraries-carbon-final = ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-target-carbon}{library-kind-final}

privatekrb5-library-libraries-macos9-debug = ¶
	¶"{SharedLibraries}DriverServicesLib¶" ¶
	{standard-libraries-macos9-debug} ¶
	{utilitieslib-macos9-debug} ¶
	{ccachelib-macos9-debug} ¶
	{preferenceslib-macos9-debug} ¶
	{loginlib-macos9-debug} ¶
	{socketslib-macos9-debug} ¶
	{errorlib-macos9-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-macos9}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-debug} ¶
	¶"{PPCLibraries}PPCMath64Lib.o¶"
privatekrb5-library-libraries-macos9-final = ¶
	¶"{SharedLibraries}DriverServicesLib¶" ¶
	{standard-libraries-macos9-final} ¶
	{utilitieslib-macos9-final} ¶
	{ccachelib-macos9-final} ¶
	{preferenceslib-macos9-final} ¶
	{loginlib-macos9-final} ¶
	{socketslib-macos9-final} ¶
	{errorlib-macos9-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-macos9}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-final} ¶
	¶"{PPCLibraries}PPCMath64Lib.o¶"
privatekrb5-library-libraries-carbon-debug = ¶
	{standard-libraries-carbon-debug} ¶
	{utilitieslib-carbon-debug} ¶
	{ccachelib-carbon-debug} ¶
	{preferenceslib-carbon-debug} ¶
	{loginlib-carbon-debug} ¶
	{socketslib-carbon-debug} ¶
	{errorlib-carbon-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-carbon}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-debug}
privatekrb5-library-libraries-carbon-final = ¶
	{standard-libraries-carbon-final} ¶
	{utilitieslib-carbon-final} ¶
	{ccachelib-carbon-final} ¶
	{preferenceslib-carbon-final} ¶
	{loginlib-carbon-final} ¶
	{socketslib-carbon-final} ¶
	{errorlib-carbon-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-target-carbon}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-final}

profile-library-libraries-macos9-debug = ¶
	{standard-libraries-macos9-debug} ¶
	{morefileslib-macos9-debug} ¶
	{utilitieslib-macos9-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-debug}
profile-library-libraries-macos9-final = ¶
	{standard-libraries-macos9-final} ¶
	{morefileslib-macos9-final} ¶
	{utilitieslib-macos9-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-macos9}{library-kind-final}
profile-library-libraries-carbon-debug = ¶
	{standard-libraries-carbon-debug} ¶
	{morefileslib-carbon-debug} ¶
	{utilitieslib-carbon-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-debug}
profile-library-libraries-carbon-final = ¶
	{standard-libraries-carbon-final} ¶
	{morefileslib-carbon-final} ¶
	{utilitieslib-carbon-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-target-carbon}{library-kind-final}

comerr-library-libraries-macos9-debug = ¶
	{standard-libraries-macos9-debug} {errorlib-macos9-debug}
comerr-library-libraries-macos9-final = ¶
	{standard-libraries-macos9-final} {errorlib-macos9-final}
comerr-library-libraries-carbon-debug = ¶
	{standard-libraries-carbon-debug} {errorlib-carbon-debug}
comerr-library-libraries-carbon-final = ¶
	{standard-libraries-carbon-final} {errorlib-carbon-final}

### Construct linker options. 

common-linker-options = -sharedlibrary
common-linker-options-debug = {common-linker-options} -sym on
common-linker-options-final = {common-linker-options} -sym off

gss-library-common-linker-options = ¶
	-cv {gss-library-current-version} ¶
	-dv {gss-library-definition-version} ¶
	-uv {gss-library-implementation-version}

gss-library-linker-options-macos9-debug = {common-linker-options-debug} {gss-library-common-linker-options}
gss-library-linker-options-macos9-final = {common-linker-options-final} {gss-library-common-linker-options}
gss-library-linker-options-carbon-debug = {common-linker-options-debug} {gss-library-common-linker-options}
gss-library-linker-options-carbon-final = {common-linker-options-final} {gss-library-common-linker-options}

krb5-library-common-linker-options = ¶
	-cv {krb5-library-current-version} ¶
	-dv {krb5-library-definition-version} ¶
	-uv {krb5-library-implementation-version}

krb5-library-linker-options-macos9-debug = {common-linker-options-debug} {krb5-library-common-linker-options}
krb5-library-linker-options-macos9-final = {common-linker-options-final} {krb5-library-common-linker-options}
krb5-library-linker-options-carbon-debug = {common-linker-options-debug} {krb5-library-common-linker-options}
krb5-library-linker-options-carbon-final = {common-linker-options-final} {krb5-library-common-linker-options}

privatekrb5-library-common-linker-options = ¶
	-cv {privatekrb5-library-current-version} ¶
	-dv {privatekrb5-library-definition-version} ¶
	-uv {privatekrb5-library-implementation-version}

privatekrb5-library-linker-options-macos9-debug = {common-linker-options-debug} {privatekrb5-library-common-linker-options} -weaklib "DriverServicesLib"
privatekrb5-library-linker-options-macos9-final = {common-linker-options-final} {privatekrb5-library-common-linker-options} -weaklib "DriverServicesLib"
privatekrb5-library-linker-options-carbon-debug = {common-linker-options-debug} {privatekrb5-library-common-linker-options}
privatekrb5-library-linker-options-carbon-final = {common-linker-options-final} {privatekrb5-library-common-linker-options}

profile-library-common-linker-options = ¶
	-cv {profile-library-current-version} ¶
	-dv {profile-library-definition-version} ¶
	-uv {profile-library-implementation-version}

profile-library-linker-options-macos9-debug = {common-linker-options-debug} {profile-library-common-linker-options}
profile-library-linker-options-macos9-final = {common-linker-options-final} {profile-library-common-linker-options}
profile-library-linker-options-carbon-debug = {common-linker-options-debug} {profile-library-common-linker-options}
profile-library-linker-options-carbon-final = {common-linker-options-final} {profile-library-common-linker-options}

comerr-library-common-linker-options = ¶
	-cv {comerr-library-current-version} ¶
	-dv {comerr-library-definition-version} ¶
	-uv {comerr-library-implementation-version}

comerr-library-linker-options-macos9-debug = {common-linker-options-debug} {comerr-library-common-linker-options}
comerr-library-linker-options-macos9-final = {common-linker-options-final} {comerr-library-common-linker-options}
comerr-library-linker-options-carbon-debug = {common-linker-options-debug} {comerr-library-common-linker-options}
comerr-library-linker-options-carbon-final = {common-linker-options-final} {comerr-library-common-linker-options}

gss-library-objects-macos9-debug = `catenate {gss-objects-macos9-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-macos9-debug}
gss-library-objects-macos9-final = `catenate {gss-objects-macos9-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-macos9-final}
gss-library-objects-carbon-debug = `catenate {gss-objects-carbon-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-carbon-debug}
gss-library-objects-carbon-final = `catenate {gss-objects-carbon-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-carbon-final}

privatekrb5-library-objects-macos9-debug = `catenate {krb5-objects-macos9-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-macos9-debug}
privatekrb5-library-objects-macos9-final = `catenate {krb5-objects-macos9-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-macos9-final}
privatekrb5-library-objects-carbon-debug = `catenate {krb5-objects-carbon-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-carbon-debug}
privatekrb5-library-objects-carbon-final = `catenate {krb5-objects-carbon-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-carbon-final}

profile-library-objects-macos9-debug = `catenate {profile-objects-macos9-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-macos9-debug}
profile-library-objects-macos9-final = `catenate {profile-objects-macos9-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-macos9-final}
profile-library-objects-carbon-debug = `catenate {profile-objects-carbon-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-carbon-debug}
profile-library-objects-carbon-final = `catenate {profile-objects-carbon-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-carbon-final}

comerr-library-objects-macos9-debug = `catenate {comerr-objects-macos9-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`
comerr-library-objects-macos9-final = `catenate {comerr-objects-macos9-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`
comerr-library-objects-carbon-debug = `catenate {comerr-objects-carbon-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`
comerr-library-objects-carbon-final = `catenate {comerr-objects-carbon-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`

library-linker-macos9					= MWLinkPPC
library-linker-carbon					= MWLinkPPC

### Construct compiler options.

common-compiler-options = ¶
		-enum int -opt all -strings pool -mapcr -strings readonly ¶
        -relax_pointers -warnings off -fatext -convertpaths -maxerrors 10 ¶
        -align mac68k -opt off -toc_data on -fp_contract on ¶
		-model farData

# Don't put the prefix file in these options because they are used to precompile the prefix file
macos9-compiler-options = -tb on
carbon-compiler-options = -tb on
debug-compiler-options = -sym on
final-compiler-options = -sym off

mitsupportlib-include-paths = ¶
	-i {mitsupportlib-root-folder}MoreFilesLib:Headers: ¶
	-i {mitsupportlib-root-folder}Common:Headers: ¶
	-i {mitsupportlib-root-folder}CLib:Headers: ¶
	-i {mitsupportlib-root-folder}SocketsLib:Headers: ¶
	-i {mitsupportlib-root-folder}ErrorLib:Headers: ¶
	-i {mitsupportlib-root-folder}UtilitiesLib:Headers:

include-paths = -i {root-folder}mac:libraries: ¶
	`catenate {include-folders-list} | StreamEdit -d -set prefix="{root-folder}mac:" -e "/-i (Å)¨1/ Print '-i 'prefix¨1"` ¶
	-I- ¶
	-i {mitkerberoslib-root-folder}CCacheLib:Headers: ¶
	-i {mitkerberoslib-root-folder}LoginLib:Headers: ¶
	-i {mitkerberoslib-root-folder}PreferencesLib:Headers: ¶
	-i {mitkerberoslib-root-folder}Kerberos5Lib:Headers: ¶
	-i {mitkerberoslib-root-folder}GSSLib:Headers: ¶
	-i {mitkerberoslib-root-folder}KerberosProfileLib:Headers: ¶
	-i {mitkerberoslib-root-folder}ComErrLib:Headers: ¶
	{mitsupportlib-include-paths}
		
compiler-options-macos9-debug = {common-compiler-options} {include-paths} {macos9-compiler-options} ¶
	{debug-compiler-options} -i {precompiled-headers-folder} -prefix KerberosHeaders.9
compiler-options-macos9-final = {common-compiler-options} {include-paths} {macos9-compiler-options} ¶
	{final-compiler-options} -i {precompiled-headers-folder} -prefix KerberosHeaders.9
compiler-options-carbon-debug = {common-compiler-options} {include-paths} {carbon-compiler-options} ¶
	{debug-compiler-options} -i {precompiled-headers-folder} -prefix KerberosHeaders.CB
compiler-options-carbon-final = {common-compiler-options} {include-paths} {carbon-compiler-options} ¶
	{final-compiler-options} -i {precompiled-headers-folder} -prefix KerberosHeaders.CB

compiler-macos9							= MWCPPC
compiler-carbon							= MWCPPC

### Precompiled headers

precompiled-headers-folder = {root-folder}mac:libraries:

precompiled-headers-macos9 = {precompiled-headers-folder}KerberosHeaders.9
precompiled-headers-carbon = {precompiled-headers-folder}KerberosHeaders.CB

precompiled-headers-source-macos9 = {precompiled-headers-folder}KerberosHeaders.9.pch
precompiled-headers-source-carbon = {precompiled-headers-folder}KerberosHeaders.CB.pch

{precompiled-headers-macos9} Ä {precompiled-headers-source-macos9} {precompiled-headers-folder}KerberosHeaders.h
	{compiler-macos9} -convertpaths {precompiled-headers-source-macos9} {common-compiler-options} {macos9-compiler-options} ¶
		-precompile {Targ} -i {precompiled-headers-folder} {include-paths} -i "{CWANSIIncludes}sys"
{precompiled-headers-carbon} Ä {precompiled-headers-source-carbon} {precompiled-headers-folder}KerberosHeaders.h
	{compiler-carbon} -convertpaths {precompiled-headers-source-carbon} {common-compiler-options} {carbon-compiler-options} ¶
		-precompile {Targ} -i {precompiled-headers-folder} {include-paths} -i "{CWANSIIncludes}sys"

make-options-common = ¶
	-f {makefile-name} ¶
	-d root-folder="{root-folder}" ¶
	-d autogenerated-files="{autogenerated-files}" ¶
	-d gss-library-output-folder="{gss-library-output-folder}" ¶
	-d gss-library-name="{gss-library-name}" ¶
	-d gss-library-export="{gss-library-export}" ¶
	-d gss-library-main="{gss-library-main}" ¶
	-d gss-library-init="{gss-library-init}" ¶
	-d gss-library-term="{gss-library-term}" ¶
	-d krb5-library-output-folder="{krb5-library-output-folder}" ¶
	-d krb5-library-name="{krb5-library-name}" ¶
	-d krb5-library-export="{krb5-library-export}" ¶
	-d krb5-library-main="{krb5-library-main}" ¶
	-d krb5-library-init="{krb5-library-init}" ¶
	-d krb5-library-term="{krb5-library-term}" ¶
	-d privatekrb5-library-output-folder="{privatekrb5-library-output-folder}" ¶
	-d privatekrb5-library-name="{privatekrb5-library-name}" ¶
	-d privatekrb5-library-export="{privatekrb5-library-export}" ¶
	-d privatekrb5-library-main="{privatekrb5-library-main}" ¶
	-d privatekrb5-library-init="{privatekrb5-library-init}" ¶
	-d privatekrb5-library-term="{privatekrb5-library-term}" ¶
	-d profile-library-output-folder="{profile-library-output-folder}" ¶
	-d profile-library-name="{profile-library-name}" ¶
	-d profile-library-export="{profile-library-export}" ¶
	-d profile-library-main="{profile-library-main}" ¶
	-d profile-library-init="{profile-library-init}" ¶
	-d profile-library-term="{profile-library-term}" ¶
	-d comerr-library-output-folder="{comerr-library-output-folder}" ¶
	-d comerr-library-name="{comerr-library-name}" ¶
	-d comerr-library-export="{comerr-library-export}" ¶
	-d comerr-library-main="{comerr-library-main}" ¶
	-d comerr-library-init="{comerr-library-init}" ¶
	-d comerr-library-term="{comerr-library-term}"

make-options-macos9-debug = ¶
	-d library-linker="{library-linker-macos9}" ¶
	-d library-platform="{library-target-macos9}" ¶
	-d library-kind="{library-kind-debug}" ¶
	-d fragment-kind={fragment-name-macos9}{fragment-name-debug-macos9} ¶
	-d gss-library-fragment-name={gss-library-fragment-name} ¶
	-d krb5-library-fragment-name={krb5-library-fragment-name} ¶
	-d privatekrb5-library-fragment-name={privatekrb5-library-fragment-name} ¶
	-d profile-library-fragment-name={profile-library-fragment-name} ¶
	-d comerr-library-fragment-name={comerr-library-fragment-name} ¶
	-d gss-library-libraries="{gss-library-libraries-macos9-debug}" ¶
	-d gss-library-objects="{gss-library-objects-macos9-debug}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-macos9-debug}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-macos9-debug}" ¶
	-d krb5-library-objects="{krb5-library-objects-macos9-debug}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-macos9-debug}" ¶
	-d privatekrb5-library-libraries="{privatekrb5-library-libraries-macos9-debug}" ¶
	-d privatekrb5-library-objects="{privatekrb5-library-objects-macos9-debug}" ¶
	-d privatekrb5-library-linker-options="{privatekrb5-library-linker-options-macos9-debug}" ¶
	-d profile-library-libraries="{profile-library-libraries-macos9-debug}" ¶
	-d profile-library-objects="{profile-library-objects-macos9-debug}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-macos9-debug}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-macos9-debug}" ¶
	-d comerr-library-objects="{comerr-library-objects-macos9-debug}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-macos9-debug}" ¶
	-d object-suffix="{object-suffix-macos9-debug}" ¶
	-d object-suffix-data="{object-suffix-macos9-data}" ¶
	-d compiler-options="{compiler-options-macos9-debug}" ¶
	-d compiler="{compiler-macos9}" ¶
	-d precompiled-headers="{precompiled-headers-macos9}"
	
make-options-macos9-final = ¶
	-d library-linker="{library-linker-macos9}" ¶
	-d library-platform="{library-target-macos9}" ¶
	-d library-kind="{library-kind-final}" ¶
	-d fragment-kind={fragment-name-macos9}{fragment-name-final-macos9} ¶
	-d gss-library-fragment-name={gss-library-fragment-name} ¶
	-d krb5-library-fragment-name={krb5-library-fragment-name} ¶
	-d privatekrb5-library-fragment-name={privatekrb5-library-fragment-name} ¶
	-d profile-library-fragment-name={profile-library-fragment-name} ¶
	-d comerr-library-fragment-name={comerr-library-fragment-name} ¶
	-d gss-library-libraries="{gss-library-libraries-macos9-final}" ¶
	-d gss-library-objects="{gss-library-objects-macos9-final}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-macos9-final}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-macos9-final}" ¶
	-d krb5-library-objects="{krb5-library-objects-macos9-final}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-macos9-final}" ¶
	-d privatekrb5-library-libraries="{privatekrb5-library-libraries-macos9-final}" ¶
	-d privatekrb5-library-objects="{privatekrb5-library-objects-macos9-final}" ¶
	-d privatekrb5-library-linker-options="{privatekrb5-library-linker-options-macos9-final}" ¶
	-d profile-library-libraries="{profile-library-libraries-macos9-final}" ¶
	-d profile-library-objects="{profile-library-objects-macos9-final}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-macos9-final}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-macos9-final}" ¶
	-d comerr-library-objects="{comerr-library-objects-macos9-final}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-macos9-final}" ¶
	-d object-suffix="{object-suffix-macos9-final}" ¶
	-d object-suffix-data="{object-suffix-macos9-data}" ¶
	-d compiler-options="{compiler-options-macos9-final}" ¶
	-d compiler="{compiler-macos9}" ¶
	-d precompiled-headers="{precompiled-headers-macos9}"
	
make-options-carbon-debug = ¶
	-d library-linker="{library-linker-carbon}" ¶
	-d library-platform="{library-target-carbon}" ¶
	-d library-kind="{library-kind-debug}" ¶
	-d fragment-kind={fragment-name-carbon}{fragment-name-debug-carbon} ¶
	-d gss-library-fragment-name={gss-library-fragment-name-carbon} ¶
	-d krb5-library-fragment-name={krb5-library-fragment-name-carbon} ¶
	-d privatekrb5-library-fragment-name={privatekrb5-library-fragment-name-carbon} ¶
	-d profile-library-fragment-name={profile-library-fragment-name-carbon} ¶
	-d comerr-library-fragment-name={comerr-library-fragment-name-carbon} ¶
	-d gss-library-libraries="{gss-library-libraries-carbon-debug}" ¶
	-d gss-library-objects="{gss-library-objects-carbon-debug}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-carbon-debug}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-carbon-debug}" ¶
	-d krb5-library-objects="{krb5-library-objects-carbon-debug}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-carbon-debug}" ¶
	-d privatekrb5-library-libraries="{privatekrb5-library-libraries-carbon-debug}" ¶
	-d privatekrb5-library-objects="{privatekrb5-library-objects-carbon-debug}" ¶
	-d privatekrb5-library-linker-options="{privatekrb5-library-linker-options-carbon-debug}" ¶
	-d profile-library-libraries="{profile-library-libraries-carbon-debug}" ¶
	-d profile-library-objects="{profile-library-objects-carbon-debug}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-carbon-debug}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-carbon-debug}" ¶
	-d comerr-library-objects="{comerr-library-objects-carbon-debug}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-carbon-debug}" ¶
	-d object-suffix="{object-suffix-carbon-debug}" ¶
	-d object-suffix-data="{object-suffix-carbon-data}" ¶
	-d compiler-options="{compiler-options-carbon-debug}" ¶
	-d compiler="{compiler-carbon}" ¶
	-d precompiled-headers="{precompiled-headers-carbon}"
	
make-options-carbon-final = ¶
	-d library-linker="{library-linker-carbon}" ¶
	-d library-platform="{library-target-carbon}" ¶
	-d library-kind="{library-kind-final}" ¶
	-d fragment-kind={fragment-name-carbon}{fragment-name-final-carbon} ¶
	-d gss-library-fragment-name={gss-library-fragment-name-carbon} ¶
	-d krb5-library-fragment-name={krb5-library-fragment-name-carbon} ¶
	-d privatekrb5-library-fragment-name={privatekrb5-library-fragment-name-carbon} ¶
	-d profile-library-fragment-name={profile-library-fragment-name-carbon} ¶
	-d comerr-library-fragment-name={comerr-library-fragment-name-carbon} ¶
	-d gss-library-libraries="{gss-library-libraries-carbon-final}" ¶
	-d gss-library-objects="{gss-library-objects-carbon-final}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-carbon-final}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-carbon-final}" ¶
	-d krb5-library-objects="{krb5-library-objects-carbon-final}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-carbon-final}" ¶
	-d privatekrb5-library-libraries="{privatekrb5-library-libraries-carbon-final}" ¶
	-d privatekrb5-library-objects="{privatekrb5-library-objects-carbon-final}" ¶
	-d privatekrb5-library-linker-options="{privatekrb5-library-linker-options-carbon-final}" ¶
	-d profile-library-libraries="{profile-library-libraries-carbon-final}" ¶
	-d profile-library-objects="{profile-library-objects-carbon-final}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-carbon-final}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-carbon-final}" ¶
	-d comerr-library-objects="{comerr-library-objects-carbon-final}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-carbon-final}" ¶
	-d object-suffix="{object-suffix-carbon-final}" ¶
	-d object-suffix-data="{object-suffix-carbon-data}" ¶
	-d compiler-options="{compiler-options-carbon-final}" ¶
	-d compiler="{compiler-carbon}" ¶
	-d precompiled-headers="{precompiled-headers-carbon}"
	
make-output = "{TempFolder}GSS/Kerberos Makefile script"
submakefile-gss-target = gss-library
submakefile-krb5-target = krb5-library

macos9-debug-build Ä glue headers documentation {makefile-dependency} {gss-objects-macos9-debug-list} {krb5-objects-macos9-debug-list} ¶
	{profile-objects-macos9-debug-list} {comerr-objects-macos9-debug-list} {include-folders-list}
	Make {make-options-common} {make-options-macos9-debug} {submakefile-gss-target} > {make-output}
	{make-output}
	Make {make-options-common} {make-options-macos9-debug} {submakefile-krb5-target} > {make-output}
	{make-output}
	
macos9-final-build Ä glue headers documentation  {makefile-dependency} {gss-objects-macos9-final-list} {krb5-objects-macos9-final-list} ¶
	{profile-objects-macos9-final-list} {comerr-objects-macos9-final-list} {include-folders-list}
	Make {make-options-common} {make-options-macos9-final} {submakefile-gss-target} > {make-output}
	{make-output}
	Make {make-options-common} {make-options-macos9-final} {submakefile-krb5-target} > {make-output}
	{make-output}
	
carbon-debug-build Ä glue headers documentation {makefile-dependency} {gss-objects-carbon-debug-list} {krb5-objects-carbon-debug-list} ¶
	{profile-objects-carbon-debug-list} {comerr-objects-carbon-debug-list} {include-folders-list}
	Make {make-options-common} {make-options-carbon-debug} {submakefile-gss-target} > {make-output}
	{make-output}
	Make {make-options-common} {make-options-carbon-debug} {submakefile-krb5-target} > {make-output}
	{make-output}
	
carbon-final-build Ä glue headers documentation  {makefile-dependency} {gss-objects-carbon-final-list} {krb5-objects-carbon-final-list} ¶
	{profile-objects-carbon-final-list} {comerr-objects-carbon-final-list} {include-folders-list}
	Make {make-options-common} {make-options-carbon-final} {submakefile-gss-target} > {make-output}
	{make-output}
	Make {make-options-common} {make-options-carbon-final} {submakefile-krb5-target} > {make-output}
	{make-output}
	
	
##############################################################################################################
###			Variable targets -- these depend on which target we select in the above make invocations
##############################################################################################################
###	We want the following to be defined in order for these targets to work:
###		For GSS library
###			gss-library-output-folder						-- destination of GSS library output
###			gss-library-name								-- name of the GSS library
###			gss-library-export								-- name of gss GSS library export file
###			gss-library-libraries							-- list of libraries GSS library links against
###			gss-library-objects								-- list of object files GSS library links
###			gss-library-fragment-name						-- name of GSS library fragment
###			gss-library-main								-- name of GSS library main entry point
###			gss-library-init								-- name of GSS library initialization routine
###			gss-library-term								-- name of GSS library termination routine
###			gss-library-linker-options						-- all other GSS library linker options
###		For Krb5 library
###			krb5-library-output-folder						-- destination of Krb5 library output
###			krb5-library-name								-- name of the Krb5 library
###			krb5-library-export								-- name of Krb5 library export file
###			krb5-library-libraries							-- list of libraries Krb5 library links against
###			krb5-library-objects							-- list of object files Krb5 library links
###			krb5-library-fragment-name						-- name of Krb5 library fragment
###			krb5-library-main								-- name of Krb5 library main entry point
###			krb5-library-init								-- name of Krb5 library initialization routine
###			krb5-library-term								-- name of Krb5 library termination routine
###			krb5-library-linker-options						-- all other Krb5 library linker options
###		For PrivateKrb5 library
###			privatekrb5-library-output-folder				-- destination of PrivateKrb5 library output
###			privatekrb5-library-name						-- name of the PrivateKrb5 library
###			privatekrb5-library-export						-- name of PrivateKrb5 library export file
###			privatekrb5-library-libraries					-- list of libraries PrivateKrb5 library links against
###			privatekrb5-library-objects						-- list of object files PrivateKrb5 library links
###			privatekrb5-library-fragment-name				-- name of PrivateKrb5 library fragment
###			privatekrb5-library-main						-- name of PrivateKrb5 library main entry point
###			privatekrb5-library-init						-- name of PrivateKrb5 library initialization routine
###			privatekrb5-library-term						-- name of PrivateKrb5 library termination routine
###			privatekrb5-library-linker-options				-- all other PrivateKrb5 library linker options
###		For profile library
###			profile-library-output-folder					-- destination of profile library output
###			profile-library-name							-- name of the profile library
###			profile-library-export							-- name of profile library export file
###			profile-library-libraries						-- list of libraries profile library links against
###			profile-library-objects							-- list of object files profile library links
###			profile-library-fragment-name					-- name of profile library fragment
###			profile-library-main							-- name of profile library main entry point
###			profile-library-init							-- name of profile library initialization routine
###			profile-library-term							-- name of profile library termination routine
###			profile-library-linker-options					-- all other profile library linker options
###		For comerr library
###			comerr-library-output-folder					-- destination of comerr library output
###			comerr-library-name								-- name of the comerr library
###			comerr-library-export							-- name of comerr library export file
###			comerr-library-libraries						-- list of libraries comerr library links against
###			comerr-library-objects							-- list of object files comerr library links
###			comerr-library-fragment-name					-- name of comerr library fragment
###			comerr-library-main								-- name of comerr library main entry point
###			comerr-library-init								-- name of comerr library initialization routine
###			comerr-library-term								-- name of comerr library termination routine
###			comerr-library-linker-options					-- all other comerr library linker options
###		General
###			library-linker									-- linker to use
###			autogenerated-files								-- list of autogenerated files
###			library-platform								-- platform name (69K or PPC)
###			library-kind									-- library kind ("d" or "")
###			fragment-kind									-- fragment kind (Carbon, debug, etc)


### script to create a folder if it does not exist
create-folder = {root-folder}mac:create-folder.mpw


### defaults, will be set to something better by the make commands above
library-linker =
library-platform =
library-kind =
fragment-kind =
gss-library-libraries =
gss-library-objects =
gss-library-linker-options =
krb5-library-libraries =
krb5-library-objects =
krb5-library-linker-options =
privatekrb5-library-libraries =
privatekrb5-library-objects =
privatekrb5-library-linker-options =
precompiled-headers =
object-suffix = .ignore.me
object-suffix-data = .ignore.me.too
profile-library-libraries =
profile-library-objects =
profile-library-linker-options =
comerr-library-libraries =
comerr-library-objects =
comerr-library-linker-options =

###	Generate various major components of build commands from the above variables
gss-library-output-files = ¶
	{gss-library-output-folder}{gss-library-name}{library-platform}{library-kind}
gss-library-dependencies = ¶
	headers {autogenerated-files} {gss-library-export} {gss-library-libraries} {gss-library-objects}
gss-library-build-command = ¶
	{library-linker} ¶
	-name "{gss-library-fragment-name}{fragment-kind}" ¶
	-main {gss-library-main} ¶
	-init {gss-library-init} ¶
	-term {gss-library-term} ¶
	-@export {gss-library-export} ¶
	-map {gss-library-output-folder}{gss-library-name}{library-platform}{library-kind}.MAP ¶
	-o {gss-library-output-folder}{gss-library-name}{library-platform}{library-kind} ¶
	{gss-library-linker-options} ¶
	{gss-library-objects} {gss-library-libraries}
	
krb5-library-output-files = ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind}
krb5-library-dependencies = ¶
	headers {autogenerated-files} {krb5-library-export} {krb5-library-libraries} {krb5-library-objects}
krb5-library-build-command = ¶
	{library-linker} ¶
	-name "{krb5-library-fragment-name}{fragment-kind}" ¶
	-main {krb5-library-main} ¶
	-init {krb5-library-init} ¶
	-term {krb5-library-term} ¶
	-@export {krb5-library-export} ¶
	-map {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind}.MAP ¶
	-o {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind} ¶
	{krb5-library-linker-options} ¶
	{krb5-library-objects} {krb5-library-libraries}

privatekrb5-library-output-files = ¶
	{privatekrb5-library-output-folder}{privatekrb5-library-name}{library-platform}{library-kind}
privatekrb5-library-dependencies = ¶
	headers {autogenerated-files} {privatekrb5-library-export} {privatekrb5-library-libraries} {privatekrb5-library-objects}
privatekrb5-library-build-command = ¶
	{library-linker} ¶
	-name "{privatekrb5-library-fragment-name}{fragment-kind}" ¶
	-main {privatekrb5-library-main} ¶
	-init {privatekrb5-library-init} ¶
	-term {privatekrb5-library-term} ¶
	-@export {privatekrb5-library-export} ¶
	-@export {krb5-library-export} ¶
	-map {privatekrb5-library-output-folder}{privatekrb5-library-name}{library-platform}{library-kind}.MAP ¶
	-o {privatekrb5-library-output-folder}{privatekrb5-library-name}{library-platform}{library-kind} ¶
	{privatekrb5-library-linker-options} ¶
	{privatekrb5-library-objects} {privatekrb5-library-libraries}

profile-library-output-files = ¶
	{profile-library-output-folder}{profile-library-name}{library-platform}{library-kind}
profile-library-dependencies = ¶
	headers {autogenerated-files} {profile-library-export} {profile-library-libraries} {profile-library-objects}
profile-library-build-command = ¶
	{library-linker} ¶
	-name "{profile-library-fragment-name}{fragment-kind}" ¶
	-main {profile-library-main} ¶
	-init {profile-library-init} ¶
	-term {profile-library-term} ¶
	-@export {profile-library-export} ¶
	-map {profile-library-output-folder}{profile-library-name}{library-platform}{library-kind}.MAP ¶
	-o {profile-library-output-folder}{profile-library-name}{library-platform}{library-kind} ¶
	{profile-library-linker-options} ¶
	{profile-library-objects} {profile-library-libraries}

comerr-library-output-files = ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform}{library-kind}
comerr-library-dependencies = ¶
	headers {autogenerated-files} {comerr-library-export} {comerr-library-libraries} {comerr-library-objects}
comerr-library-build-command = ¶
	{library-linker} ¶
	-name "{comerr-library-fragment-name}{fragment-kind}" ¶
	-main {comerr-library-main} ¶
	-init {comerr-library-init} ¶
	-term {comerr-library-term} ¶
	-@export {comerr-library-export} ¶
	-map {comerr-library-output-folder}{comerr-library-name}{library-platform}{library-kind}.MAP ¶
	-o {comerr-library-output-folder}{comerr-library-name}{library-platform}{library-kind} ¶
	{comerr-library-linker-options} ¶
	{comerr-library-objects} {comerr-library-libraries}

###	Build commands

gss-library Ä {gss-library-output-files}
krb5-library Ä {krb5-library-output-files}
privatekrb5-library Ä {privatekrb5-library-output-files}
profile-library Ä {profile-library-output-files}
comerr-library Ä {comerr-library-output-files}

{gss-library-output-files} ÄÄ {gss-library-dependencies} {makefile-dependency}
	{create-folder} {gss-library-output-folder}
	{gss-library-build-command}
	
{krb5-library-output-files} ÄÄ {krb5-library-dependencies} {makefile-dependency}
	{create-folder} {krb5-library-output-folder}
	{krb5-library-build-command}

{privatekrb5-library-output-files} ÄÄ {privatekrb5-library-dependencies} {makefile-dependency}
	{create-folder} {privatekrb5-library-output-folder}
	{privatekrb5-library-build-command}

{profile-library-output-files} ÄÄ {profile-library-dependencies} {makefile-dependency}
	{create-folder} {profile-library-output-folder}
	{profile-library-build-command}

{comerr-library-output-files} ÄÄ {comerr-library-dependencies} {makefile-dependency}
	{create-folder} {comerr-library-output-folder}
	{comerr-library-build-command}

##############################################################################################################
###			Default compilation rules
##############################################################################################################

{object-suffix} Ä .c {autogenerated-files} {makefile-dependency} {precompiled-headers}
	echo {DepDir}{Default}{object-suffix}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix} {compiler-options} -i "{CWANSIIncludes}sys" 

{object-suffix-data} Ä .c {autogenerated-files} {makefile-dependency} {precompiled-headers}
	echo {DepDir}{Default}{object-suffix-data}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix-data} {compiler-options} -i "{CWANSIIncludes}sys" 

##############################################################################################################
###			Autogenerating classic 68K glue files
##############################################################################################################

classic-glue-generation-script 						= {root-folder}mac:CFMGlue.pl
gss-library-glue-output-folder						= {root-folder}:GSSLib:ClassicGlue:
krb5-library-glue-output-folder						= {root-folder}:Kerberos5Lib:ClassicGlue:
profile-library-glue-output-folder					= {root-folder}:KerberosProfileLib:ClassicGlue:
comerr-library-glue-output-folder					= {root-folder}:ComErrLib:ClassicGlue:

gss-library-glue-output								= {gss-library-glue-output-folder}GSSLib.glue.c {gss-library-glue-output-folder}GSSLib.glue.h
krb5-library-glue-output							= {krb5-library-glue-output-folder}Kerberos5Lib.glue.c {krb5-library-glue-output-folder}Kerberos5Lib.glue.h
profile-library-glue-output							= {profile-library-glue-output-folder}KrbProfileLib.glue.c {profile-library-glue-output-folder}KrbProfileLib.glue.h
comerr-library-glue-output							= {comerr-library-glue-output-folder}ComErrLib.glue.c {comerr-library-glue-output-folder}ComErrLib.glue.h

classic-glue-output = ¶
	{gss-library-glue-output} ¶
	{krb5-library-glue-output} ¶
	{profile-library-glue-output} ¶
	{comerr-library-glue-output}

glue Ä {classic-glue-output}

glue-gss Ä {gss-library-glue-output}
glue-krb5 Ä {krb5-library-glue-output}
glue-profile Ä {profile-library-glue-output}
glue-comerr Ä {comerr-library-glue-output}

{krb5-library-glue-output} Ä {root-folder}mac:K5.CFMglue.cin {root-folder}mac:K5.CFMglue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:GSSLib.glue.h {root-folder}mac:K5.moreCFMglue.cin {classic-glue-generation-script}
	{create-folder} {krb5-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:K5.CFMglue.proto.h > {root-folder}mac:K5.CFMglue.c
	Catenate {root-folder}mac:K5.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:K5.CFMglue.c ¶
	{root-folder}mac:K5.moreCFMglue.cin | Catenate > {krb5-library-glue-output-folder}Kerberos5Lib.glue.c
	Duplicate -y {root-folder}mac:Kerberos5Lib.glue.h {krb5-library-glue-output-folder}Kerberos5Lib.glue.h

{gss-library-glue-output} Ä {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:GSS.CFMglue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:Kerberos5Lib.glue.h {root-folder}mac:GSS.moreCFMglue.cin {classic-glue-generation-script}
	{create-folder} {gss-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:GSS.CFMglue.proto.h > {root-folder}mac:GSS.CFMglue.c
	Catenate {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:GSS.CFMglue.c ¶
	{root-folder}mac:GSS.moreCFMglue.cin | Catenate > {gss-library-glue-output-folder}GSSLib.glue.c
	Duplicate -y {root-folder}mac:GSSLib.glue.h {gss-library-glue-output-folder}GSSLib.glue.h

{profile-library-glue-output} Ä {root-folder}mac:KrbProfileLib.glue.pre.cin {root-folder}mac:KrbProfileLib.glue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:KrbProfileLib.glue.h {root-folder}mac:KrbProfileLib.glue.post.cin {classic-glue-generation-script}
	{create-folder} {profile-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:KrbProfileLib.glue.proto.h > {root-folder}mac:KrbProfileLib.CFMglue.c
	Catenate {root-folder}mac:KrbProfileLib.glue.pre.cin {root-folder}mac:CFMglue.c {root-folder}mac:KrbProfileLib.CFMglue.c ¶
	{root-folder}mac:KrbProfileLib.glue.post.cin | Catenate > {profile-library-glue-output-folder}KrbProfileLib.glue.c
	Duplicate -y {root-folder}mac:KrbProfileLib.glue.h {profile-library-glue-output-folder}KrbProfileLib.glue.h

{comerr-library-glue-output} Ä {root-folder}mac:ComErrLib.glue.pre.cin {root-folder}mac:ComErrLib.glue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:ComErrLib.glue.h {root-folder}mac:ComErrLib.glue.post.cin {classic-glue-generation-script}
	{create-folder} {comerr-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:ComErrLib.glue.proto.h > {root-folder}mac:ComErrLib.CFMglue.c
	Catenate {root-folder}mac:ComErrLib.glue.pre.cin {root-folder}mac:CFMglue.c {root-folder}mac:ComErrLib.CFMglue.c ¶
	{root-folder}mac:ComErrLib.glue.post.cin | Catenate > {comerr-library-glue-output-folder}ComErrLib.glue.c
	Duplicate -y {root-folder}mac:ComErrLib.glue.h {comerr-library-glue-output-folder}ComErrLib.glue.h

##############################################################################################################
###			Clean target deletes all generated files
##############################################################################################################

clean Ä
	# Need a dummy invalid name at the end to cover the case when nothing is found
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-macos9-debug}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-macos9-final}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-macos9-data}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-carbon-debug}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-carbon-final}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-carbon-data}/ Print"` supercalifragilisticexpialidoucious
	Delete -i {all-lists} {autogenerated-files}
	
##############################################################################################################
###			Copying headers around
##############################################################################################################

gss-headers-output-folder							= {root-folder}:GSSLib:Headers:GSS:
krb5-headers-output-folder							= {root-folder}:Kerberos5Lib:Headers:Kerberos5:
comerr-headers-output-folder						= {root-folder}:ComErrLib:Headers:KerberosComErr:
profile-headers-output-folder						= {root-folder}:KerberosProfileLib:Headers:KerberosProfile:

gss-headers-output = ¶
	"{gss-headers-output-folder}gssapi.h" ¶
	"{gss-headers-output-folder}GSS.h" ¶
	"{gss-headers-output-folder}gssapi_krb5.h"

krb5-headers-output = ¶
	"{krb5-headers-output-folder}krb5.h" ¶
	"{krb5-headers-output-folder}Kerberos5.h" ¶
	"{krb5-headers-output-folder}win-mac.h"

comerr-headers-output = ¶
	"{comerr-headers-output-folder}com_err.h" ¶
	"{comerr-headers-output-folder}KerberosComErr.h"
	
profile-headers-output = ¶
	"{profile-headers-output-folder}profile.h" ¶
	"{profile-headers-output-folder}KerberosProfile.h"
	
headers-output = {gss-headers-output} {krb5-headers-output} ¶
	{comerr-headers-output} {profile-headers-output} 

headers Ä unset-echo {headers-output}

"{gss-headers-output-folder}GSS.h" Ä {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Echo "#include <GSS/gssapi.h>" > "{Targ}"
	Echo "#include <GSS/gssapi_krb5.h>" >> "{Targ}"
	SetFile -a l "{Targ}"

"{gss-headers-output-folder}gssapi.h" Ä "{root-folder}lib:gssapi:generic:gssapi.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}lib:gssapi:generic:gssapi.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{gss-headers-output-folder}gssapi_krb5.h" Ä "{root-folder}lib:gssapi:krb5:gssapi_krb5.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}lib:gssapi:krb5:gssapi_krb5.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{krb5-headers-output-folder}Kerberos5.h" Ä "{root-folder}include:krb5.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Echo "#include <Kerberos5/krb5.h>" > "{Targ}"
	SetFile -a l "{Targ}"

"{krb5-headers-output-folder}krb5.h" Ä "{root-folder}include:krb5.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}include:krb5.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{krb5-headers-output-folder}win-mac.h" Ä "{root-folder}include:win-mac.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}include:win-mac.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{comerr-headers-output-folder}KerberosComErr.h" Ä "{root-folder}util:et:com_err.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Echo "#include <KerberosComErr/com_err.h>" > "{Targ}"
	SetFile -a l "{Targ}"

"{comerr-headers-output-folder}com_err.h" Ä "{root-folder}util:et:com_err.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}util:et:com_err.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{profile-headers-output-folder}KerberosProfile.h" Ä "{root-folder}util:profile:profile.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Echo "#include <KerberosProfile/profile.h>" > "{Targ}"
	SetFile -a l "{Targ}"

"{profile-headers-output-folder}profile.h" Ä "{root-folder}util:profile:profile.h" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}util:profile:profile.h" > "{Targ}"
	SetFile -a l "{Targ}"

##############################################################################################################
###			Copying documentation around
##############################################################################################################

gss-documentation-output-folder						= {root-folder}:GSSLib:Documentation:
krb5-documentation-output-folder					= {root-folder}:Kerberos5Lib:Documentation:
comerr-documentation-output-folder					= {root-folder}:ComErrLib:Documentation:
profile-documentation-output-folder					= {root-folder}:KerberosProfileLib:Documentation:

gss-documentation-output = ¶
	{gss-documentation-output-folder}"GSSLib ReadMe"

krb5-documentation-output = ¶
	{krb5-documentation-output-folder}"krb5api.pdf"

comerr-documentation-output = ¶
	{comerr-documentation-output-folder}"ComErrLib ReadMe"
	
profile-documentation-output = ¶
	{profile-documentation-output-folder}"KerberosProfileLib ReadMe"
	
documentation-output = {gss-documentation-output} {krb5-documentation-output} ¶
	{profile-documentation-output} {comerr-documentation-output}

documentation Ä unset-echo {documentation-output}

{gss-documentation-output-folder}"GSSLib ReadMe" Ä {root-folder}"mac:GSSLib ReadMe" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:GSSLib ReadMe" > {Targ}
	SetFile -a l {Targ}

{krb5-documentation-output-folder}"krb5api.pdf" Ä {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	If (`Exists {root-folder}":::Documentation:pdf:krb5api.pdf"`)
		Catenate {root-folder}":::Documentation:pdf:krb5api.pdf" > {Targ}
		SetFile -a l -t 'PDF ' -c 'CARO' {Targ}
	End

{comerr-documentation-output-folder}"ComErrLib ReadMe" Ä {root-folder}"mac:ComErrLib ReadMe" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:ComErrLib ReadMe" > {Targ}
	SetFile -a l {Targ}

{profile-documentation-output-folder}"KerberosProfileLib ReadMe" Ä {root-folder}"mac:KerberosProfileLib ReadMe" {makefile-dependency}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:KerberosProfileLib ReadMe" > {Targ}
	SetFile -a l {Targ}

##############################################################################################################
###			Important global constants
##############################################################################################################

root-folder											= ::
mitsupportlib-root-folder							= {root-folder}:::MITSupportLib:
mitkerberoslib-root-folder							= {root-folder}:
makefile-name										= {root-folder}mac:Makefile

library-output-folder								= {root-folder}bin:

library-platform-PPC					= .PPC

library-kind-debug						= .debug
library-kind-final						=

##############################################################################################################
###			Top-level targets -- abstract targets for convenient grouping
##############################################################################################################

#	Everything
all Ä unset-echo all-debug all-final

#	Debugging versions
all-debug Ä unset-echo ppc-debug

#	Final versions
all-final Ä unset-echo ppc-final

#	Clasic 68K glue
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
krb5-library-output-folder							= {root-folder}:Kerberos5Lib:Binaries:
profile-library-output-folder						= {root-folder}:KerberosProfileLib:Binaries:
comerr-library-output-folder						= {root-folder}:ComErrLib:Binaries:

gss-library-name									= GSSLib
krb5-library-name									= Kerberos5Lib
profile-library-name								= KrbProfileLib
comerr-library-name									= ComErrLib

gss-library-export									= {root-folder}mac:GSSLibrary.exp
krb5-library-export									= {root-folder}mac:K5Library.exp
profile-library-export								= {root-folder}util:profile:profile.exp
comerr-library-export								= {root-folder}util:et:et.exp

gss-library-fragment-name							= "GSSLibrary"
krb5-library-fragment-name							= "MIT Kerberos¥Kerberos5Lib"
profile-library-fragment-name						= "MIT Kerberos¥KerberosProfileLib"
comerr-library-fragment-name						= "MIT Kerberos¥ComErrLib"

gss-library-main									= ¶"¶"
krb5-library-main									= ¶"¶"
profile-library-main								= ¶"¶"
comerr-library-main									= ¶"¶"

gss-library-init									= __initializeGSS
krb5-library-init									= __initializeK5
profile-library-init								= InitializeProfileLib
comerr-library-init									= __initialize
	
gss-library-term 									= __terminateGSS
krb5-library-term									= __terminateK5
profile-library-term								= TerminateProfileLib
comerr-library-term									= __terminate

gss-library-current-version							= 1
gss-library-definition-version						= 0
gss-library-implementation-version					= 1

krb5-library-current-version						= 4
krb5-library-definition-version						= 4
krb5-library-implementation-version					= 4

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
list-generation-script = "{list-generation-script-folder}macfile_gen.pl"
list-generation-script-root = ".."

all-files-list									= {root-folder}"All files.list"
all-sources-list								= {root-folder}"All sources.list"
all-folders-list								= {root-folder}"All folders.list"
include-folders-list							= {root-folder}"Include folders.list"

gss-sources-list								= {root-folder}"GSS sources.list"
krb5-sources-list								= {root-folder}"Krb5 sources.list"
profile-sources-list							= {root-folder}"Profile sources.list"

gss-objects-ppc-debug-list						= {root-folder}"GSS objects PPC debug.list"
gss-objects-ppc-final-list						= {root-folder}"GSS objects PPC final.list"

krb5-objects-ppc-debug-list						= {root-folder}"Krb5 objects PPC debug.list"
krb5-objects-ppc-final-list						= {root-folder}"Krb5 objects PPC final.list"

profile-objects-ppc-debug-list					= {root-folder}"Profile objects PPC debug.list"
profile-objects-ppc-final-list					= {root-folder}"Profile objects PPC final.list"

comerr-objects-ppc-debug-list					= {root-folder}"ComErr objects PPC debug.list"
comerr-objects-ppc-final-list					= {root-folder}"ComErr objects PPC final.list"

all-lists = ¶
	{all-files-list} ¶
	{all-sources-list} ¶
	{all-folders-list} ¶
	{include-folders-list} ¶
	{gss-sources-list} ¶
	{krb5-sources-list} ¶
	{gss-objects-ppc-debug-list} ¶
	{gss-objects-ppc-final-list} ¶
	{krb5-objects-ppc-debug-list} ¶
	{krb5-objects-ppc-final-list} ¶
	{profile-objects-ppc-debug-list} ¶
	{profile-objects-ppc-final-list} ¶
	{comerr-objects-ppc-debug-list} ¶
	{comerr-objects-ppc-final-list}

file-lists Ä {all-lists}

# Note that even though the list generation script tries to have a mechanism allowing you to run it
# in different directories, it actually doesn't work too well because it wants a UNIX-style relative
# path to root Makefile.in. This is why we run it with -x to specify the root.

{all-files-list} Ä {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-files {list-generation-script-root} ¶
 > {Targ}

{all-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{all-folders-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} all-folders {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{include-folders-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} include-folders {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-sources {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-ppc-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{gss-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} gss-objects-ppc-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-ppc-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{krb5-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} krb5-objects-ppc-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-ppc-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{profile-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} profile-objects-ppc-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-ppc-debug {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

{comerr-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl -x"{list-generation-script-working-folder}" {list-generation-script} comerr-objects-ppc-final {list-generation-script-root} ¶
 < {all-files-list} > {Targ}

##############################################################################################################
###			Autogenerated files
##############################################################################################################

autogeneration-h-script = {root-folder}util:et:et_h.perl
autogeneration-c-script = {root-folder}util:et:et_c.perl

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
	{root-folder}lib:gssapi:generic:gssapi.h ¶
	{root-folder}include:autoconf.h

###			error table headers

{root-folder}include:asn1_err.h Ä {root-folder}lib:krb5:error_tables:asn1_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}include:asn1_err.h" < "{root-folder}lib:krb5:error_tables:asn1_err.et"

{root-folder}include:kdb5_err.h Ä {root-folder}lib:krb5:error_tables:kdb5_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}include:kdb5_err.h" < "{root-folder}lib:krb5:error_tables:kdb5_err.et"

{root-folder}include:krb5_err.h Ä {root-folder}lib:krb5:error_tables:krb5_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}include:krb5_err.h" < "{root-folder}lib:krb5:error_tables:krb5_err.et"

{root-folder}include:kv5m_err.h Ä {root-folder}lib:krb5:error_tables:kv5m_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}include:kv5m_err.h" < "{root-folder}lib:krb5:error_tables:kv5m_err.et"

{root-folder}include:adm_err.h Ä {root-folder}lib:krb5:error_tables:adm_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}include:adm_err.h" < "{root-folder}lib:krb5:error_tables:adm_err.et"
	
{root-folder}lib:gssapi:generic:gssapi_err_generic.h Ä {root-folder}lib:gssapi:generic:gssapi_err_generic.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}lib:gssapi:generic:gssapi_err_generic.h" < "{root-folder}lib:gssapi:generic:gssapi_err_generic.et"
	
{root-folder}lib:gssapi:krb5:gssapi_err_krb5.h Ä {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}lib:gssapi:krb5:gssapi_err_krb5.h" < "{root-folder}lib:gssapi:krb5:gssapi_err_krb5.et"

{root-folder}util:profile:prof_err.h Ä {root-folder}util:profile:prof_err.et {makefile-name} {autogeneration-h-script}
	perl {autogeneration-h-script} outfile="{root-folder}util:profile:prof_err.h" < "{root-folder}util:profile:prof_err.et"

###			error table sources

{root-folder}lib:krb5:error_tables:asn1_err.c Ä {root-folder}lib:krb5:error_tables:asn1_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:asn1_err.c" < "{root-folder}lib:krb5:error_tables:asn1_err.et"

{root-folder}lib:krb5:error_tables:kdb5_err.c Ä {root-folder}lib:krb5:error_tables:kdb5_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:kdb5_err.c" < "{root-folder}lib:krb5:error_tables:kdb5_err.et"

{root-folder}lib:krb5:error_tables:krb5_err.c Ä {root-folder}lib:krb5:error_tables:krb5_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:krb5_err.c" < "{root-folder}lib:krb5:error_tables:krb5_err.et"

{root-folder}lib:krb5:error_tables:kv5m_err.c Ä {root-folder}lib:krb5:error_tables:kv5m_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:kv5m_err.c" < "{root-folder}lib:krb5:error_tables:kv5m_err.et"

{root-folder}lib:krb5:error_tables:adm_err.c Ä {root-folder}lib:krb5:error_tables:adm_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:krb5:error_tables:adm_err.c" < "{root-folder}lib:krb5:error_tables:adm_err.et"

{root-folder}lib:gssapi:generic:gssapi_err_generic.c Ä {root-folder}lib:gssapi:generic:gssapi_err_generic.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:gssapi:generic:gssapi_err_generic.c" < "{root-folder}lib:gssapi:generic:gssapi_err_generic.et"

{root-folder}lib:gssapi:krb5:gssapi_err_krb5.c Ä {root-folder}lib:gssapi:krb5:gssapi_err_krb5.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}lib:gssapi:krb5:gssapi_err_krb5.c" < "{root-folder}lib:gssapi:krb5:gssapi_err_krb5.et"

{root-folder}util:profile:prof_err.c Ä {root-folder}util:profile:prof_err.et {makefile-name} {autogeneration-c-script}
	perl {autogeneration-c-script} outfile="{root-folder}util:profile:prof_err.c" < "{root-folder}util:profile:prof_err.et"

###			other autogenerated files

{root-folder}include:krb5.h Ä {root-folder}include:krb5.hin {root-folder}include:krb5_err.h ¶
	{root-folder}include:kdb5_err.h {root-folder}include:kv5m_err.h {root-folder}include:asn1_err.h
	Catenate {root-folder}include:krb5.hin {root-folder}include:krb5_err.h {root-folder}include:kdb5_err.h ¶
	{root-folder}include:kv5m_err.h {root-folder}include:asn1_err.h > {root-folder}include:krb5.h
	
{root-folder}util:profile:profile.h Ä {root-folder}util:profile:profile.hin {root-folder}util:profile:prof_err.h
	Catenate {root-folder}util:profile:profile.hin {root-folder}util:profile:prof_err.h > {root-folder}util:profile:profile.h
	
{root-folder}include:profile.h Ä {root-folder}util:profile:profile.h
	Catenate {root-folder}util:profile:profile.h > {root-folder}include:profile.h
	SetFile -a l "{Targ}"

{root-folder}include:krb5:osconf.h Ä {root-folder}include:krb5:stock:osconf.h
	Catenate {root-folder}include:krb5:stock:osconf.h > {root-folder}include:krb5:osconf.h
	SetFile -a l "{Targ}"

{root-folder}lib:gssapi:generic:gssapi.h Ä {root-folder}lib:gssapi:generic:gssapi.hin
	Catenate {root-folder}lib:gssapi:generic:gssapi.hin > {root-folder}lib:gssapi:generic:gssapi.h
	SetFile -a l "{Targ}"
	
{root-folder}include:autoconf.h Ä {root-folder}mac:libraries:autoconf.h
	Catenate {root-folder}mac:libraries:autoconf.h > {root-folder}include:autoconf.h
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
###			library-platform								-- platform name (68K or PPC)
###			library-kind									-- library kind (".debug" or "")
###			object-suffix									-- object file suffix (.ppcf.o, .ppcd.o, .68kf.o, .68kd.o)
###			object-suffix-data								-- object file suffix fdor data libraries (.ppc.o, .68k.o)


### The following variables are platform- or kind-specific, but constant

clib-ppc-debug						= {mitsupportlib-root-folder}CLib:Binaries:CLib.PPC.debug
clib-ppc-final						= {mitsupportlib-root-folder}CLib:Binaries:CLib.PPC

runtimelib-ppc-debug				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.PPC.debug
runtimelib-ppc-final				= {mitsupportlib-root-folder}RuntimeLib:Binaries:RuntimeLib.PPC

runtimelib-static-ppc-debug			= {mitsupportlib-root-folder}"RuntimeLib:Binaries:ShlibRuntime.Lib.PPC.debug"
runtimelib-static-ppc-final			= {mitsupportlib-root-folder}"RuntimeLib:Binaries:ShlibRuntime.Lib.PPC"

standard-libraries-ppc-debug			= ¶
	"{clib-ppc-debug}" ¶
	"{runtimelib-ppc-debug}" ¶
	"{runtimelib-static-ppc-debug}" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}MathLib¶"
standard-libraries-ppc-final			= ¶
	"{clib-ppc-final}" ¶
	"{runtimelib-ppc-final}" ¶
	"{runtimelib-static-ppc-final}" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}MathLib¶"

ccachelib-ppc-debug						= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.PPC.debug
ccachelib-ppc-final						= {mitkerberoslib-root-folder}CCacheLib:Binaries:CCacheLib.PPC

loginlib-ppc-debug						= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.PPC.debug
loginlib-ppc-final						= {mitkerberoslib-root-folder}LoginLib:Binaries:KrbLoginLib.stub.PPC

socketslib-ppc-debug					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.PPC.debug
socketslib-ppc-final					= {mitsupportlib-root-folder}SocketsLib:Binaries:SocketsLib.PPC

errorlib-ppc-debug						= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.PPC.debug
errorlib-ppc-final						= {mitsupportlib-root-folder}ErrorLib:Binaries:ErrorLib.PPC

utilitieslib-ppc-debug					= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.PPC.debug
utilitieslib-ppc-final					= {mitsupportlib-root-folder}UtilitiesLib:Binaries:UtilitiesLib.PPC

object-suffix-ppc-debug					= .ppcd.o
object-suffix-ppc-final					= .ppcf.o
object-suffix-ppc-data					= .ppc.o

gss-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-debug}
gss-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-platform-ppc}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-final}

krb5-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{ccachelib-ppc-debug} ¶
	{loginlib-ppc-debug} ¶
	{socketslib-ppc-debug} ¶
	{errorlib-ppc-debug} ¶
	{profile-library-output-folder}{profile-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-debug} ¶
	¶"{PPCLibraries}PPCMath64Lib.o¶" ¶
	¶"{SharedLibraries}DriverServicesLib¶"
krb5-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{ccachelib-ppc-final} ¶
	{loginlib-ppc-final} ¶
	{socketslib-ppc-final} ¶
	{errorlib-ppc-final} ¶
	{profile-library-output-folder}{profile-library-name}{library-platform-ppc}{library-kind-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-final} ¶
	¶"{PPCLibraries}PPCMath64Lib.o¶" ¶
	¶"{SharedLibraries}DriverServicesLib¶"

profile-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{utilitieslib-ppc-debug} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-debug}
profile-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{utilitieslib-ppc-final} ¶
	{comerr-library-output-folder}{comerr-library-name}{library-platform-ppc}{library-kind-final}

comerr-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} {errorlib-ppc-debug}
comerr-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} {errorlib-ppc-final}

### Construct linker options. 

common-linker-options = -sharedlibrary
common-linker-options-debug = {common-linker-options} -sym on
common-linker-options-final = {common-linker-options} -sym off

gss-library-common-linker-options = ¶
	-cv {gss-library-current-version} ¶
	-dv {gss-library-definition-version} ¶
	-uv {gss-library-implementation-version}

gss-library-linker-options-ppc-debug = {common-linker-options-debug} {gss-library-common-linker-options}
gss-library-linker-options-ppc-final = {common-linker-options-final} {gss-library-common-linker-options}

krb5-library-common-linker-options = ¶
	-cv {krb5-library-current-version} ¶
	-dv {krb5-library-definition-version} ¶
	-uv {krb5-library-implementation-version}

krb5-library-linker-options-ppc-debug = {common-linker-options-debug} {krb5-library-common-linker-options} -weaklib "DriverServicesLib"
krb5-library-linker-options-ppc-final = {common-linker-options-final} {krb5-library-common-linker-options} -weaklib "DriverServicesLib"

profile-library-common-linker-options = ¶
	-cv {profile-library-current-version} ¶
	-dv {profile-library-definition-version} ¶
	-uv {profile-library-implementation-version}

profile-library-linker-options-ppc-debug = {common-linker-options-debug} {profile-library-common-linker-options}
profile-library-linker-options-ppc-final = {common-linker-options-final} {profile-library-common-linker-options}

comerr-library-common-linker-options = ¶
	-cv {comerr-library-current-version} ¶
	-dv {comerr-library-definition-version} ¶
	-uv {comerr-library-implementation-version}

comerr-library-linker-options-ppc-debug = {common-linker-options-debug} {comerr-library-common-linker-options}
comerr-library-linker-options-ppc-final = {common-linker-options-final} {comerr-library-common-linker-options}

gss-library-objects-ppc-debug = `catenate {gss-objects-ppc-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-ppc-debug}
gss-library-objects-ppc-final = `catenate {gss-objects-ppc-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:GSS.CFM{object-suffix-ppc-final}

krb5-library-objects-ppc-debug = `catenate {krb5-objects-ppc-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-ppc-debug}
krb5-library-objects-ppc-final = `catenate {krb5-objects-ppc-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:K5.CFM{object-suffix-ppc-final}

profile-library-objects-ppc-debug = `catenate {profile-objects-ppc-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-ppc-debug}
profile-library-objects-ppc-final = `catenate {profile-objects-ppc-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"` ¶
	{root-folder}mac:ProfileLib.CFM{object-suffix-ppc-final}

comerr-library-objects-ppc-debug = `catenate {comerr-objects-ppc-debug-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`
comerr-library-objects-ppc-final = `catenate {comerr-objects-ppc-final-list} | StreamEdit -d -set prefix="{root-folder}" -e "/¥:(Å)¨2/ Print prefix¨2"`

library-linker-ppc						= MWLinkPPC

### Construct compiler options.

common-compiler-options = ¶
		-enum int -opt all -strings pool -mapcr ¶
        -mpw_pointers -warnings off -fatext -nosyspath -maxerrors 1000 ¶
        -align mac68k -opt off -toc_data on -fp_contract on ¶
		-model farData

# Don't put the prefix file in these options because they are used to precompile the prefix file
ppc-compiler-options = -tb on
debug-compiler-options = -sym on
final-compiler-options = -sym off

mitsupportlib-include-paths = ¶
	-i {mitsupportlib-root-folder}SocketsLib:Headers: ¶
	-i {mitsupportlib-root-folder}ErrorLib:Headers: ¶
	-i {mitsupportlib-root-folder}UtilitiesLib:Headers:

include-paths = `catenate {include-folders-list} | StreamEdit -d -set prefix="{root-folder}mac:" -e "/-i (Å)¨1/ Print '-i 'prefix¨1"` ¶
	-i {mitkerberoslib-root-folder}CCacheLib:Headers: ¶
	-i {mitkerberoslib-root-folder}LoginLib:Headers: ¶
	{mitsupportlib-include-paths}
		
compiler-options-ppc-debug = {include-paths} {common-compiler-options} {ppc-compiler-options} ¶
	{debug-compiler-options} -prefix {precompiled-headers-ppc}
compiler-options-ppc-final = {include-paths} {common-compiler-options} {ppc-compiler-options} ¶
	{final-compiler-options} -prefix {precompiled-headers-ppc}

compiler-ppc							= MWCPPC

### Precompiled headers

precompiled-headers-folder = {root-folder}mac:libraries:

precompiled-headers-ppc = {precompiled-headers-folder}KerberosHeaders.PPC

precompiled-headers-source = {precompiled-headers-folder}KerberosHeaders.pch

{precompiled-headers-ppc} Ä {precompiled-headers-source} {precompiled-headers-folder}KerberosHeaders.h
	{compiler-ppc} {precompiled-headers-source} {common-compiler-options} {ppc-compiler-options} ¶
		-precompile {Targ} -i {precompiled-headers-folder} {mitsupportlib-include-paths}

make-options-common = ¶
	-f {makefile-name} ¶
	-d root-folder="{root-folder}" ¶
	-d autogenerated-files="{autogenerated-files}" ¶
	-d gss-library-output-folder="{gss-library-output-folder}" ¶
	-d gss-library-name="{gss-library-name}" ¶
	-d gss-library-export="{gss-library-export}" ¶
	-d gss-library-fragment-name={gss-library-fragment-name} ¶
	-d gss-library-main="{gss-library-main}" ¶
	-d gss-library-init="{gss-library-init}" ¶
	-d gss-library-term="{gss-library-term}" ¶
	-d krb5-library-output-folder="{krb5-library-output-folder}" ¶
	-d krb5-library-name="{krb5-library-name}" ¶
	-d krb5-library-export="{krb5-library-export}" ¶
	-d krb5-library-fragment-name={krb5-library-fragment-name} ¶
	-d krb5-library-main="{krb5-library-main}" ¶
	-d krb5-library-init="{krb5-library-init}" ¶
	-d krb5-library-term="{krb5-library-term}" ¶
	-d profile-library-output-folder="{profile-library-output-folder}" ¶
	-d profile-library-name="{profile-library-name}" ¶
	-d profile-library-export="{profile-library-export}" ¶
	-d profile-library-fragment-name={profile-library-fragment-name} ¶
	-d profile-library-main="{profile-library-main}" ¶
	-d profile-library-init="{profile-library-init}" ¶
	-d profile-library-term="{profile-library-term}" ¶
	-d comerr-library-output-folder="{comerr-library-output-folder}" ¶
	-d comerr-library-name="{comerr-library-name}" ¶
	-d comerr-library-export="{comerr-library-export}" ¶
	-d comerr-library-fragment-name={comerr-library-fragment-name} ¶
	-d comerr-library-main="{comerr-library-main}" ¶
	-d comerr-library-init="{comerr-library-init}" ¶
	-d comerr-library-term="{comerr-library-term}"

make-options-ppc-debug = ¶
	-d library-linker="{library-linker-ppc}" ¶
	-d library-platform="{library-platform-ppc}" ¶
	-d library-kind="{library-kind-debug}" ¶
	-d gss-library-libraries="{gss-library-libraries-ppc-debug}" ¶
	-d gss-library-objects="{gss-library-objects-ppc-debug}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-ppc-debug}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-ppc-debug}" ¶
	-d krb5-library-objects="{krb5-library-objects-ppc-debug}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-ppc-debug}" ¶
	-d profile-library-libraries="{profile-library-libraries-ppc-debug}" ¶
	-d profile-library-objects="{profile-library-objects-ppc-debug}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-ppc-debug}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-ppc-debug}" ¶
	-d comerr-library-objects="{comerr-library-objects-ppc-debug}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-ppc-debug}" ¶
	-d object-suffix="{object-suffix-ppc-debug}" ¶
	-d object-suffix-data="{object-suffix-ppc-data}" ¶
	-d compiler-options="{compiler-options-ppc-debug}" ¶
	-d compiler="{compiler-ppc}" ¶
	-d precompiled-headers="{precompiled-headers-ppc}"
	
make-options-ppc-final = ¶
	-d library-linker="{library-linker-ppc}" ¶
	-d library-platform="{library-platform-ppc}" ¶
	-d library-kind="{library-kind-final}" ¶
	-d gss-library-libraries="{gss-library-libraries-ppc-final}" ¶
	-d gss-library-objects="{gss-library-objects-ppc-final}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-ppc-final}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-ppc-final}" ¶
	-d krb5-library-objects="{krb5-library-objects-ppc-final}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-ppc-final}" ¶
	-d profile-library-libraries="{profile-library-libraries-ppc-final}" ¶
	-d profile-library-objects="{profile-library-objects-ppc-final}" ¶
	-d profile-library-linker-options="{profile-library-linker-options-ppc-final}" ¶
	-d comerr-library-libraries="{comerr-library-libraries-ppc-final}" ¶
	-d comerr-library-objects="{comerr-library-objects-ppc-final}" ¶
	-d comerr-library-linker-options="{comerr-library-linker-options-ppc-final}" ¶
	-d object-suffix="{object-suffix-ppc-final}" ¶
	-d object-suffix-data="{object-suffix-ppc-data}" ¶
	-d compiler-options="{compiler-options-ppc-final}" ¶
	-d compiler="{compiler-ppc}" ¶
	-d precompiled-headers="{precompiled-headers-ppc}"
	
make-output = "{TempFolder}GSS/Kerberos Makefile script"
submakefile-target = gss-library

ppc-debug Ä glue headers documentation {makefile-name} {gss-objects-ppc-debug-list} {krb5-objects-ppc-debug-list} ¶
	{profile-objects-ppc-debug-list} {comerr-objects-ppc-debug-list} {include-folders-list}
	Make {make-options-common} {make-options-ppc-debug} {submakefile-target} > {make-output}
	{make-output}
	
ppc-final Ä glue headers documentation  {makefile-name} {gss-objects-ppc-final-list} {krb5-objects-ppc-final-list} ¶
	{profile-objects-ppc-final-list} {comerr-objects-ppc-final-list} {include-folders-list}
	Make {make-options-common} {make-options-ppc-final} {submakefile-target} > {make-output}
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
###			library-platform								-- platform name (68K or PPC)
###			library-kind									-- library kind (".debug" or "")


### script to create a folder if it does not exist
create-folder = {root-folder}mac:create-folder.mpw


### defaults, will be set to something better by the make commands above
library-linker =
library-platform =
library-kind =
gss-library-libraries =
gss-library-objects =
gss-library-linker-options =
krb5-library-libraries =
krb5-library-objects =
krb5-library-linker-options =
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
	{autogenerated-files} {gss-library-export} {gss-library-libraries} {gss-library-objects}
gss-library-build-command = ¶
	{library-linker} ¶
	-name "{gss-library-fragment-name}{library-kind}" ¶
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
	{autogenerated-files} {krb5-library-export} {krb5-library-libraries} {krb5-library-objects}
krb5-library-build-command = ¶
	{library-linker} ¶
	-name "{krb5-library-fragment-name}{library-kind}" ¶
	-main {krb5-library-main} ¶
	-init {krb5-library-init} ¶
	-term {krb5-library-term} ¶
	-@export {krb5-library-export} ¶
	-map {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind}.MAP ¶
	-o {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind} ¶
	{krb5-library-linker-options} ¶
	{krb5-library-objects} {krb5-library-libraries}

profile-library-output-files = ¶
	{profile-library-output-folder}{profile-library-name}{library-platform}{library-kind}
profile-library-dependencies = ¶
	{autogenerated-files} {profile-library-export} {profile-library-libraries} {profile-library-objects}
profile-library-build-command = ¶
	{library-linker} ¶
	-name "{profile-library-fragment-name}{library-kind}" ¶
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
	{autogenerated-files} {comerr-library-export} {comerr-library-libraries} {comerr-library-objects}
comerr-library-build-command = ¶
	{library-linker} ¶
	-name "{comerr-library-fragment-name}{library-kind}" ¶
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
profile-library Ä {profile-library-output-files}
comerr-library Ä {comerr-library-output-files}

{gss-library-output-files} ÄÄ {gss-library-dependencies} {makefile-name}
	{create-folder} {gss-library-output-folder}
	{gss-library-build-command}
	
{krb5-library-output-files} ÄÄ {krb5-library-dependencies} {makefile-name}
	{create-folder} {krb5-library-output-folder}
	{krb5-library-build-command}

{profile-library-output-files} ÄÄ {profile-library-dependencies} {makefile-name}
	{create-folder} {profile-library-output-folder}
	{profile-library-build-command}

{comerr-library-output-files} ÄÄ {comerr-library-dependencies} {makefile-name}
	{create-folder} {comerr-library-output-folder}
	{comerr-library-build-command}

##############################################################################################################
###			Default compilation rules
##############################################################################################################

{object-suffix} Ä .c {autogenerated-files} {makefile-name} {precompiled-headers}
	echo {DepDir}{Default}{object-suffix}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix} {compiler-options}

{object-suffix-data} Ä .c {autogenerated-files} {makefile-name} {precompiled-headers}
	echo {DepDir}{Default}{object-suffix-data}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix-data} {compiler-options}

##############################################################################################################
###			Autogenerating classic 68K glue files
##############################################################################################################

classic-glue-generation-script 						= {root-folder}mac:CFMGlue.pl
gss-library-glue-output-folder						= {root-folder}:GSSLib:ClassicGlue:
krb5-library-glue-output-folder						= {root-folder}:Kerberos5Lib:ClassicGlue:
profile-library-glue-output-folder					= {root-folder}:KerberosProfileLib:ClassicGlue:
comerr-library-glue-output-folder					= {root-folder}:ComErrLib:ClassicGlue:

gss-library-glue-output								= {gss-library-glue-output-folder}GSSLib.glue.c
krb5-library-glue-output							= {krb5-library-glue-output-folder}Kerberos5Lib.glue.c
profile-library-glue-output							= {profile-library-glue-output-folder}KrbProfileLib.glue.c
comerr-library-glue-output							= {comerr-library-glue-output-folder}ComErrLib.glue.c

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
	{root-folder}mac:CFMglue.c {root-folder}mac:K5.moreCFMglue.cin {classic-glue-generation-script}
	{create-folder} {krb5-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:K5.CFMglue.proto.h > {root-folder}mac:K5.CFMglue.c
	Catenate {root-folder}mac:K5.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:K5.CFMglue.c ¶
	{root-folder}mac:K5.moreCFMglue.cin | Catenate > {krb5-library-glue-output}

{gss-library-glue-output} Ä {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:GSS.CFMglue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:GSS.moreCFMglue.cin {classic-glue-generation-script}
	{create-folder} {gss-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:GSS.CFMglue.proto.h > {root-folder}mac:GSS.CFMglue.c
	Catenate {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:GSS.CFMglue.c ¶
	{root-folder}mac:GSS.moreCFMglue.cin | Catenate > {gss-library-glue-output}

{profile-library-glue-output} Ä {root-folder}mac:KrbProfileLib.glue.pre.cin {root-folder}mac:KrbProfileLib.glue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:KrbProfileLib.glue.post.cin {classic-glue-generation-script}
	{create-folder} {profile-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:KrbProfileLib.glue.proto.h > {root-folder}mac:KrbProfileLib.CFMglue.c
	Catenate {root-folder}mac:KrbProfileLib.glue.pre.cin {root-folder}mac:CFMglue.c {root-folder}mac:KrbProfileLib.CFMglue.c ¶
	{root-folder}mac:KrbProfileLib.glue.post.cin | Catenate > {profile-library-glue-output}

{comerr-library-glue-output} Ä {root-folder}mac:ComErrLib.glue.pre.cin {root-folder}mac:ComErrLib.glue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:ComErrLib.glue.post.cin {classic-glue-generation-script}
	{create-folder} {comerr-library-glue-output-folder}
	perl {classic-glue-generation-script} < {root-folder}mac:ComErrLib.glue.proto.h > {root-folder}mac:ComErrLib.CFMglue.c
	Catenate {root-folder}mac:ComErrLib.glue.pre.cin {root-folder}mac:CFMglue.c {root-folder}mac:ComErrLib.CFMglue.c ¶
	{root-folder}mac:ComErrLib.glue.post.cin | Catenate > {comerr-library-glue-output}

##############################################################################################################
###			Clean target deletes all generated files
##############################################################################################################

clean Ä
	# Need a dummy invalid name at the end to cover the case when nothing is found
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-debug}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-final}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-data}/ Print"` supercalifragilisticexpialidoucious
	Delete -i {all-lists}
	
##############################################################################################################
###			Copying headers around
##############################################################################################################

gss-headers-output-folder							= {root-folder}:GSSLib:Headers:
krb5-headers-output-folder							= {root-folder}:Kerberos5Lib:Headers:
comerr-headers-output-folder						= {root-folder}:ComErrLib:Headers:
profile-headers-output-folder						= {root-folder}:KerberosProfileLib:Headers:

gss-headers-output = ¶
	"{gss-headers-output-folder}gssapi.h" ¶
	"{gss-headers-output-folder}gssapi_krb5.h"

krb5-headers-output = ¶
	"{krb5-headers-output-folder}krb5.h" ¶
	"{krb5-headers-output-folder}win-mac.h"

comerr-headers-output = ¶
	"{comerr-headers-output-folder}com_err.h"
	
profile-headers-output = ¶
	"{profile-headers-output-folder}profile.h"
	
headers-output = {gss-headers-output} {krb5-headers-output} ¶
	{comerr-headers-output} {profile-headers-output} 

headers Ä unset-echo {headers-output}

"{gss-headers-output-folder}gssapi.h" Ä "{root-folder}lib:gssapi:generic:gssapi.h" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}lib:gssapi:generic:gssapi.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{gss-headers-output-folder}gssapi_krb5.h" Ä "{root-folder}lib:gssapi:krb5:gssapi_krb5.h" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}lib:gssapi:krb5:gssapi_krb5.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{krb5-headers-output-folder}krb5.h" Ä "{root-folder}include:krb5.h" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}include:krb5.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{krb5-headers-output-folder}win-mac.h" Ä "{root-folder}include:win-mac.h" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}include:win-mac.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{comerr-headers-output-folder}com_err.h" Ä "{root-folder}util:et:com_err.h" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l "{Targ}"
	End
	Catenate "{root-folder}util:et:com_err.h" > "{Targ}"
	SetFile -a l "{Targ}"

"{profile-headers-output-folder}profile.h" Ä "{root-folder}util:profile:profile.h" {makefile-name}
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

{gss-documentation-output-folder}"GSSLib ReadMe" Ä {root-folder}"mac:GSSLib ReadMe" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:GSSLib ReadMe" > {Targ}
	SetFile -a l {Targ}

{krb5-documentation-output-folder}"krb5api.pdf" Ä {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	If (`Exists {root-folder}":::Documentation:pdf:krb5api.pdf"`)
		Catenate {root-folder}":::Documentation:pdf:krb5api.pdf" > {Targ}
		SetFile -a l -t 'PDF ' -c 'CARO' {Targ}
	End

{comerr-documentation-output-folder}"ComErrLib ReadMe" Ä {root-folder}"mac:ComErrLib ReadMe" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:ComErrLib ReadMe" > {Targ}
	SetFile -a l {Targ}

{profile-documentation-output-folder}"KerberosProfileLib ReadMe" Ä {root-folder}"mac:KerberosProfileLib ReadMe" {makefile-name}
	"{create-folder}" "{TargDir}"
	If (`Exists "{Targ}" | Count -l`)
		SetFile -a l {Targ}
	End
	Catenate {root-folder}"mac:KerberosProfileLib ReadMe" > {Targ}
	SetFile -a l {Targ}

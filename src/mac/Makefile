##############################################################################################################
###			Important global constants
##############################################################################################################

root-folder											= ::
makefile-name										= {root-folder}mac:Makefile

library-output-folder								= {root-folder}bin:

gss-krb5-library-name								= ¶"MIT GSS/Kerberos library¶"
gss-krb5-library-output-folder						= {library-output-folder}
gss-krb5-library-debug								= {gss-krb5-library-output-folder}{gss-krb5-library-name}{library-kind-debug}
gss-krb5-library-final								= {gss-krb5-library-output-folder}{gss-krb5-library-name}{library-kind-final}

library-platform-68K					= .68K
library-platform-PPC					= .PPC

library-kind-debug						= .debug
library-kind-final						=

##############################################################################################################
###			Top-level targets -- abstract targets for convinient grouping
##############################################################################################################

#	Everything
all Ä glue gss-krb5-library-debug gss-krb5-library-final

#	Debugging versions
all-debug Ä ppc-debug 68k-debug

#	Final versions
all-final Ä ppc-final 68k-final

#	Clasic 68K glue
glue Ä glue-gss glue-krb5

##############################################################################################################
###			More global constants
##############################################################################################################

krb5-globals-root-folder							= {root-folder}¶"mac:libraries:Kerberos v5 Globals:¶"

gss-library-output-folder							= {root-folder}:GSSLib:Binaries:
krb5-library-output-folder							= {root-folder}:Kerberos5Lib:Binaries:
krb5-globals-library-output-folder					= {root-folder}:Kerberos5GlobalsLib:Binaries:
krb5-globals-data-library-output-folder				= {krb5-globals-library-output-folder}

gss-library-name									= GSSLib
krb5-library-name									= Kerberos5Lib
krb5-globals-library-name							= Krb5GlobalsLib
krb5-globals-data-library-name						= Krb5GlobalsDataLib

gss-library-export									= {root-folder}mac:GSSLibrary.exp
krb5-library-export									= {root-folder}mac:K5Library.exp
krb5-globals-library-export							= {krb5-globals-root-folder}Krb5Globals.exp
krb5-globals-data-library-export					= {krb5-globals-root-folder}Krb5GlobalsData.exp

gss-library-fragment-name							= MIT_¥GSSLib
krb5-library-fragment-name							= MIT_¥Kerberos5Lib
krb5-globals-library-fragment-name					= MIT_¥Kerberos5GlobalsLib
krb5-globals-data-library-fragment-name				= MIT_¥Kerberos5GlobalsDataLib

gss-library-main									= ¶"¶"
krb5-library-main									= ¶"¶"
krb5-globals-library-main							= ¶"¶"
krb5-globals-data-library-main						= ¶"¶"

gss-library-init									= __initializeGSS
krb5-library-init									= __initializeK5
krb5-globals-library-init							= __initialize_Kerberos5GlobalsLib
krb5-globals-data-library-init						= __initialize
	
gss-library-term 									= __terminateGSS
krb5-library-term									= __terminateK5
krb5-globals-library-term							= __terminate_Kerberos5GlobalsLib
krb5-globals-data-library-term						= __terminate

gss-library-current-version							= 1
gss-library-definition-version						= 1
gss-library-implementation-version					= 0

krb5-library-current-version						= 1
krb5-library-definition-version						= 1
krb5-library-implementation-version					= 0

krb5-globals-library-current-version				= 0
krb5-globals-library-definition-version				= 0
krb5-globals-library-implementation-version			= 0

krb5-globals-data-library-current-version			= 0
krb5-globals-data-library-definition-version		= 0
krb5-globals-data-library-implementation-version	= 0

##############################################################################################################
###			Generation of file lists
##############################################################################################################

list-generation-script = ":macfile_gen.pl"
list-generation-script-root = ".."
list-generation-script-prefix = ":"

all-files-list									= {root-folder}"All files.list"
all-sources-list								= {root-folder}"All sources.list"
all-folders-list								= {root-folder}"All folders.list"
include-folders-list							= {root-folder}"Include folders.list"

gss-sources-list								= {root-folder}"GSS sources.list"
krb5-sources-list								= {root-folder}"Krb5 sources.list"

gss-objects-ppc-debug-list						= {root-folder}"GSS objects PPC debug.list"
gss-objects-68k-debug-list						= {root-folder}"GSS objects 68K debug.list"
gss-objects-ppc-final-list						= {root-folder}"GSS objects PPC final.list"
gss-objects-68k-final-list						= {root-folder}"GSS objects 68K final.list"

krb5-objects-ppc-debug-list						= {root-folder}"Krb5 objects PPC debug.list"
krb5-objects-68k-debug-list						= {root-folder}"Krb5 objects 68K debug.list"
krb5-objects-ppc-final-list						= {root-folder}"Krb5 objects PPC final.list"
krb5-objects-68k-final-list						= {root-folder}"Krb5 objects 68K final.list"

all-lists = ¶
	{all-files-list} ¶
	{all-sources-list} ¶
	{all-folders-list} ¶
	{include-folders-list} ¶
	{gss-sources-list} ¶
	{krb5-sources-list} ¶
	{gss-objects-ppc-debug-list} ¶
	{gss-objects-68k-debug-list} ¶
	{gss-objects-ppc-final-list} ¶
	{gss-objects-68k-final-list} ¶
	{krb5-objects-ppc-debug-list} ¶
	{krb5-objects-68k-debug-list} ¶
	{krb5-objects-ppc-final-list} ¶
	{krb5-objects-68k-final-list}

file-lists Ä {all-lists}

{all-files-list} Ä {list-generation-script} {makefile-name}
	perl {list-generation-script} all-files {list-generation-script-root} {list-generation-script-prefix} ¶
 > {Targ}

{all-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} all-sources {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{all-folders-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} all-folders {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{include-folders-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} include-folders {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{gss-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} gss-sources {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{krb5-sources-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} krb5-sources {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{gss-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} gss-objects-ppc-debug {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{gss-objects-68k-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} gss-objects-68k-debug {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{gss-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} gss-objects-ppc-final {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{gss-objects-68k-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} gss-objects-68k-final {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{krb5-objects-ppc-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} krb5-objects-ppc-debug {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{krb5-objects-68k-debug-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} krb5-objects-68k-debug {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{krb5-objects-ppc-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} krb5-objects-ppc-final {list-generation-script-root} {list-generation-script-prefix} ¶
 < {all-files-list} > {Targ}

{krb5-objects-68k-final-list} Ä {all-files-list} {list-generation-script} {makefile-name}
	perl {list-generation-script} krb5-objects-68k-final {list-generation-script-root} {list-generation-script-prefix} ¶
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
	Duplicate -y {root-folder}util:profile:profile.h {root-folder}include:profile.h

{root-folder}include:krb5:osconf.h Ä {root-folder}include:krb5:stock:osconf.h
	Duplicate -y {root-folder}include:krb5:stock:osconf.h {root-folder}include:krb5:osconf.h

{root-folder}lib:gssapi:generic:gssapi.h Ä {root-folder}lib:gssapi:generic:gssapi.hin
	Duplicate -y {root-folder}lib:gssapi:generic:gssapi.hin {root-folder}lib:gssapi:generic:gssapi.h
	
{root-folder}include:autoconf.h Ä {root-folder}mac:libraries:autoconf.h
	Duplicate -y {root-folder}libraries:autoconf.h {root-folder}include:autoconf.h

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
###		For Krb5 globals library
###			krb5-globals-library-output-folder				-- destination of Krb5 globals library output
###			krb5-globals-library-name						-- name of the Krb5 globals library
###			krb5-globals-library-export						-- name of gss Krb5 globals library export file
###			krb5-globals-library-libraries					-- list of libraries Krb5 globals library links against
###			krb5-globals-library-objects					-- list of object files Krb5 globals library links
###			krb5-globals-library-fragment-name				-- name of Krb5 globals library fragment
###			krb5-globals-library-main						-- name of Krb5 globals library main entry point
###			krb5-globals-library-init						-- name of Krb5 globals library initialization routine
###			krb5-globals-library-term						-- name of Krb5 globals library termination routine
###			krb5-globals-library-linker-options				-- all other Krb5 globals library linker options
###		General
###			library-linker									-- linker to use
###			autogenerated-files								-- list of autogenerated files
###			library-platform								-- platform name (68K or PPC)
###			library-kind									-- library kind (".debug" or "")
###			object-suffix									-- object file suffix (.ppcf.o, .ppcd.o, .68kf.o, .68kd.o)
###			object-suffix-data								-- object file suffix fdor data libraries (.ppc.o, .68k.o)


### The following variables are platform- or kind-specific, but constant

standard-libraries-ppc-debug			= ¶
	¶"{root-folder}bin:MIT CLib.PPC.debug¶" ¶
	¶"{root-folder}bin:MIT RuntimeLib.PPC.debug¶" ¶
	¶"{MWPPCLibraries}MSL ShLibRuntime.Lib¶" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}MathLib¶"
standard-libraries-68k-debug			= ¶
	¶"{root-folder}bin:MIT CLib.68K.debug¶" ¶
	¶"{root-folder}bin:MIT RuntimeLib.68K.debug¶" ¶
	¶"{MW68KLibraries}MSL ShLibRuntimeCFM68K.Lib¶" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{MW68KLibraries}MathLibCFM68K (4i_8d).Lib¶"
standard-libraries-ppc-final			= ¶
	¶"{root-folder}bin:MIT CLib.PPC¶" ¶
	¶"{root-folder}bin:MIT RuntimeLib.PPC¶" ¶
	¶"{MWPPCLibraries}MSL ShLibRuntime.Lib¶" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{SharedLibraries}MathLib¶"
standard-libraries-68k-final			= ¶
	¶"{root-folder}bin:MIT CLib.68K¶" ¶
	¶"{root-folder}bin:MIT RuntimeLib.68K¶" ¶
	¶"{MW68KLibraries}MSL ShLibRuntimeCFM68K.Lib¶" ¶
	¶"{SharedLibraries}InterfaceLib¶" ¶
	¶"{MW68KLibraries}MathLibCFM68K (4i_8d).Lib¶"

ccache-ppc-debug						= {root-folder}¶"mac:libraries:CCache API:bin:CCacheLib.PPC.debug¶"
ccache-68k-debug						= {root-folder}¶"mac:libraries:CCache API:bin:CCacheLib.68K.debug¶"
ccache-ppc-final						= {root-folder}¶"mac:libraries:CCache API:bin:CCacheLib.PPC¶"
ccache-68k-final						= {root-folder}¶"mac:libraries:CCache API:bin:CCacheLib.68K¶"

object-suffix-ppc-debug					= .ppcd.o
object-suffix-68k-debug					= .68kd.o
object-suffix-ppc-final					= .ppcf.o
object-suffix-68k-final					= .68kf.o
object-suffix-ppc-data					= .ppc.o
object-suffix-68k-data					= .68k.o

gss-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-debug}
gss-library-libraries-68k-debug = ¶
	{standard-libraries-68k-debug} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-68k}{library-kind-debug}
gss-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-final}
gss-library-libraries-68k-final = ¶
	{standard-libraries-68k-final} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-68k}{library-kind-final}

krb5-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{ccache-ppc-debug} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-ppc}{library-kind-debug}
krb5-library-libraries-68k-debug = ¶
	{standard-libraries-68k-debug} ¶
	{ccache-68k-debug} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-68k}{library-kind-debug}
krb5-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{ccache-ppc-final} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-ppc}{library-kind-final}
krb5-library-libraries-68k-final = ¶
	{standard-libraries-68k-final} ¶
	{ccache-68k-final} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-68k}{library-kind-final}

krb5-globals-library-libraries-ppc-debug = ¶
	{standard-libraries-ppc-debug} ¶
	{ccache-ppc-debug} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-ppc}
krb5-globals-library-libraries-68k-debug = ¶
	{standard-libraries-68k-debug} ¶
	{ccache-68k-debug} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-68k}
krb5-globals-library-libraries-ppc-final = ¶
	{standard-libraries-ppc-final} ¶
	{ccache-ppc-final} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-ppc}
krb5-globals-library-libraries-68k-final = ¶
	{standard-libraries-68k-final} ¶
	{ccache-68k-final} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-68k}
	
krb5-globals-data-library-libraries-ppc = ¶"{MWPPCLibraries}MSL RuntimePPC.Lib¶"
krb5-globals-data-library-libraries-68k = ¶"{MW68KLibraries}MSL MWCFM68KRuntime.Lib¶"

### Construct linker options. 

common-linker-options = -sharedlibrary
common-linker-options-debug = {common-linker-options} -sym on
common-linker-options-final = {common-linker-options} -sym off

gss-library-common-linker-options = ¶
	-cv {gss-library-current-version} ¶
	-dv {gss-library-definition-version} ¶
	-uv {gss-library-implementation-version}

gss-library-linker-options-ppc-debug = {common-linker-options-debug} {gss-library-common-linker-options}
gss-library-linker-options-68k-debug = {common-linker-options-debug} {gss-library-common-linker-options}
gss-library-linker-options-ppc-final = {common-linker-options-final} {gss-library-common-linker-options}
gss-library-linker-options-68k-final = {common-linker-options-final} {gss-library-common-linker-options}

krb5-library-common-linker-options = ¶
	-cv {krb5-library-current-version} ¶
	-dv {krb5-library-definition-version} ¶
	-uv {krb5-library-implementation-version}

krb5-library-linker-options-ppc-debug = {common-linker-options-debug} {krb5-library-common-linker-options}
krb5-library-linker-options-68k-debug = {common-linker-options-debug} {krb5-library-common-linker-options}
krb5-library-linker-options-ppc-final = {common-linker-options-final} {krb5-library-common-linker-options}
krb5-library-linker-options-68k-final = {common-linker-options-final} {krb5-library-common-linker-options}

krb5-globals-library-common-linker-options = ¶
	-cv {krb5-globals-library-current-version} ¶
	-dv {krb5-globals-library-definition-version} ¶
	-uv {krb5-globals-library-implementation-version}

krb5-globals-library-linker-options-ppc-debug = {common-linker-options-debug} {krb5-globals-library-common-linker-options}
krb5-globals-library-linker-options-68k-debug = {common-linker-options-debug} {krb5-globals-library-common-linker-options}
krb5-globals-library-linker-options-ppc-final = {common-linker-options-final} {krb5-globals-library-common-linker-options}
krb5-globals-library-linker-options-68k-final = {common-linker-options-final} {krb5-globals-library-common-linker-options}

krb5-globals-data-library-common-linker-options = ¶
	-cv {krb5-globals-data-library-current-version} ¶
	-dv {krb5-globals-data-library-definition-version} ¶
	-uv {krb5-globals-data-library-implementation-version} ¶
	-sharedata

krb5-globals-data-library-linker-options-ppc = {common-linker-options-debug} {krb5-globals-data-library-common-linker-options}
krb5-globals-data-library-linker-options-68k = {common-linker-options-debug} {krb5-globals-data-library-common-linker-options}

gss-library-objects-ppc-debug = `catenate {gss-objects-ppc-debug-list}` {root-folder}mac:GSS.CFM{object-suffix-ppc-debug}
gss-library-objects-68k-debug = `catenate {gss-objects-68k-debug-list}` {root-folder}mac:GSS.CFM{object-suffix-68k-debug}
gss-library-objects-ppc-final = `catenate {gss-objects-ppc-final-list}` {root-folder}mac:GSS.CFM{object-suffix-ppc-final}
gss-library-objects-68k-final = `catenate {gss-objects-68k-final-list}` {root-folder}mac:GSS.CFM{object-suffix-68k-final}

krb5-library-objects-ppc-debug = `catenate {krb5-objects-ppc-debug-list}` {root-folder}mac:K5.CFM{object-suffix-ppc-debug}
krb5-library-objects-68k-debug = `catenate {krb5-objects-68k-debug-list}` {root-folder}mac:K5.CFM{object-suffix-68k-debug}
krb5-library-objects-ppc-final = `catenate {krb5-objects-ppc-final-list}` {root-folder}mac:K5.CFM{object-suffix-ppc-final}
krb5-library-objects-68k-final = `catenate {krb5-objects-68k-final-list}` {root-folder}mac:K5.CFM{object-suffix-68k-debug}

krb5-globals-library-objects-ppc-debug = ¶
	{krb5-globals-root-folder}Krb5Globals{object-suffix-ppc-debug} ¶
	{krb5-globals-root-folder}Krb5Globals.CFM{object-suffix-ppc-debug}
krb5-globals-library-objects-68k-debug = ¶
	{krb5-globals-root-folder}Krb5Globals{object-suffix-68k-debug} ¶
	{krb5-globals-root-folder}Krb5Globals.CFM{object-suffix-68k-debug}
krb5-globals-library-objects-ppc-final = ¶
	{krb5-globals-root-folder}Krb5Globals{object-suffix-ppc-final} ¶
	{krb5-globals-root-folder}Krb5Globals.CFM{object-suffix-ppc-final}
krb5-globals-library-objects-68k-final = ¶
	{krb5-globals-root-folder}Krb5Globals{object-suffix-68k-debug} ¶
	{krb5-globals-root-folder}Krb5Globals.CFM{object-suffix-68k-debug}

krb5-globals-data-library-objects-ppc = {krb5-globals-root-folder}Krb5GlobalsData{object-suffix-ppc-data}
krb5-globals-data-library-objects-68k = {krb5-globals-root-folder}Krb5GlobalsData{object-suffix-68k-data}

library-linker-ppc						= MWLinkPPC
library-linker-68K						= MWLink68K

### Construct compiler options.

common-compiler-options = ¶
		-enum int -opt all -strings pool -mapcr ¶
        -mpw_pointers -warnings off -fatext -nosyspath -maxerrors 1000 ¶
        -align mac68k -opt off -toc_data on -fp_contract on ¶
		-model farData

# Don't put the prefix file in these options because they are used to precompile the prefix file
ppc-compiler-options = 
68k-compiler-options = -model cfmflat 
debug-compiler-options = -sym on
final-compiler-options = -sym off

include-paths = `catenate {include-folders-list}` ¶
	-i {root-folder}mac:libraries:¶"CCache API¶":include ¶
	-i {krb5-globals-root-folder}
		
compiler-options-ppc-debug = {include-paths} {common-compiler-options} {ppc-compiler-options} ¶
	{debug-compiler-options} -prefix {precompiled-headers-ppc}
compiler-options-68k-debug = {include-paths} {common-compiler-options} {68k-compiler-options} ¶
	{debug-compiler-options} -prefix {precompiled-headers-68k}
compiler-options-ppc-final = {include-paths} {common-compiler-options} {ppc-compiler-options} ¶
	{final-compiler-options} -prefix {precompiled-headers-ppc}
compiler-options-68k-final = {include-paths} {common-compiler-options} {68k-compiler-options} ¶
	{final-compiler-options} -prefix {precompiled-headers-68k}

compiler-ppc							= MWCPPC
compiler-68k							= MWC68K

### Precompiled headers

precompiled-headers-folder = {root-folder}mac:libraries:

precompiled-headers-ppc = {precompiled-headers-folder}KerberosHeaders.PPC
precompiled-headers-68k = {precompiled-headers-folder}KerberosHeaders.68K

precompiled-headers-source = {precompiled-headers-folder}mac:KerberosHeaders.pch

{precompiled-headers-ppc} Ä {precompiled-headers-source} {precompiled-headers-folder}KerberosHeaders.h
	{compiler-ppc} {precompiled-headers-source} {common-compiler-options} {ppc-compiler-options} ¶
		-precompile {Targ} -i {precompiled-headers-folder}

{precompiled-headers-68k} Ä {precompiled-headers-source} {precompiled-headers-folder}KerberosHeaders.h
	{compiler-68k} {precompiled-headers-source} {common-compiler-options} {68k-compiler-options} ¶
		-precompile {Targ} -i {precompiled-headers-folder}

make-options-common = ¶
	-f {makefile-name} ¶
	-d autogenerated-files="{autogenerated-files}" ¶
	-d gss-library-output-folder="{gss-library-output-folder}" ¶
	-d gss-library-name="{gss-library-name}" ¶
	-d gss-library-export="{gss-library-export}" ¶
	-d gss-library-fragment-name="{gss-library-fragment-name}" ¶
	-d gss-library-main="{gss-library-main}" ¶
	-d gss-library-init="{gss-library-init}" ¶
	-d gss-library-term="{gss-library-term}" ¶
	-d krb5-library-output-folder="{krb5-library-output-folder}" ¶
	-d krb5-library-name="{krb5-library-name}" ¶
	-d krb5-library-export="{krb5-library-export}" ¶
	-d krb5-library-fragment-name="{krb5-library-fragment-name}" ¶
	-d krb5-library-main="{krb5-library-main}" ¶
	-d krb5-library-init="{krb5-library-init}" ¶
	-d krb5-library-term="{krb5-library-term}" ¶
	-d krb5-globals-library-output-folder="{krb5-globals-library-output-folder}" ¶
	-d krb5-globals-library-name="{krb5-globals-library-name}" ¶
	-d krb5-globals-library-export="{krb5-globals-library-export}" ¶
	-d krb5-globals-library-fragment-name="{krb5-globals-library-fragment-name}" ¶
	-d krb5-globals-library-main="{krb5-globals-library-main}" ¶
	-d krb5-globals-library-init="{krb5-globals-library-init}" ¶
	-d krb5-globals-data-library-term="{krb5-globals-data-library-term}" ¶
	-d krb5-globals-data-library-output-folder="{krb5-globals-data-library-output-folder}" ¶
	-d krb5-globals-data-library-name="{krb5-globals-data-library-name}" ¶
	-d krb5-globals-data-library-export="{krb5-globals-data-library-export}" ¶
	-d krb5-globals-data-library-fragment-name="{krb5-globals-data-library-fragment-name}" ¶
	-d krb5-globals-data-library-main="{krb5-globals-data-library-main}" ¶
	-d krb5-globals-data-library-init="{krb5-globals-data-library-init}" ¶
	-d krb5-globals-data-library-term="{krb5-globals-data-library-term}"

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
	-d krb5-globals-library-libraries="{krb5-globals-library-libraries-ppc-debug}" ¶
	-d krb5-globals-library-objects="{krb5-globals-library-objects-ppc-debug}" ¶
	-d krb5-globals-library-linker-options="{krb5-globals-library-linker-options-ppc-debug}" ¶
	-d krb5-globals-data-library-libraries="{krb5-globals-data-library-libraries-ppc}" ¶
	-d krb5-globals-data-library-objects="{krb5-globals-data-library-objects-ppc}" ¶
	-d krb5-globals-data-library-linker-options="{krb5-globals-data-library-linker-options-ppc}" ¶
	-d object-suffix="{object-suffix-ppc-debug}" ¶
	-d object-suffix-data="{object-suffix-ppc-data}" ¶
	-d compiler-options="{compiler-options-ppc-debug}" ¶
	-d compiler="{compiler-ppc}" ¶
	-d precompiled-headers="{precompiled-headers-ppc}"
	
make-options-68k-debug = ¶
	-d library-linker="{library-linker-68k}" ¶
	-d library-platform="{library-platform-68k}" ¶
	-d library-kind="{library-kind-debug}" ¶
	-d gss-library-libraries="{gss-library-libraries-68k-debug}" ¶
	-d gss-library-objects="{gss-library-objects-68k-debug}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-68k-debug}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-68k-debug}" ¶
	-d krb5-library-objects="{krb5-library-objects-68k-debug}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-68k-debug}" ¶
	-d krb5-globals-library-libraries="{krb5-globals-library-libraries-68k-debug}" ¶
	-d krb5-globals-library-objects="{krb5-globals-library-objects-68k-debug}" ¶
	-d krb5-globals-library-linker-options="{krb5-globals-library-linker-options-68k-debug}" ¶
	-d krb5-globals-data-library-libraries="{krb5-globals-data-library-libraries-68k}" ¶
	-d krb5-globals-data-library-objects="{krb5-globals-data-library-objects-68k}" ¶
	-d krb5-globals-data-library-linker-options="{krb5-globals-data-library-linker-options-68k}" ¶
	-d object-suffix="{object-suffix-68k-debug}" ¶
	-d object-suffix-data="{object-suffix-68k-data}" ¶
	-d compiler-options="{compiler-options-68k-debug}" ¶
	-d compiler="{compiler-68k}" ¶
	-d precompiled-headers="{precompiled-headers-68k}"

	
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
	-d krb5-globals-library-libraries="{krb5-globals-library-libraries-ppc-final}" ¶
	-d krb5-globals-library-objects="{krb5-globals-library-objects-ppc-final}" ¶
	-d krb5-globals-library-linker-options="{krb5-globals-library-linker-options-ppc-final}" ¶
	-d krb5-globals-data-library-libraries="{krb5-globals-data-library-libraries-ppc}" ¶
	-d krb5-globals-data-library-objects="{krb5-globals-data-library-objects-ppc}" ¶
	-d krb5-globals-data-library-linker-options="{krb5-globals-data-library-linker-options-ppc}" ¶
	-d object-suffix="{object-suffix-ppc-final}" ¶
	-d object-suffix-data="{object-suffix-ppc-data}" ¶
	-d compiler-options="{compiler-options-ppc-final}" ¶
	-d compiler="{compiler-ppc}" ¶
	-d precompiled-headers="{precompiled-headers-ppc}"
	
make-options-68k-final = ¶
	-d library-linker="{library-linker-68k}" ¶
	-d library-platform="{library-platform-68k}" ¶
	-d library-kind="{library-kind-final}" ¶
	-d gss-library-libraries="{gss-library-libraries-68k-final}" ¶
	-d gss-library-objects="{gss-library-objects-68k-final}" ¶
	-d gss-library-linker-options="{gss-library-linker-options-68k-final}" ¶
	-d krb5-library-libraries="{krb5-library-libraries-68k-final}" ¶
	-d krb5-library-objects="{krb5-library-objects-68k-final}" ¶
	-d krb5-library-linker-options="{krb5-library-linker-options-68k-final}" ¶
	-d krb5-globals-library-libraries="{krb5-globals-library-libraries-68k-final}" ¶
	-d krb5-globals-library-objects="{krb5-globals-library-objects-68k-final}" ¶
	-d krb5-globals-library-linker-options="{krb5-globals-library-linker-options-68k-final}" ¶
	-d krb5-globals-data-library-libraries="{krb5-globals-data-library-libraries-68k}" ¶
	-d krb5-globals-data-library-objects="{krb5-globals-data-library-objects-68k}" ¶
	-d krb5-globals-data-library-linker-options="{krb5-globals-data-library-linker-options-68k}" ¶
	-d object-suffix="{object-suffix-68k-final}" ¶
	-d object-suffix-data="{object-suffix-68k-data}" ¶
	-d compiler-options="{compiler-options-68k-final}" ¶
	-d compiler="{compiler-68k}" ¶
	-d precompiled-headers="{precompiled-headers-68k}"

make-output = "{TempFolder}GSS/Kerberos Makefile script"
submakefile-target = gss-library

ppc-debug Ä {makefile-name} {gss-objects-ppc-debug-list} {krb5-objects-ppc-debug-list} {include-folders-list}
	Make {make-options-common} {make-options-ppc-debug} {submakefile-target} > {make-output}
	{make-output}
	
68k-debug Ä {makefile-name} {gss-objects-68k-debug-list} {krb5-objects-68k-debug-list} {include-folders-list}
	Make {make-options-common} {make-options-68k-debug} {submakefile-target} > {make-output}
	{make-output}
	
ppc-final Ä {makefile-name} {gss-objects-ppc-final-list} {krb5-objects-ppc-final-list} {include-folders-list}
	Make {make-options-common} {make-options-ppc-final} {submakefile-target} > {make-output}
	{make-output}
	
68k-final Ä {makefile-name} {gss-objects-68k-final-list} {krb5-objects-68k-final-list} {include-folders-list}
	Make {make-options-common} {make-options-68k-final} {submakefile-target} > {make-output}
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
###			krb5-library-export								-- name of gss Krb5 library export file
###			krb5-library-libraries							-- list of libraries Krb5 library links against
###			krb5-library-objects							-- list of object files Krb5 library links
###			krb5-library-fragment-name						-- name of Krb5 library fragment
###			krb5-library-main								-- name of Krb5 library main entry point
###			krb5-library-init								-- name of Krb5 library initialization routine
###			krb5-library-term								-- name of Krb5 library termination routine
###			krb5-library-linker-options						-- all other Krb5 library linker options
###		For Krb5 globals library
###			krb5-globals-library-output-folder				-- destination of Krb5 globals library output
###			krb5-globals-library-name						-- name of the Krb5 globals library
###			krb5-globals-library-export						-- name of gss Krb5 globals library export file
###			krb5-globals-library-libraries					-- list of libraries Krb5 globals library links against
###			krb5-globals-library-objects					-- list of object files Krb5 globals library links
###			krb5-globals-library-fragment-name				-- name of Krb5 globals library fragment
###			krb5-globals-library-main						-- name of Krb5 globals library main entry point
###			krb5-globals-library-init						-- name of Krb5 globals library initialization routine
###			krb5-globals-library-term						-- name of Krb5 globals library termination routine
###			krb5-globals-library-linker-options				-- all other Krb5 globals library linker options
###		For Krb5 globals data library
###			krb5-globals-data-library-output-folder			-- destination of Krb5 globals library output
###			krb5-globals-data-library-name					-- name of the Krb5 globals library
###			krb5-globals-data-library-export				-- name of gss Krb5 globals library export file
###			krb5-globals-data-library-libraries				-- list of libraries Krb5 globals library links against
###			krb5-globals-data-library-objects				-- list of object files Krb5 globals library links
###			krb5-globals-data-library-fragment-name			-- name of Krb5 globals library fragment
###			krb5-globals-data-library-main					-- name of Krb5 globals library main entry point
###			krb5-globals-data-library-init					-- name of Krb5 globals library initialization routine
###			krb5-globals-data-library-term					-- name of Krb5 globals library termination routine
###			krb5-globals-data-library-linker-options		-- all other Krb5 globals library linker options
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
krb5-globals-library-libraries =
krb5-globals-library-objects =
krb5-globals-library-linker-options =
krb5-globals-data-library-libraries =
krb5-globals-data-library-objects =
krb5-globals-data-library-linker-options =
precompiled-headers =
object-suffix = .ignore.me
object-suffix-data = .ignore.me.too

###	Generate various major components of build commands from the above variables
gss-library-output-files = ¶
	{gss-library-output-folder}{gss-library-name}{library-platform}{library-kind}
gss-library-dependencies = ¶
	{autogenerated-files} {gss-library-export} {gss-library-libraries} {gss-library-objects}
gss-library-build-command = ¶
	{library-linker} ¶
	-name {gss-library-fragment-name}{library-kind} ¶
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
	-name {krb5-library-fragment-name}{library-kind} ¶
	-main {krb5-library-main} ¶
	-init {krb5-library-init} ¶
	-term {krb5-library-term} ¶
	-@export {krb5-library-export} ¶
	-map {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind}.MAP ¶
	-o {krb5-library-output-folder}{krb5-library-name}{library-platform}{library-kind} ¶
	{krb5-library-linker-options} ¶
	{krb5-library-objects} {krb5-library-libraries}

krb5-globals-library-output-files = ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform}{library-kind}
krb5-globals-library-dependencies = ¶
	{autogenerated-files} {krb5-globals-library-export} {krb5-globals-library-libraries} {krb5-globals-library-objects}
krb5-globals-library-build-command = ¶
	{library-linker} ¶
	-name {krb5-globals-library-fragment-name}{library-kind} ¶
	-main {krb5-globals-library-main} ¶
	-init {krb5-globals-library-init} ¶
	-term {krb5-globals-library-term} ¶
	-@export {krb5-globals-library-export} ¶
	-map {krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform}{library-kind}.MAP ¶
	-o {krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform}{library-kind} ¶
	{krb5-globals-library-linker-options} ¶
	{krb5-globals-library-objects} {krb5-globals-library-libraries}

krb5-globals-data-library-output-files = ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform}
krb5-globals-data-library-dependencies = ¶
	{autogenerated-files} {krb5-globals-data-library-export} {krb5-globals-data-library-libraries} {krb5-globals-data-library-objects}
krb5-globals-data-library-build-command = ¶
	{library-linker} ¶
	-name {krb5-globals-data-library-fragment-name} ¶
	-main {krb5-globals-data-library-main} ¶
	-init {krb5-globals-data-library-init} ¶
	-term {krb5-globals-data-library-term} ¶
	-@export {krb5-globals-data-library-export} ¶
	-map {krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform}.MAP ¶
	-o {krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform} ¶
	{krb5-globals-data-library-linker-options} ¶
	{krb5-globals-data-library-objects} {krb5-globals-data-library-libraries}

###	Build commands

gss-library Ä {gss-library-output-files}
krb5-library Ä {krb5-library-output-files}
krb5-globals-library Ä {krb5-globals-library-output-files}
krb5-globals-data-library Ä {krb5-globals-data-library-output-files}

{gss-library-output-files} ÄÄ {gss-library-dependencies} {makefile-name}
	{create-folder} {gss-library-output-folder}
	{gss-library-build-command}
	
{krb5-library-output-files} ÄÄ {krb5-library-dependencies} {makefile-name}
	{create-folder} {krb5-library-output-folder}
	{krb5-library-build-command}

{krb5-globals-library-output-files} ÄÄ {krb5-globals-library-dependencies} {makefile-name}
	{create-folder} {krb5-globals-library-output-folder}
	{krb5-globals-library-build-command}
	
{krb5-globals-data-library-output-files} ÄÄ {krb5-globals-data-library-dependencies} {makefile-name}
	{create-folder} {krb5-globals-data-library-output-folder}
	{krb5-globals-data-library-build-command}

##############################################################################################################
###			Default compilation rules
##############################################################################################################

{object-suffix} Ä .c {autogenerated-files} {makefile-name} {precompiled-headers}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix} {compiler-options}

{object-suffix-data} Ä .c {autogenerated-files} {makefile-name} {precompiled-headers}
	{compiler} {DepDir}{Default}.c -o {DepDir}{Default}{object-suffix-data} {compiler-options}

##############################################################################################################
###			Autogenerating classic 68K glue files
##############################################################################################################

classic-glue-generation-script = {root-folder}CFMGlue.pl

classic-glue-output = ¶
	{root-folder}K5.CFMglue.c ¶
	{root-folder}GSS.CFMglue.c

glue Ä {classic-glue-output}

glue-gss Ä {root-folder}K5.CFMglue.c
glue-krb5 Ä {root-folder}GSS.CFMglue.c

{root-folder}mac:K5.CFMglue.c Ä {root-folder}mac:K5.CFMglue.cin {root-folder}mac:K5.CFMglue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:K5.moreCFMglue.cin {classic-glue-generation-script}
	perl {classic-glue-generation-script} < {root-folder}mac:K5.CFMglue.proto.h > {root-folder}mac:K5.CFMglue.c
	Catenate {root-folder}mac:K5.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:K5.CFMglue.c ¶
	{root-folder}mac:K5.moreCFMglue.cin | Catenate > {root-folder}mac:K5.CFMglue.c

{root-folder}mac:GSS.CFMglue.c Ä {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:GSS.CFMglue.proto.h ¶
	{root-folder}mac:CFMglue.c {root-folder}mac:GSS.moreCFMglue.cin {classic-glue-generation-script}
	perl {classic-glue-generation-script} < {root-folder}mac:GSS.CFMglue.proto.h > {root-folder}mac:GSS.CFMglue.c
	Catenate {root-folder}mac:GSS.CFMglue.cin {root-folder}mac:CFMglue.c {root-folder}mac:GSS.CFMglue.c ¶
	{root-folder}mac:GSS.moreCFMglue.cin | Catenate > {root-folder}mac:GSS.CFMglue.c

##############################################################################################################
###			Building the library files from multiple fragments
##############################################################################################################

gss-krb5-library-final-fragment-list = ¶
	{gss-library-output-folder}{gss-library-name}{library-platform-ppc}{library-kind-final} ¶
	{gss-library-output-folder}{gss-library-name}{library-platform-68k}{library-kind-final} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-final} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-68k}{library-kind-final} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-ppc}{library-kind-final} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-68k}{library-kind-final} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-ppc} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-68k} ¶
	{ccache-ppc-final} ¶
	{ccache-68k-final}
	
gss-krb5-library-debug-fragment-list = ¶
	{gss-library-output-folder}{gss-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{gss-library-output-folder}{gss-library-name}{library-platform-68k}{library-kind-debug} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{krb5-library-output-folder}{krb5-library-name}{library-platform-68k}{library-kind-debug} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-ppc}{library-kind-debug} ¶
	{krb5-globals-library-output-folder}{krb5-globals-library-name}{library-platform-68k}{library-kind-debug} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-ppc} ¶
	{krb5-globals-data-library-output-folder}{krb5-globals-data-library-name}{library-platform-68k} ¶
	{ccache-ppc-debug} ¶
	{ccache-68k-debug}

gss-krb5-library-final Ä all-final
	Make -d fragments="{gss-krb5-library-final-fragment-list}" -d target="{gss-krb5-library-final}" gss-krb5-library > {make-output}
	{make-output}

gss-krb5-library-debug Ä all-debug
	Make -d fragments="{gss-krb5-library-debug-fragment-list}" -d target="{gss-krb5-library-debug}" gss-krb5-library > {make-output}
	{make-output}

gss-krb5-library Ä
	Delete -i {target}
	Rez {root-folder}"version.r" -a -o {target}
	MergeFragment -x -z {fragments} {target}
	SetFile {target} -c gss-krb5-library-creator -t 'shlb'
	DeRez -only "'cfrg'(0)" {target} "{RIncludes}"CodeFragments.r | StreamEdit -s {root-folder}FragmentAlias.mpw | Rez -a -o {target} -i "{RIncludes}"

##############################################################################################################
###			Clean target deletes all generated files
##############################################################################################################

clean Ä
	# Need a dummy invalid name at the end to cover the case when nothing is found
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-debug}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-68k-debug}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-final}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-68k-final}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-ppc-data}/ Print"` supercalifragilisticexpialidoucious
	Delete -i `files -r -s -o -f "{root-folder}" | StreamEdit  -d -e "/Å{object-suffix-68k-data}/ Print"` supercalifragilisticexpialidoucious
	Delete -i {all-lists}
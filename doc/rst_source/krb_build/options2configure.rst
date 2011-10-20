.. _options2configure:

Options to Configure
=========================

There are a number of options to configure which you can use to control how the Kerberos distribution is built. i
The following table lists the most commonly used options to Kerberos V5's configure program.


--help
    Provides help to configure. This will list the set of commonly used options for building Kerberos.
--prefix=PREFIX
    By default, Kerberos will install the package's files rooted at '\/usr\/local' as in '\/usr\/local/bin', '\/usr\/local\/sbin', etc. 
    If you desire a different location, use this option.
--exec-prefix=EXECPREFIX
    This option allows one to separate the architecture independent programs from the configuration files and manual pages.
--localstatedir=LOCALSTATEDIR
    This option sets the directory for locally modifiable single-machine data. 
    In Kerberos, this mostly is useful for setting a location for the KDC data files, 
    as they will be installed in LOCALSTATEDIR\/krb5kdc, which is by default PREFIX\/var\/krb5kdc.
CC=COMPILER
    Use COMPILER as the C compiler.
CFLAGS=FLAGS
    Use FLAGS as the default set of C compiler flags.
    Note that if you use the native Ultrix compiler on a DECstation you are likely to lose 
    if you pass no flags to cc; md4.c takes an estimated 3,469 billion years to compile if you provide neither the -g flag nor the -O flag to cc.
CPPFLAGS=CPPOPTS
    Use CPPOPTS as the default set of C preprocessor flags. 
    The most common use of this option is to select certain #define's for use with the operating system's include files.
LD=LINKER
    Use LINKER as the default loader if it should be different from C compiler as specified above.
LDFLAGS=LDOPTS
    This option allows one to specify optional arguments to be passed to the linker. This might be used to specify optional library paths.
--with-krb4
    This option enables Kerberos V4 backwards compatibility using the builtin Kerberos V4 library.
--with-krb4=KRB4DIR
    This option enables Kerberos V4 backwards compatibility using a pre-existing Kerberos V4 installation. 
    The directory specified by KRB4DIR specifies where the V4 header files should be found (KRB4DIR\/include) 
    as well as where the V4 Kerberos library should be found (KRB4DIR/lib).
--without-krb4
    Disables Kerberos V4 backwards compatibility. 
    This prevents Kerberos V4 clients from using the V5 services including the KDC. 
    This would be useful if you know you will never install or need to interact with V4 clients.
--with-netlib[=libs]
    Allows for suppression of or replacement of network libraries. 
    By default, Kerberos V5 configuration will look for *-lnsl* and *-lsocket*. 
    If your operating system has a broken resolver library (see Solaris versions 2.0 through 2.3) 
    or fails to pass the tests in src/tests/resolv you will need to use this option.
--with-tcl=TCLPATH
    Some of the unit-tests in the build tree rely upon using a program in Tcl. 
    The directory specified by TCLPATH specifies where the Tcl header file (TCLPATH/include/tcl.h 
    as well as where the Tcl library should be found (TCLPATH/lib).
--enable-shared
    This option will turn on the building and use of shared library objects in the Kerberos build. This option is only supported on certain platforms.
--enable-dns

--enable-dns-for-kdc

--enable-dns-for-realm
    Enable the use of DNS to look up a host's Kerberos realm, or a realm's KDCs, if the information is not provided in krb5.conf. 
    See Hostnames for the Master and Slave KDCs for information about using DNS to locate the KDCs, 
    and Mapping Hostnames onto Kerberos Realms for information about using DNS to determine the default realm. 
    By default, DNS lookups are enabled for the former but not for the latter.
--enable-kdc-replay-cache
    Enable a cache in the KDC to detect retransmitted messages, and resend the previous responses to them. 
    This protects against certain types of attempts to extract information from the KDC through some of the hardware preauthentication systems.
--with-system-et
    Use an installed version of the error-table support software, the compile_et program, the com_err.h header file and the com_err library. 
    If these are not in the default locations, you may wish to specify CPPFLAGS=-I/some/dir and LDFLAGS=-L/some/other/dir options at configuration time as well.

    If this option is not given, a version supplied with the Kerberos sources will be built and installed along with the rest of the Kerberos tree, for Kerberos applications to link against.
--with-system-ss
    Use an installed version of the subsystem command-line interface software, 
    the mk_cmds program, the ss/ss.h header file and the ss library. 
    If these are not in the default locations, you may wish to specify CPPFLAGS=-I/some/dir and LDFLAGS=-L/some/other/dir options 
    at configuration time as well. See also the SS_LIB option.

    If this option is not given, the ss library supplied with the Kerberos sources will be compiled and linked into those programs that need it; it will not be installed separately.
SS_LIB=libs...
    If -lss is not the correct way to link in your installed ss library, for example if additional support libraries are needed, specify the correct link options here. Some variants of this library are around which allow for Emacs-like line editing, but different versions require different support libraries to be explicitly specified.

    This option is ignored if --with-system-ss is not specified.
--with-system-db
    Use an installed version of the Berkeley DB package, which must provide an API compatible with version 1.85. 
    This option is unsupported and untested. In particular, we do not know if the database-rename code used in the dumpfile load operation will behave properly.

    If this option is not given, a version supplied with the Kerberos sources will be built and installed. 
    (We are not updating this version at this time because of licensing issues with newer versions that we haven't investigated sufficiently yet.)
DB_HEADER=headername.h
    If db.h is not the correct header file to include to compile against the Berkeley DB 1.85 API, 
    specify the correct header file name with this option. For example, DB_HEADER=db3/db_185.h.
DB_LIB=libs...
    If -ldb is not the correct library specification for the Berkeley DB library version to be used, override it with this option. For example, DB_LIB=-ldb-3.3. 

For example, in order to configure Kerberos on a Solaris machine using the suncc compiler with the optimizer turned on, 
run the configure script with the following options::

     % ./configure CC=suncc CFLAGS=-O
     

For a slightly more complicated example, consider a system where several packages to be used by Kerberos are installed in /usr/foobar, i
including Berkeley DB 3.3, and an ss library that needs to link against the curses library. The configuration of Kerberos might be done thus::

      ./configure CPPFLAGS=-I/usr/foobar/include LDFLAGS=-L/usr/foobar/lib \
                   --with-system-et --with-system-ss --with-system-db \
                   SS_LIB='-lss -lcurses' \
                   DB_HEADER=db3/db_185.h DB_LIB=-ldb-3.3
     

In previous releases, --with- options were used to specify the compiler and linker and their options. 


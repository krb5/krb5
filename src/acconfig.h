/* just stuff needed by kerberos 5 */
/* This is in the top level so that it is in the same "local" directory
   as aclocal.m4, so autoreconf causes autoheader to find it. Nothing actually
   includes this file, it is always processed into something else. */

#undef ANSI_STDIO
#undef HAS_SETVBUF
#undef HAS_STDLIB_H
#undef HAS_STRDUP
#undef HAS_LABS
#undef HAS_VOID_TYPE
#undef KRB5_NO_PROTOTYPES
#undef KRB5_PROVIDE_PROTOTYPES
#undef KRB5_NO_NESTED_PROTOTYPES
#undef NO_STDLIB_H

#undef NO_YYLINENO
#undef POSIX_FILE_LOCKS
#undef POSIX_SIGTYPE
#undef POSIX_TERMIOS
#undef POSIX_TYPES
#undef USE_DIRENT_H
#undef USE_STRING_H
#undef WAIT_USES_INT
#undef krb5_sigtype
#undef HAS_UNISTD_H
#undef KRB5_USE_INET
#undef ODBM


/* Define if MIT Project Athena default configuration should be used */
#undef KRB5_ATHENA_COMPAT

/* Define if Kerberos V4 backwards compatibility should be supported */
#undef KRB5_KRB4_COMPAT

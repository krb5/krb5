/* just stuff needed by kerberos 5 */
/* This is in the top level so that it is in the same "local" directory
   as aclocal.m4, so autoreconf causes autoheader to find it. Nothing actually
   includes this file, it is always processed into something else. */

/* Don't use too large a block, because the autoheader processing can't
   handle it on some systems.  */

/* Define if "struct sockaddr_storage" is available.  */
#undef HAVE_STRUCT_SOCKADDR_STORAGE

/* Define to `long' if <sys/types.h> doesn't define. */
#undef time_t

/*
 * The stuff following here is taken from util/db2/acconfig.h
 */

#undef ssize_t

/* BSD4.3, non-posix types */

#undef u_char
#undef u_short
#undef u_int
#undef u_long

/* sized types used by db internals */

#undef int8_t
#undef u_int8_t
#undef int16_t
#undef u_int16_t
#undef int32_t
#undef u_int32_t


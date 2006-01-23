/* A Bison parser, made by GNU Bison 1.875.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     tAGO = 258,
     tDAY = 259,
     tDAYZONE = 260,
     tID = 261,
     tMERIDIAN = 262,
     tMINUTE_UNIT = 263,
     tMONTH = 264,
     tMONTH_UNIT = 265,
     tSEC_UNIT = 266,
     tSNUMBER = 267,
     tUNUMBER = 268,
     tZONE = 269,
     tDST = 270,
     tNEVER = 271
   };
#endif
#define tAGO 258
#define tDAY 259
#define tDAYZONE 260
#define tID 261
#define tMERIDIAN 262
#define tMINUTE_UNIT 263
#define tMONTH 264
#define tMONTH_UNIT 265
#define tSEC_UNIT 266
#define tSNUMBER 267
#define tUNUMBER 268
#define tZONE 269
#define tDST 270
#define tNEVER 271




/* Copy the first part of user declarations.  */
#line 1 "getdate.y"

/*
**  Originally written by Steven M. Bellovin <smb@research.att.com> while
**  at the University of North Carolina at Chapel Hill.  Later tweaked by
**  a couple of people on Usenet.  Completely overhauled by Rich $alz
**  <rsalz@bbn.com> and Jim Berets <jberets@bbn.com> in August, 1990;
**  send any email to Rich.
**
**  This grammar has nine shift/reduce conflicts.
**
**  This code is in the public domain and has no copyright.
*/
/* SUPPRESS 287 on yaccpar_sccsid *//* Unusd static variable */
/* SUPPRESS 288 on yyerrlab *//* Label unused */

#ifdef HAVE_CONFIG_H
#if defined (emacs) || defined (CONFIG_BROKETS)
#include <config.h>
#else
#include "config.h"
#endif
#endif
#include <string.h>

/* Since the code of getdate.y is not included in the Emacs executable
   itself, there is no need to #define static in this file.  Even if
   the code were included in the Emacs executable, it probably
   wouldn't do any harm to #undef it here; this will only cause
   problems if we try to write to a static variable, which I don't
   think this code needs to do.  */
#ifdef emacs
#undef static
#endif

/* The following block of alloca-related preprocessor directives is here
   solely to allow compilation by non GNU-C compilers of the C parser
   produced from this file by old versions of bison.  Newer versions of
   bison include a block similar to this one in bison.simple.  */

#ifdef __GNUC__
#undef alloca
#define alloca __builtin_alloca
#else
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#else
#ifdef _AIX /* for Bison */
 #pragma alloca
#else
void *alloca ();
#endif
#endif
#endif

#include <stdio.h>
#include <ctype.h>

#if defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif

/* The code at the top of get_date which figures out the offset of the
   current time zone checks various CPP symbols to see if special
   tricks are need, but defaults to using the gettimeofday system call.
   Include <sys/time.h> if that will be used.  */

#if	defined(vms)

#include <types.h>
#include <time.h>

#else

#include <sys/types.h>

#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#include <time.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <time.h>
#endif
#endif

#ifdef timezone
#undef timezone /* needed for sgi */
#endif

/*
** We use the obsolete `struct my_timeb' as part of our interface!
** Since the system doesn't have it, we define it here;
** our callers must do likewise.
*/
struct my_timeb {
    time_t		time;		/* Seconds since the epoch	*/
    unsigned short	millitm;	/* Field not used		*/
    short		timezone;	/* Minutes west of GMT		*/
    short		dstflag;	/* Field not used		*/
};
#endif	/* defined(vms) */

#if defined (STDC_HEADERS) || defined (USG)
#include <string.h>
#endif

/* Some old versions of bison generate parsers that use bcopy.
   That loses on systems that don't provide the function, so we have
   to redefine it here.  */
#ifndef bcopy
#define bcopy(from, to, len) memcpy ((to), (from), (len))
#endif

extern struct tm	*gmtime();
extern struct tm	*localtime();

#define yyparse getdate_yyparse
#define yylex getdate_yylex
#define yyerror getdate_yyerror

static int getdate_yylex (void);
static int getdate_yyerror (char *);


#define EPOCH		1970
#define EPOCH_END	2038 /* assumes 32 bits */
#define HOUR(x)		((time_t)(x) * 60)
#define SECSPERDAY	(24L * 60L * 60L)


/*
**  An entry in the lexical lookup table.
*/
typedef struct _TABLE {
    char	*name;
    int		type;
    time_t	value;
} TABLE;


/*
**  Daylight-savings mode:  on, off, or not yet known.
*/
typedef enum _DSTMODE {
    DSTon, DSToff, DSTmaybe
} DSTMODE;

/*
**  Meridian:  am, pm, or 24-hour style.
*/
typedef enum _MERIDIAN {
    MERam, MERpm, MER24
} MERIDIAN;


/*
**  Global variables.  We could get rid of most of these by using a good
**  union as the yacc stack.  (This routine was originally written before
**  yacc had the %union construct.)  Maybe someday; right now we only use
**  the %union very rarely.
*/
static char	*yyInput;
static DSTMODE	yyDSTmode;
static time_t	yyDayOrdinal;
static time_t	yyDayNumber;
static int	yyHaveDate;
static int	yyHaveDay;
static int	yyHaveRel;
static int	yyHaveTime;
static int	yyHaveZone;
static time_t	yyTimezone;
static time_t	yyDay;
static time_t	yyHour;
static time_t	yyMinutes;
static time_t	yyMonth;
static time_t	yySeconds;
static time_t	yyYear;
static MERIDIAN	yyMeridian;
static time_t	yyRelMonth;
static time_t	yyRelSeconds;



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 185 "getdate.y"
typedef union YYSTYPE {
    time_t		Number;
    enum _MERIDIAN	Meridian;
} YYSTYPE;
/* Line 191 of yacc.c.  */
#line 296 "y.tab.c"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 308 "y.tab.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   43

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  20
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  10
/* YYNRULES -- Number of rules. */
#define YYNRULES  41
/* YYNRULES -- Number of states. */
#define YYNSTATES  52

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   271

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    18,     2,     2,    19,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    17,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     7,     9,    11,    13,    15,    17,
      19,    22,    27,    32,    39,    46,    48,    50,    53,    55,
      58,    61,    65,    71,    75,    79,    82,    87,    90,    94,
      97,    99,   102,   105,   107,   110,   113,   115,   118,   121,
     123,   124
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      21,     0,    -1,    -1,    21,    22,    -1,    16,    -1,    23,
      -1,    24,    -1,    26,    -1,    25,    -1,    27,    -1,    13,
       7,    -1,    13,    17,    13,    29,    -1,    13,    17,    13,
      12,    -1,    13,    17,    13,    17,    13,    29,    -1,    13,
      17,    13,    17,    13,    12,    -1,    14,    -1,     5,    -1,
      14,    15,    -1,     4,    -1,     4,    18,    -1,    13,     4,
      -1,    13,    19,    13,    -1,    13,    19,    13,    19,    13,
      -1,    13,    12,    12,    -1,    13,     9,    12,    -1,     9,
      13,    -1,     9,    13,    18,    13,    -1,    13,     9,    -1,
      13,     9,    13,    -1,    28,     3,    -1,    28,    -1,    13,
       8,    -1,    12,     8,    -1,     8,    -1,    12,    11,    -1,
      13,    11,    -1,    11,    -1,    12,    10,    -1,    13,    10,
      -1,    10,    -1,    -1,     7,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short yyrline[] =
{
       0,   199,   199,   200,   201,   212,   215,   218,   221,   224,
     229,   235,   241,   248,   254,   264,   268,   273,   279,   283,
     287,   293,   297,   302,   308,   314,   318,   323,   327,   334,
     338,   341,   344,   347,   350,   353,   356,   359,   362,   365,
     370,   373
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "tAGO", "tDAY", "tDAYZONE", "tID", 
  "tMERIDIAN", "tMINUTE_UNIT", "tMONTH", "tMONTH_UNIT", "tSEC_UNIT", 
  "tSNUMBER", "tUNUMBER", "tZONE", "tDST", "tNEVER", "':'", "','", "'/'", 
  "$accept", "spec", "item", "time", "zone", "day", "date", "rel", 
  "relunit", "o_merid", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,    58,    44,    47
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    20,    21,    21,    21,    22,    22,    22,    22,    22,
      23,    23,    23,    23,    23,    24,    24,    24,    25,    25,
      25,    26,    26,    26,    26,    26,    26,    26,    26,    27,
      27,    28,    28,    28,    28,    28,    28,    28,    28,    28,
      29,    29
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     2,     1,     1,     1,     1,     1,     1,
       2,     4,     4,     6,     6,     1,     1,     2,     1,     2,
       2,     3,     5,     3,     3,     2,     4,     2,     3,     2,
       1,     2,     2,     1,     2,     2,     1,     2,     2,     1,
       0,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     4,     0,     1,    18,    16,    33,     0,    39,    36,
       0,     0,    15,     3,     5,     6,     8,     7,     9,    30,
      19,    25,    32,    37,    34,    20,    10,    31,    27,    38,
      35,     0,     0,     0,    17,    29,     0,    24,    28,    23,
      40,    21,    26,    41,    12,     0,    11,     0,    40,    22,
      14,    13
};

/* YYDEFGOTO[NTERM-NUM]. */
static const yysigned_char yydefgoto[] =
{
      -1,     2,    13,    14,    15,    16,    17,    18,    19,    46
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -13
static const yysigned_char yypact[] =
{
      -6,   -13,    12,   -13,    -7,   -13,   -13,     5,   -13,   -13,
      23,    -4,    13,   -13,   -13,   -13,   -13,   -13,   -13,    26,
     -13,    17,   -13,   -13,   -13,   -13,   -13,   -13,   -11,   -13,
     -13,    18,    24,    25,   -13,   -13,    27,   -13,   -13,   -13,
       2,    22,   -13,   -13,   -13,    29,   -13,    30,    20,   -13,
     -13,   -13
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -13,   -13,   -13,   -13,   -13,   -13,   -13,   -13,   -13,   -12
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
      25,    37,    38,    26,    27,    28,    29,    30,    31,    43,
       1,    20,     3,    32,    44,    33,     4,     5,    21,    45,
       6,     7,     8,     9,    10,    11,    12,    43,    34,    35,
      39,    22,    50,    23,    24,    36,    51,    40,    41,     0,
      42,    47,    48,    49
};

static const yysigned_char yycheck[] =
{
       4,    12,    13,     7,     8,     9,    10,    11,    12,     7,
      16,    18,     0,    17,    12,    19,     4,     5,    13,    17,
       8,     9,    10,    11,    12,    13,    14,     7,    15,     3,
      12,     8,    12,    10,    11,    18,    48,    13,    13,    -1,
      13,    19,    13,    13
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    16,    21,     0,     4,     5,     8,     9,    10,    11,
      12,    13,    14,    22,    23,    24,    25,    26,    27,    28,
      18,    13,     8,    10,    11,     4,     7,     8,     9,    10,
      11,    12,    17,    19,    15,     3,    18,    12,    13,    12,
      13,    13,    13,     7,    12,    17,    29,    19,    13,    13,
      12,    29
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrlab1

/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)         \
  Current.first_line   = Rhs[1].first_line;      \
  Current.first_column = Rhs[1].first_column;    \
  Current.last_line    = Rhs[N].last_line;       \
  Current.last_column  = Rhs[N].last_column;
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (cinluded).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short *bottom, short *top)
#else
static void
yy_stack_print (bottom, top)
    short *bottom;
    short *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylineno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylineno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 4:
#line 201 "getdate.y"
    {
	    yyYear = 1970;
	    yyMonth = 1;
	    yyDay = 1;
	    yyHour = yyMinutes = yySeconds = 0;
	    yyDSTmode = DSToff;
	    yyTimezone = 0; /* gmt */
	    yyHaveDate++;
        }
    break;

  case 5:
#line 212 "getdate.y"
    {
	    yyHaveTime++;
	}
    break;

  case 6:
#line 215 "getdate.y"
    {
	    yyHaveZone++;
	}
    break;

  case 7:
#line 218 "getdate.y"
    {
	    yyHaveDate++;
	}
    break;

  case 8:
#line 221 "getdate.y"
    {
	    yyHaveDay++;
	}
    break;

  case 9:
#line 224 "getdate.y"
    {
	    yyHaveRel++;
	}
    break;

  case 10:
#line 229 "getdate.y"
    {
	    yyHour = yyvsp[-1].Number;
	    yyMinutes = 0;
	    yySeconds = 0;
	    yyMeridian = yyvsp[0].Meridian;
	}
    break;

  case 11:
#line 235 "getdate.y"
    {
	    yyHour = yyvsp[-3].Number;
	    yyMinutes = yyvsp[-1].Number;
	    yySeconds = 0;
	    yyMeridian = yyvsp[0].Meridian;
	}
    break;

  case 12:
#line 241 "getdate.y"
    {
	    yyHour = yyvsp[-3].Number;
	    yyMinutes = yyvsp[-1].Number;
	    yyMeridian = MER24;
	    yyDSTmode = DSToff;
	    yyTimezone = - (yyvsp[0].Number % 100 + (yyvsp[0].Number / 100) * 60);
	}
    break;

  case 13:
#line 248 "getdate.y"
    {
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
	    yyMeridian = yyvsp[0].Meridian;
	}
    break;

  case 14:
#line 254 "getdate.y"
    {
	    yyHour = yyvsp[-5].Number;
	    yyMinutes = yyvsp[-3].Number;
	    yySeconds = yyvsp[-1].Number;
	    yyMeridian = MER24;
	    yyDSTmode = DSToff;
	    yyTimezone = - (yyvsp[0].Number % 100 + (yyvsp[0].Number / 100) * 60);
	}
    break;

  case 15:
#line 264 "getdate.y"
    {
	    yyTimezone = yyvsp[0].Number;
	    yyDSTmode = DSToff;
	}
    break;

  case 16:
#line 268 "getdate.y"
    {
	    yyTimezone = yyvsp[0].Number;
	    yyDSTmode = DSTon;
	}
    break;

  case 17:
#line 273 "getdate.y"
    {
	    yyTimezone = yyvsp[-1].Number;
	    yyDSTmode = DSTon;
	}
    break;

  case 18:
#line 279 "getdate.y"
    {
	    yyDayOrdinal = 1;
	    yyDayNumber = yyvsp[0].Number;
	}
    break;

  case 19:
#line 283 "getdate.y"
    {
	    yyDayOrdinal = 1;
	    yyDayNumber = yyvsp[-1].Number;
	}
    break;

  case 20:
#line 287 "getdate.y"
    {
	    yyDayOrdinal = yyvsp[-1].Number;
	    yyDayNumber = yyvsp[0].Number;
	}
    break;

  case 21:
#line 293 "getdate.y"
    {
	    yyMonth = yyvsp[-2].Number;
	    yyDay = yyvsp[0].Number;
	}
    break;

  case 22:
#line 297 "getdate.y"
    {
	    yyMonth = yyvsp[-4].Number;
	    yyDay = yyvsp[-2].Number;
	    yyYear = yyvsp[0].Number;
	}
    break;

  case 23:
#line 302 "getdate.y"
    {
	    /* ISO 8601 format.  yyyy-mm-dd.  */
	    yyYear = yyvsp[-2].Number;
	    yyMonth = -yyvsp[-1].Number;
	    yyDay = -yyvsp[0].Number;
	}
    break;

  case 24:
#line 308 "getdate.y"
    {
	    /* e.g. 17-JUN-1992.  */
	    yyDay = yyvsp[-2].Number;
	    yyMonth = yyvsp[-1].Number;
	    yyYear = -yyvsp[0].Number;
	}
    break;

  case 25:
#line 314 "getdate.y"
    {
	    yyMonth = yyvsp[-1].Number;
	    yyDay = yyvsp[0].Number;
	}
    break;

  case 26:
#line 318 "getdate.y"
    {
	    yyMonth = yyvsp[-3].Number;
	    yyDay = yyvsp[-2].Number;
	    yyYear = yyvsp[0].Number;
	}
    break;

  case 27:
#line 323 "getdate.y"
    {
	    yyMonth = yyvsp[0].Number;
	    yyDay = yyvsp[-1].Number;
	}
    break;

  case 28:
#line 327 "getdate.y"
    {
	    yyMonth = yyvsp[-1].Number;
	    yyDay = yyvsp[-2].Number;
	    yyYear = yyvsp[0].Number;
	}
    break;

  case 29:
#line 334 "getdate.y"
    {
	    yyRelSeconds = -yyRelSeconds;
	    yyRelMonth = -yyRelMonth;
	}
    break;

  case 31:
#line 341 "getdate.y"
    {
	    yyRelSeconds += yyvsp[-1].Number * yyvsp[0].Number * 60L;
	}
    break;

  case 32:
#line 344 "getdate.y"
    {
	    yyRelSeconds += yyvsp[-1].Number * yyvsp[0].Number * 60L;
	}
    break;

  case 33:
#line 347 "getdate.y"
    {
	    yyRelSeconds += yyvsp[0].Number * 60L;
	}
    break;

  case 34:
#line 350 "getdate.y"
    {
	    yyRelSeconds += yyvsp[-1].Number;
	}
    break;

  case 35:
#line 353 "getdate.y"
    {
	    yyRelSeconds += yyvsp[-1].Number;
	}
    break;

  case 36:
#line 356 "getdate.y"
    {
	    yyRelSeconds++;
	}
    break;

  case 37:
#line 359 "getdate.y"
    {
	    yyRelMonth += yyvsp[-1].Number * yyvsp[0].Number;
	}
    break;

  case 38:
#line 362 "getdate.y"
    {
	    yyRelMonth += yyvsp[-1].Number * yyvsp[0].Number;
	}
    break;

  case 39:
#line 365 "getdate.y"
    {
	    yyRelMonth += yyvsp[0].Number;
	}
    break;

  case 40:
#line 370 "getdate.y"
    {
	    yyval.Meridian = MER24;
	}
    break;

  case 41:
#line 373 "getdate.y"
    {
	    yyval.Meridian = yyvsp[0].Meridian;
	}
    break;


    }

/* Line 991 of yacc.c.  */
#line 1530 "y.tab.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("syntax error, unexpected ") + 1;
	  yysize += yystrlen (yytname[yytype]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* Return failure if at end of input.  */
      if (yychar == YYEOF)
        {
	  /* Pop the error token.  */
          YYPOPSTACK;
	  /* Pop the rest of the stack.  */
	  while (yyss < yyssp)
	    {
	      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
	      yydestruct (yystos[*yyssp], yyvsp);
	      YYPOPSTACK;
	    }
	  YYABORT;
        }

      YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
      yydestruct (yytoken, &yylval);
      yychar = YYEMPTY;

    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab2;


/*----------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action.  |
`----------------------------------------------------*/
yyerrlab1:

  /* Suppress GCC warning that yyerrlab1 is unused when no action
     invokes YYERROR.  */
#if defined (__GNUC_MINOR__) && 2093 <= (__GNUC__ * 1000 + __GNUC_MINOR__) \
    && !defined __cplusplus
  __attribute__ ((__unused__))
#endif


  goto yyerrlab2;


/*---------------------------------------------------------------.
| yyerrlab2 -- pop states until the error token can be shifted.  |
`---------------------------------------------------------------*/
yyerrlab2:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      yyvsp--;
      yystate = *--yyssp;

      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 378 "getdate.y"


/* Month and day table. */
static TABLE const MonthDayTable[] = {
    { "january",	tMONTH,  1 },
    { "february",	tMONTH,  2 },
    { "march",		tMONTH,  3 },
    { "april",		tMONTH,  4 },
    { "may",		tMONTH,  5 },
    { "june",		tMONTH,  6 },
    { "july",		tMONTH,  7 },
    { "august",		tMONTH,  8 },
    { "september",	tMONTH,  9 },
    { "sept",		tMONTH,  9 },
    { "october",	tMONTH, 10 },
    { "november",	tMONTH, 11 },
    { "december",	tMONTH, 12 },
    { "sunday",		tDAY, 0 },
    { "monday",		tDAY, 1 },
    { "tuesday",	tDAY, 2 },
    { "tues",		tDAY, 2 },
    { "wednesday",	tDAY, 3 },
    { "wednes",		tDAY, 3 },
    { "thursday",	tDAY, 4 },
    { "thur",		tDAY, 4 },
    { "thurs",		tDAY, 4 },
    { "friday",		tDAY, 5 },
    { "saturday",	tDAY, 6 },
    { NULL }
};

/* Time units table. */
static TABLE const UnitsTable[] = {
    { "year",		tMONTH_UNIT,	12 },
    { "month",		tMONTH_UNIT,	1 },
    { "fortnight",	tMINUTE_UNIT,	14 * 24 * 60 },
    { "week",		tMINUTE_UNIT,	7 * 24 * 60 },
    { "day",		tMINUTE_UNIT,	1 * 24 * 60 },
    { "hour",		tMINUTE_UNIT,	60 },
    { "minute",		tMINUTE_UNIT,	1 },
    { "min",		tMINUTE_UNIT,	1 },
    { "second",		tSEC_UNIT,	1 },
    { "sec",		tSEC_UNIT,	1 },
    { NULL }
};

/* Assorted relative-time words. */
static TABLE const OtherTable[] = {
    { "tomorrow",	tMINUTE_UNIT,	1 * 24 * 60 },
    { "yesterday",	tMINUTE_UNIT,	-1 * 24 * 60 },
    { "today",		tMINUTE_UNIT,	0 },
    { "now",		tMINUTE_UNIT,	0 },
    { "last",		tUNUMBER,	-1 },
    { "this",		tMINUTE_UNIT,	0 },
    { "next",		tUNUMBER,	2 },
    { "first",		tUNUMBER,	1 },
/*  { "second",		tUNUMBER,	2 }, */
    { "third",		tUNUMBER,	3 },
    { "fourth",		tUNUMBER,	4 },
    { "fifth",		tUNUMBER,	5 },
    { "sixth",		tUNUMBER,	6 },
    { "seventh",	tUNUMBER,	7 },
    { "eighth",		tUNUMBER,	8 },
    { "ninth",		tUNUMBER,	9 },
    { "tenth",		tUNUMBER,	10 },
    { "eleventh",	tUNUMBER,	11 },
    { "twelfth",	tUNUMBER,	12 },
    { "ago",		tAGO,		1 },
    { "never",		tNEVER,		0 },
    { NULL }
};

/* The timezone table. */
/* Some of these are commented out because a time_t can't store a float. */
static TABLE const TimezoneTable[] = {
    { "gmt",	tZONE,     HOUR( 0) },	/* Greenwich Mean */
    { "ut",	tZONE,     HOUR( 0) },	/* Universal (Coordinated) */
    { "utc",	tZONE,     HOUR( 0) },
    { "wet",	tZONE,     HOUR( 0) },	/* Western European */
    { "bst",	tDAYZONE,  HOUR( 0) },	/* British Summer */
    { "wat",	tZONE,     HOUR( 1) },	/* West Africa */
    { "at",	tZONE,     HOUR( 2) },	/* Azores */
#if	0
    /* For completeness.  BST is also British Summer, and GST is
     * also Guam Standard. */
    { "bst",	tZONE,     HOUR( 3) },	/* Brazil Standard */
    { "gst",	tZONE,     HOUR( 3) },	/* Greenland Standard */
#endif
#if 0
    { "nft",	tZONE,     HOUR(3.5) },	/* Newfoundland */
    { "nst",	tZONE,     HOUR(3.5) },	/* Newfoundland Standard */
    { "ndt",	tDAYZONE,  HOUR(3.5) },	/* Newfoundland Daylight */
#endif
    { "ast",	tZONE,     HOUR( 4) },	/* Atlantic Standard */
    { "adt",	tDAYZONE,  HOUR( 4) },	/* Atlantic Daylight */
    { "est",	tZONE,     HOUR( 5) },	/* Eastern Standard */
    { "edt",	tDAYZONE,  HOUR( 5) },	/* Eastern Daylight */
    { "cst",	tZONE,     HOUR( 6) },	/* Central Standard */
    { "cdt",	tDAYZONE,  HOUR( 6) },	/* Central Daylight */
    { "mst",	tZONE,     HOUR( 7) },	/* Mountain Standard */
    { "mdt",	tDAYZONE,  HOUR( 7) },	/* Mountain Daylight */
    { "pst",	tZONE,     HOUR( 8) },	/* Pacific Standard */
    { "pdt",	tDAYZONE,  HOUR( 8) },	/* Pacific Daylight */
    { "yst",	tZONE,     HOUR( 9) },	/* Yukon Standard */
    { "ydt",	tDAYZONE,  HOUR( 9) },	/* Yukon Daylight */
    { "hst",	tZONE,     HOUR(10) },	/* Hawaii Standard */
    { "hdt",	tDAYZONE,  HOUR(10) },	/* Hawaii Daylight */
    { "cat",	tZONE,     HOUR(10) },	/* Central Alaska */
    { "ahst",	tZONE,     HOUR(10) },	/* Alaska-Hawaii Standard */
    { "nt",	tZONE,     HOUR(11) },	/* Nome */
    { "idlw",	tZONE,     HOUR(12) },	/* International Date Line West */
    { "cet",	tZONE,     -HOUR(1) },	/* Central European */
    { "met",	tZONE,     -HOUR(1) },	/* Middle European */
    { "mewt",	tZONE,     -HOUR(1) },	/* Middle European Winter */
    { "mest",	tDAYZONE,  -HOUR(1) },	/* Middle European Summer */
    { "swt",	tZONE,     -HOUR(1) },	/* Swedish Winter */
    { "sst",	tDAYZONE,  -HOUR(1) },	/* Swedish Summer */
    { "fwt",	tZONE,     -HOUR(1) },	/* French Winter */
    { "fst",	tDAYZONE,  -HOUR(1) },	/* French Summer */
    { "eet",	tZONE,     -HOUR(2) },	/* Eastern Europe, USSR Zone 1 */
    { "bt",	tZONE,     -HOUR(3) },	/* Baghdad, USSR Zone 2 */
#if 0
    { "it",	tZONE,     -HOUR(3.5) },/* Iran */
#endif
    { "zp4",	tZONE,     -HOUR(4) },	/* USSR Zone 3 */
    { "zp5",	tZONE,     -HOUR(5) },	/* USSR Zone 4 */
#if 0
    { "ist",	tZONE,     -HOUR(5.5) },/* Indian Standard */
#endif
    { "zp6",	tZONE,     -HOUR(6) },	/* USSR Zone 5 */
#if	0
    /* For completeness.  NST is also Newfoundland Stanard, and SST is
     * also Swedish Summer. */
    { "nst",	tZONE,     -HOUR(6.5) },/* North Sumatra */
    { "sst",	tZONE,     -HOUR(7) },	/* South Sumatra, USSR Zone 6 */
#endif	/* 0 */
    { "wast",	tZONE,     -HOUR(7) },	/* West Australian Standard */
    { "wadt",	tDAYZONE,  -HOUR(7) },	/* West Australian Daylight */
#if 0
    { "jt",	tZONE,     -HOUR(7.5) },/* Java (3pm in Cronusland!) */
#endif
    { "cct",	tZONE,     -HOUR(8) },	/* China Coast, USSR Zone 7 */
    { "jst",	tZONE,     -HOUR(9) },	/* Japan Standard, USSR Zone 8 */
    { "kst",	tZONE,     -HOUR(9) },	/* Korean Standard */
#if 0
    { "cast",	tZONE,     -HOUR(9.5) },/* Central Australian Standard */
    { "cadt",	tDAYZONE,  -HOUR(9.5) },/* Central Australian Daylight */
#endif
    { "east",	tZONE,     -HOUR(10) },	/* Eastern Australian Standard */
    { "eadt",	tDAYZONE,  -HOUR(10) },	/* Eastern Australian Daylight */
    { "gst",	tZONE,     -HOUR(10) },	/* Guam Standard, USSR Zone 9 */
    { "kdt",	tZONE,     -HOUR(10) },	/* Korean Daylight */
    { "nzt",	tZONE,     -HOUR(12) },	/* New Zealand */
    { "nzst",	tZONE,     -HOUR(12) },	/* New Zealand Standard */
    { "nzdt",	tDAYZONE,  -HOUR(12) },	/* New Zealand Daylight */
    { "idle",	tZONE,     -HOUR(12) },	/* International Date Line East */
    {  NULL  }
};

/* ARGSUSED */
static int
yyerror(s)
    char	*s;
{
  return 0;
}


static time_t
ToSeconds(Hours, Minutes, Seconds, Meridian)
    time_t	Hours;
    time_t	Minutes;
    time_t	Seconds;
    MERIDIAN	Meridian;
{
    if (Minutes < 0 || Minutes > 59 || Seconds < 0 || Seconds > 59)
	return -1;
    switch (Meridian) {
    case MER24:
	if (Hours < 0 || Hours > 23)
	    return -1;
	return (Hours * 60L + Minutes) * 60L + Seconds;
    case MERam:
	if (Hours < 1 || Hours > 12)
	    return -1;
	return (Hours * 60L + Minutes) * 60L + Seconds;
    case MERpm:
	if (Hours < 1 || Hours > 12)
	    return -1;
	return ((Hours + 12) * 60L + Minutes) * 60L + Seconds;
    default:
	abort ();
    }
    /* NOTREACHED */
}

/*
 * From hh:mm:ss [am|pm] mm/dd/yy [tz], compute and return the number
 * of seconds since 00:00:00 1/1/70 GMT.
 */
static time_t
Convert(Month, Day, Year, Hours, Minutes, Seconds, Meridian, DSTmode)
    time_t	Month;
    time_t	Day;
    time_t	Year;
    time_t	Hours;
    time_t	Minutes;
    time_t	Seconds;
    MERIDIAN	Meridian;
    DSTMODE	DSTmode;
{
    static int DaysInMonth[12] = {
	31, 0, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    time_t	tod;
    time_t	Julian;
    int		i;

    if (Year < 0)
	Year = -Year;
    if (Year < 1900)
	Year += 1900;
    DaysInMonth[1] = Year % 4 == 0 && (Year % 100 != 0 || Year % 400 == 0)
		    ? 29 : 28;
    if (Year < EPOCH
	|| Year > EPOCH_END
	|| Month < 1 || Month > 12
	/* Lint fluff:  "conversion from long may lose accuracy" */
	|| Day < 1 || Day > DaysInMonth[(int)--Month])
	 return -1;

    for (Julian = Day - 1, i = 0; i < Month; i++)
	Julian += DaysInMonth[i];
    for (i = EPOCH; i < Year; i++)
	 Julian += 365 + ((i % 4 == 0) && ((Year % 100 != 0) ||
					   (Year % 400 == 0)));
    Julian *= SECSPERDAY;
    Julian += yyTimezone * 60L;
    if ((tod = ToSeconds(Hours, Minutes, Seconds, Meridian)) < 0)
	return -1;
    Julian += tod;
    if (DSTmode == DSTon
     || (DSTmode == DSTmaybe && localtime(&Julian)->tm_isdst))
	Julian -= 60 * 60;
    return Julian;
}


static time_t
DSTcorrect(Start, Future)
    time_t	Start;
    time_t	Future;
{
    time_t	StartDay;
    time_t	FutureDay;

    StartDay = (localtime(&Start)->tm_hour + 1) % 24;
    FutureDay = (localtime(&Future)->tm_hour + 1) % 24;
    return (Future - Start) + (StartDay - FutureDay) * 60L * 60L;
}


static time_t
RelativeDate(Start, DayOrdinal, DayNumber)
    time_t	Start;
    time_t	DayOrdinal;
    time_t	DayNumber;
{
    struct tm	*tm;
    time_t	now;

    now = Start;
    tm = localtime(&now);
    now += SECSPERDAY * ((DayNumber - tm->tm_wday + 7) % 7);
    now += 7 * SECSPERDAY * (DayOrdinal <= 0 ? DayOrdinal : DayOrdinal - 1);
    return DSTcorrect(Start, now);
}


static time_t
RelativeMonth(Start, RelMonth)
    time_t	Start;
    time_t	RelMonth;
{
    struct tm	*tm;
    time_t	Month;
    time_t	Year;
    time_t	ret;

    if (RelMonth == 0)
	return 0;
    tm = localtime(&Start);
    Month = 12 * tm->tm_year + tm->tm_mon + RelMonth;
    Year = Month / 12;
    Month = Month % 12 + 1;
    ret = Convert(Month, (time_t)tm->tm_mday, Year,
		  (time_t)tm->tm_hour, (time_t)tm->tm_min, (time_t)tm->tm_sec,
		  MER24, DSTmaybe);
    if (ret == -1)
      return ret;
    return DSTcorrect(Start, ret);
}


static int
LookupWord(buff)
    char		*buff;
{
    register char	*p;
    register char	*q;
    register const TABLE	*tp;
    int			i;
    int			abbrev;

    /* Make it lowercase. */
    for (p = buff; *p; p++)
	if (isupper((int) *p))
	    *p = tolower((int) *p);

    if (strcmp(buff, "am") == 0 || strcmp(buff, "a.m.") == 0) {
	yylval.Meridian = MERam;
	return tMERIDIAN;
    }
    if (strcmp(buff, "pm") == 0 || strcmp(buff, "p.m.") == 0) {
	yylval.Meridian = MERpm;
	return tMERIDIAN;
    }

    /* See if we have an abbreviation for a month. */
    if (strlen(buff) == 3)
	abbrev = 1;
    else if (strlen(buff) == 4 && buff[3] == '.') {
	abbrev = 1;
	buff[3] = '\0';
    }
    else
	abbrev = 0;

    for (tp = MonthDayTable; tp->name; tp++) {
	if (abbrev) {
	    if (strncmp(buff, tp->name, 3) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	}
	else if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}
    }

    for (tp = TimezoneTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    if (strcmp(buff, "dst") == 0) 
	return tDST;

    for (tp = UnitsTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Strip off any plural and try the units table again. */
    i = strlen(buff) - 1;
    if (buff[i] == 's') {
	buff[i] = '\0';
	for (tp = UnitsTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }
	buff[i] = 's';		/* Put back for "this" in OtherTable. */
    }

    for (tp = OtherTable; tp->name; tp++)
	if (strcmp(buff, tp->name) == 0) {
	    yylval.Number = tp->value;
	    return tp->type;
	}

    /* Drop out any periods and try the timezone table again. */
    for (i = 0, p = q = buff; *q; q++)
	if (*q != '.')
	    *p++ = *q;
	else
	    i++;
    *p = '\0';
    if (i)
	for (tp = TimezoneTable; tp->name; tp++)
	    if (strcmp(buff, tp->name) == 0) {
		yylval.Number = tp->value;
		return tp->type;
	    }

    return tID;
}


static int
yylex()
{
    register char	c;
    register char	*p;
    char		buff[20];
    int			Count;
    int			sign;

    for ( ; ; ) {
	while (isspace((int) *yyInput))
	    yyInput++;

	c = *yyInput;
	if (isdigit((int) c) || c == '-' || c == '+') {
	    if (c == '-' || c == '+') {
		sign = c == '-' ? -1 : 1;
		if (!isdigit((int) (*++yyInput)))
		    /* skip the '-' sign */
		    continue;
	    }
	    else
		sign = 0;
	    for (yylval.Number = 0; isdigit((int) (c = *yyInput++)); )
		yylval.Number = 10 * yylval.Number + c - '0';
	    yyInput--;
	    if (sign < 0)
		yylval.Number = -yylval.Number;
	    return sign ? tSNUMBER : tUNUMBER;
	}
	if (isalpha((int) c)) {
	    for (p = buff; isalpha((int) (c = *yyInput++)) || c == '.'; )
		if (p < &buff[sizeof buff - 1])
		    *p++ = c;
	    *p = '\0';
	    yyInput--;
	    return LookupWord(buff);
	}
	if (c != '(')
	    return *yyInput++;
	Count = 0;
	do {
	    c = *yyInput++;
	    if (c == '\0')
		return c;
	    if (c == '(')
		Count++;
	    else if (c == ')')
		Count--;
	} while (Count > 0);
    }
}


#define TM_YEAR_ORIGIN 1900

/* Yield A - B, measured in seconds.  */
static time_t
difftm(a, b)
     struct tm *a, *b;
{
  int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
  int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
  return
    (
     (
      (
       /* difference in day of year */
       a->tm_yday - b->tm_yday
       /* + intervening leap days */
       +  ((ay >> 2) - (by >> 2))
       -  (ay/100 - by/100)
       +  ((ay/100 >> 2) - (by/100 >> 2))
       /* + difference in years * 365 */
       +  (time_t)(ay-by) * 365
       )*24 + (a->tm_hour - b->tm_hour)
      )*60 + (a->tm_min - b->tm_min)
     )*60 + (a->tm_sec - b->tm_sec);
}

/* For get_date extern declaration compatibility check... yuck.  */
#include <krb5.h>
/* #include "kadmin.h" */

time_t
get_date(p)
    char		*p;
{
    struct my_timeb	*now = NULL;
    struct tm		*tm, gmt;
    struct my_timeb	ftz;
    time_t		Start;
    time_t		tod;
    time_t		delta;

    yyInput = p;
    if (now == NULL) {
        now = &ftz;

	ftz.time = time((time_t *) 0);

	if (! (tm = gmtime (&ftz.time)))
	    return -1;
	gmt = *tm;	/* Make a copy, in case localtime modifies *tm.  */
	ftz.timezone = difftm (&gmt, localtime (&ftz.time)) / 60;
    }

    tm = localtime(&now->time);
    yyYear = tm->tm_year;
    yyMonth = tm->tm_mon + 1;
    yyDay = tm->tm_mday;
    yyTimezone = now->timezone;
    yyDSTmode = DSTmaybe;
    yyHour = 0;
    yyMinutes = 0;
    yySeconds = 0;
    yyMeridian = MER24;
    yyRelSeconds = 0;
    yyRelMonth = 0;
    yyHaveDate = 0;
    yyHaveDay = 0;
    yyHaveRel = 0;
    yyHaveTime = 0;
    yyHaveZone = 0;

    /*
     * When yyparse returns, zero or more of yyHave{Time,Zone,Date,Day,Rel} 
     * will have been incremented.  The value is number of items of
     * that type that were found; for all but Rel, more than one is
     * illegal.
     *
     * For each yyHave indicator, the following values are set:
     *
     * yyHaveTime:
     *	yyHour, yyMinutes, yySeconds: hh:mm:ss specified, initialized
     *				      to zeros above
     *	yyMeridian: MERam, MERpm, or MER24
     *	yyTimeZone: time zone specified in minutes
     *  yyDSTmode: DSToff if yyTimeZone is set, otherwise unchanged
     *		   (initialized above to DSTmaybe)
     *
     * yyHaveZone:
     *  yyTimezone: as above
     *  yyDSTmode: DSToff if a non-DST zone is specified, otherwise DSTon
     *	XXX don't understand interaction with yyHaveTime zone info
     *
     * yyHaveDay:
     *	yyDayNumber: 0-6 for Sunday-Saturday
     *  yyDayOrdinal: val specified with day ("second monday",
     *		      Ordinal=2), otherwise 1
     *
     * yyHaveDate:
     *	yyMonth, yyDay, yyYear: mm/dd/yy specified, initialized to
     *				today above
     *
     * yyHaveRel:
     *	yyRelSeconds: seconds specified with MINUTE_UNITs ("3 hours") or
     *		      SEC_UNITs ("30 seconds")
     *  yyRelMonth: months specified with MONTH_UNITs ("3 months", "1
     *		     year")
     *
     * The code following yyparse turns these values into a single
     * date stamp.
     */
    if (yyparse()
     || yyHaveTime > 1 || yyHaveZone > 1 || yyHaveDate > 1 || yyHaveDay > 1)
	return -1;

    /*
     * If an absolute time specified, set Start to the equivalent Unix
     * timestamp.  Otherwise, set Start to now, and if we do not have
     * a relatime time (ie: only yyHaveZone), decrement Start to the
     * beginning of today.
     *
     * By having yyHaveDay in the "absolute" list, "next Monday" means
     * midnight next Monday.  Otherwise, "next Monday" would mean the
     * time right now, next Monday.  It's not clear to me why the
     * current behavior is preferred.
     */
    if (yyHaveDate || yyHaveTime || yyHaveDay) {
	Start = Convert(yyMonth, yyDay, yyYear, yyHour, yyMinutes, yySeconds,
		    yyMeridian, yyDSTmode);
	if (Start < 0)
	    return -1;
    }
    else {
	Start = now->time;
	if (!yyHaveRel)
	    Start -= ((tm->tm_hour * 60L + tm->tm_min) * 60L) + tm->tm_sec;
    }

    /*
     * Add in the relative time specified.  RelativeMonth adds in the
     * months, accounting for the fact that the actual length of "3
     * months" depends on where you start counting.
     *
     * XXX By having this separate from the previous block, we are
     * allowing dates like "10:00am 3 months", which means 3 months
     * from 10:00am today, or even "1/1/99 two days" which means two
     * days after 1/1/99.
     *
     * XXX Shouldn't this only be done if yyHaveRel, just for
     * thoroughness?
     */
    Start += yyRelSeconds;
    delta = RelativeMonth(Start, yyRelMonth);
    if (delta == (time_t) -1)
      return -1;
    Start += delta;

    /*
     * Now, if you specified a day of week and counter, add it in.  By
     * disallowing Date but allowing Time, you can say "5pm next
     * monday".
     *
     * XXX The yyHaveDay && !yyHaveDate restriction should be enforced
     * above and be able to cause failure.
     */
    if (yyHaveDay && !yyHaveDate) {
	tod = RelativeDate(Start, yyDayOrdinal, yyDayNumber);
	Start += tod;
    }

    /* Have to do *something* with a legitimate -1 so it's distinguishable
     * from the error return value.  (Alternately could set errno on error.) */
    return Start == -1 ? 0 : Start;
}


#if	defined(TEST)

/* ARGSUSED */
main(ac, av)
    int		ac;
    char	*av[];
{
    char	buff[128];
    time_t	d;

    (void)printf("Enter date, or blank line to exit.\n\t> ");
    (void)fflush(stdout);
    while (gets(buff) && buff[0]) {
	d = get_date(buff, (struct my_timeb *)NULL);
	if (d == -1)
	    (void)printf("Bad format - couldn't convert.\n");
	else
	    (void)printf("%s", ctime(&d));
	(void)printf("\t> ");
	(void)fflush(stdout);
    }
    exit(0);
    /* NOTREACHED */
}
#endif	/* defined(TEST) */



/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 */

/* String table of messages for kadm5_create */

char *str_PARSE_NAME = "while parsing admin principal name.";

char *str_HISTORY_PARSE_NAME = "while parsing admin history principal name.";

char *str_ADMIN_PRINC_EXISTS = "Warning! Admin principal already exists.";

char *str_CHANGEPW_PRINC_EXISTS = "Warning! Changepw principal already exists.";

char *str_HISTORY_PRINC_EXISTS = "Warning! Admin history principal already exists.";

char *str_ADMIN_PRINC_WRONG_ATTRS =
    "Warning! Admin principal has incorrect attributes.\n"
    "\tDISALLOW_TGT should be set, and max_life should be three hours.\n"
    "\tThis program will leave them as-is, but beware!.";

char *str_CHANGEPW_PRINC_WRONG_ATTRS =
    "Warning! Changepw principal has incorrect attributes.\n"
    "\tDISALLOW_TGT and PW_CHANGE_SERVICE should both be set, and "
    "max_life should be five minutes.\n"
    "\tThis program will leave them as-is, but beware!.";

char *str_HISTORY_PRINC_WRONG_ATTRS =
    "Warning! Admin history principal has incorrect attributes.\n"
    "\tDISALLOW_ALL_TIX should be set.\n"
    "\tThis program will leave it as-is, but beware!.";

char *str_CREATED_PRINC_DB =
    "%s: Admin principal database created (or it already existed).\n"; /* whoami */

char *str_CREATED_POLICY_DB =
    "%s: Admin policy database created (or it already existed).\n"; /* whoami */

char *str_RANDOM_KEY =
    "while calling random key for %s.";  /* principal name */

char *str_ENCRYPT_KEY =
    "while calling encrypt key for %s."; /* principal name */

char *str_PUT_PRINC =
    "while storing %s in Kerberos database.";  /* principal name */

char *str_CREATING_POLICY_DB = "while creating/opening admin policy database.";

char *str_CLOSING_POLICY_DB = "while closing admin policy database.";

char *str_CREATING_PRINC_DB = "while creating/opening admin principal database.";

char *str_CLOSING_PRINC_DB = "while closing admin principal database.";

char *str_CREATING_PRINC_ENTRY =
    "while creating admin principal database entry for %s."; /* princ_name */

char *str_A_PRINC = "a principal";

char *str_UNPARSE_PRINC = "while unparsing principal.";

char *str_CREATED_PRINC = "%s: Created %s principal.\n"; /* whoami, princ_name */

char *str_INIT_KDB = "while initializing kdb.";

char *str_NO_KDB =
    "while initializing kdb.\nThe Kerberos KDC database needs to exist in /krb5.\n\
If you haven't run kdb5_create you need to do so before running this command.";


char *str_INIT_RANDOM_KEY = "while initializing random key generator.";

char *str_TOO_MANY_ADMIN_PRINC =
    "while fetching admin princ. Can only have one admin principal.";

char *str_TOO_MANY_CHANGEPW_PRINC =
    "while fetching changepw princ. Can only have one changepw principal.";

char *str_TOO_MANY_HIST_PRINC =
    "while fetching history princ. Can only have one history principal.";

char *str_WHILE_DESTROYING_ADMIN_SESSION = "while closing session with admin server and destroying tickets.";

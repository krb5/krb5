#ifdef SANDIA
/*
 * kadmin/server/adm_parse.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Sandia National Laboratories also makes no representations about the
 * suitability of the modifications, or additions to this software for
 * any purpose.  It is provided "as is" without express or implied warranty.
 *
 * Edit a KDC database.
 */
 
#include <syslog.h>
#include <stdio.h>

#if defined (unicos61) || (defined(mips) && defined(SYSTYPE_BSD43)) || defined(sysvimp)
#include <time.h>
#else
#include <sys/time.h>
#endif  /* unicos61 */
#if defined(aux20)
#include <time.h>
#endif  /* aux20 */

#include "k5-int.h"

void
kadmin_parse_and_set(input_string)
char *input_string;
{
    extern int classification;
    extern krb5_kvno KDB5_VERSION_NUM;
    extern krb5_deltat KDB5_MAX_TKT_LIFE;
    extern krb5_deltat KDB5_MAX_REN_LIFE;
    extern krb5_timestamp KDB5_EXP_DATE;
    extern krb5_flags NEW_ATTRIBUTES;

    int num_args;
    char parameter[40];
    char first_token[40];
    char second_token[40];
 
    int bypass = 0;

    struct tm exp_date;
    long todays_date;
    int year;
    int month;
    int mday;

    first_token[0] = second_token[0] = '\0';
    num_args = sscanf(input_string, "%s %s %s", parameter,
                        first_token, second_token);

    if (strcmp(parameter, "BYPASS") == 0) {
        bypass++;
        syslog(LOG_ERR,
	  "CAUTION: Classified and  Unclassified Principals will be allowed");
	return;
    }
 
    if (strcmp(parameter, "CLASSIFICATION") == 0) {
        if (strcmp(first_token, "CLASS") == 0) {
            classification = 1;
            if (bypass) classification = 0;
	}
	return;
    }

    if (strcmp(parameter, "VERSION_NUM") == 0) {
        if (num_args < 2) {
                KDB5_VERSION_NUM  = 1;
        } else {
                KDB5_VERSION_NUM = atoi(first_token);
        }
        return;
    }    

    if (strcmp(parameter, "MAX_TKT_LIFE") == 0) {
        if (num_args < 2) {
                KDB5_MAX_TKT_LIFE = KRB5_KDB_MAX_LIFE;
        } else {
            switch (second_token[0]) {
                case 's':
                        KDB5_MAX_TKT_LIFE = atoi(first_token);
                        break;
                case 'm':
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 60;
                        break;
                case 'h':
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 3600;
                        break;
                case 'd':
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 86400;
                        break;
                case 'w':
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 604800;
                        break;
                case 'M':               /* 30 days */
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 18144000;
                        break;
                case 'y':               /* 365 days */
                        KDB5_MAX_TKT_LIFE = atoi(first_token) * 220752000;
                        break;
                case 'e':               /* eternity */
                        KDB5_MAX_TKT_LIFE = 2145830400;
                        break;
                default:
                        break;
            }            
        }
        return;
    }    

    if (strcmp(parameter, "MAX_REN_LIFE") == 0) {
        if (num_args < 2) {
                KDB5_MAX_REN_LIFE = KRB5_KDB_MAX_RLIFE;
        } else {
            switch (second_token[0]) {
                case 's':
                        KDB5_MAX_REN_LIFE = atoi(first_token);
                        break;
                case 'm':
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 60;
                        break;
                case 'h':
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 3600;
                        break;
                case 'd':
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 86400;
                        break;
                case 'w':
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 604800;
                        break;
                case 'M':               /* 30 days */
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 18144000;
                        break;
                case 'y':               /* 365 days */
                        KDB5_MAX_REN_LIFE = atoi(first_token) * 220752000;
                        break;
                case 'e':               /* eternity */
                        KDB5_MAX_REN_LIFE = 2145830400;
                        break;
                default:
                        break;
            }
        }
        return;
    }    
 
 
    if (strcmp(parameter, "SET_EXP_DATE") == 0) {
        (void) time(&todays_date);
        switch (first_token[0]) {
              case 'e':               /* eternity */
                      KDB5_EXP_DATE = 2145830400;
                      year = 2037;
                      month = 12;
                      mday = 30;
                      sprintf(first_token, "%s", "eternity");
                      break;
              case 'y':               /* yesterday */
                      KDB5_EXP_DATE = todays_date - 86400;
                      year = 1970;
                      month = 01;
                      mday = 01;
                      sprintf(first_token, "%s", "yesterday");
                      break;
              case '0':
              case '1':
              case '2':
              case '3':
              case '9':
                sscanf(first_token, "%d/%d/%d", &year, &month, &mday);
                      year = (year > 1900) ? year - 1900 : year;
                      year = (year > 137) ? year - 100 : year;
                      year = (year > 137) ? 137 : year;
                      exp_date.tm_year =
                         ((year >= 00 && year < 38) ||
                          (year >= 70 && year <= 138)) ? year : 137;
                      exp_date.tm_mon =
                          (month >= 1 &&
                           month <= 12) ? month - 1 : 0;
                      exp_date.tm_mday =
                          (mday >= 1 &&
                           mday <= 31) ? mday : 1;
                      exp_date.tm_hour = 0;
                      exp_date.tm_min = 1;
                      exp_date.tm_sec = 0;
                      KDB5_EXP_DATE = convert_tm_to_sec(&exp_date);
                      break;
              default:
                      KDB5_EXP_DATE = KRB5_KDB_EXPIRATION;
                      sprintf(first_token, "%s", "Default KDB Expiration");
                      break;
        }
        if (year < 1900) year += 1900;
        if (year < 1938) year += 100;
        return;
    }
 
    if (strcmp(parameter, "SET_PWCHG") == 0) {
        if (num_args < 2) {
           NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_PWCHANGE;
        } else {
            if (first_token[0] == 'y' || first_token[0] == 'Y') {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_PWCHANGE;
            } else {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES & ~KRB5_KDB_REQUIRES_PWCHANGE;
                KDB5_VERSION_NUM  = 1;
            }
        }
        return;
    }    

    if (strcmp(parameter, "SET_PREAUTH") == 0) {
        if (num_args < 2) {
           NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_PRE_AUTH;
        } else {
            if (first_token[0] == 'y' || first_token[0] == 'Y') {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_PRE_AUTH;
            } else {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES & ~KRB5_KDB_REQUIRES_PRE_AUTH;
            }
        }
        return;
    }    

    if (strcmp(parameter, "SET_SECUREID") == 0) {
        if (num_args < 2) {
           NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_HW_AUTH |
                KRB5_KDB_REQUIRES_PRE_AUTH;
        } else {
            if (first_token[0] == 'y' || first_token[0] == 'Y') {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES | KRB5_KDB_REQUIRES_HW_AUTH |
                        KRB5_KDB_REQUIRES_PRE_AUTH;
            } else {
                NEW_ATTRIBUTES = NEW_ATTRIBUTES & ~KRB5_KDB_REQUIRES_HW_AUTH;
            }
        }
        return;
    }
}
#else
/* Need something to compile. */
#include <stdio.h>
#endif

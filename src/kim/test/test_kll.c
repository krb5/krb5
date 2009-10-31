#include <Kerberos/Kerberos.h>
#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>

/* Prototypes */
void Initialize(void);
void TestErrorHandling (void);
void TestHighLevelAPI (void);
void TestKLPrincipal (void);
void TestKerberosRealms (void);
void TestLoginOptions (void);
char* TimeToString (char* timeString, long t);
void TestApplicationOptions (void);
void MyKerberosLoginIdleCallback (
                                  KLRefCon 			inAppData);

int main(void)
{
    KLTime t;
    KLStatus err;
    KLPrincipal principal;

    /* force use of UI */
    fclose (stdin);

    err = KLCreatePrincipalFromTriplet ("nobody", "", "TEST-KERBEROS-1.3.1", &principal);
    printf ("KLCreatePrincipalFromTriplet(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLChangePassword (principal);
        printf ("KLChangePassword() (err = %d)\n", err);
        KLDisposePrincipal (principal);
    }

    err = KLLastChangedTime(&t);
    printf ("KLLastChangedTime returned %d (err = %d)\n", t, err);

    TestKLPrincipal ();
    TestLoginOptions ();
    TestApplicationOptions ();
    TestErrorHandling ();
    TestKerberosRealms ();
    TestHighLevelAPI ();

    err = KLLastChangedTime(&t);
    printf ("KLLastChangedTime returned %d (err = %d)\n", t, err);

    return 0;
}

void TestErrorHandling (void)
{
    long err;
    char*	errorString;

    err = KLGetErrorString (KRB5KRB_AP_ERR_BAD_INTEGRITY, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klCredentialsBadAddressErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klCacheDoesNotExistErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klPasswordMismatchErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klInsecurePasswordErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klPasswordChangeFailedErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klCantContactServerErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }

    err = KLGetErrorString (klCantDisplayUIErr, &errorString);
    printf ("KLGetErrorString() returned %s (err = %ld)\n", errorString, err);
    if (!err) { KLDisposeString (errorString); }
}

void TestHighLevelAPI (void)
{
    KLStatus err;
    KLPrincipal	inPrincipal, outPrincipal, outPrincipal2;
    char *outCredCacheName, *outCredCacheName2;
    KLTime	expirationTime;
    char*	principalString;
    char	timeString[256];
    KLBoolean	valid;

    err = KLCreatePrincipalFromTriplet ("grail", "", "TESTV5-KERBEROS-1.3.1", &inPrincipal);
    printf ("KLCreatePrincipalFromTriplet(grail@TESTV5-KERBEROS-1.3.1) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLAcquireNewInitialTicketsWithPassword (inPrincipal, NULL, "liarg", &outCredCacheName);
        if (err != klNoErr) {
            printf ("KLAcquireNewInitialTicketsWithPassword() returned err = %d\n", err);
        } else {
            printf ("KLAcquireNewInitialTicketsWithPassword() returned '%s'\n", outCredCacheName);
            KLDisposeString (outCredCacheName);
        }
        KLDisposePrincipal (inPrincipal);
    }

    err = KLCreatePrincipalFromTriplet ("nobody", "", "TEST-KERBEROS-1.3.1", &inPrincipal);
    printf ("KLCreatePrincipalFromTriplet(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLAcquireNewInitialTicketsWithPassword (inPrincipal, NULL, "ydobon", &outCredCacheName);
        if (err != klNoErr) {
            printf ("KLAcquireNewInitialTicketsWithPassword() returned err = %d\n", err);
        } else {
            printf ("KLAcquireNewInitialTicketsWithPassword() returned '%s'\n", outCredCacheName);
            KLDisposeString (outCredCacheName);
        }
        KLDisposePrincipal (inPrincipal);
    }

    err = KLAcquireNewInitialTickets (NULL, NULL, &inPrincipal, &outCredCacheName);
    printf ("KLAcquireNewInitialTickets() (err = %d)\n", err);
    if (err == klNoErr) {
        KLDisposeString (outCredCacheName);
        err = KLAcquireInitialTickets (inPrincipal, NULL, &outPrincipal, &outCredCacheName);
        printf ("KLAcquireInitialTickets() (err = %d)\n", err);
        if (err == klNoErr) {
            KLDisposeString (outCredCacheName);
            KLDisposePrincipal (outPrincipal);
        }
        KLDisposePrincipal (inPrincipal);
    }

    err = KLSetDefaultLoginOption (loginOption_LoginName, "testname", 3);
    printf ("KLSetDefaultLoginOption(loginOption_LoginName) to testname (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLSetDefaultLoginOption (loginOption_LoginInstance, "testinstance", 6);
        printf ("KLSetDefaultLoginOption(loginOption_LoginInstance) to testinstance (err = %d)\n", err);
    }

    err = KLAcquireNewInitialTickets (NULL, NULL, &inPrincipal, &outCredCacheName);
    printf ("KLAcquireNewInitialTickets() (err = %d)\n", err);
    if (err == klNoErr) {
        KLDisposeString (outCredCacheName);
        KLDisposePrincipal (inPrincipal);
    }

    // Principal == NULL
    while (KLAcquireNewInitialTickets (NULL, NULL, &outPrincipal, &outCredCacheName) == klNoErr) {
        err = KLTicketExpirationTime (outPrincipal, kerberosVersion_All, &expirationTime);
        err = KLCacheHasValidTickets (outPrincipal, kerberosVersion_All, &valid, &outPrincipal2, &outCredCacheName2);
        if (err == klNoErr) {
            err = KLGetStringFromPrincipal (outPrincipal2, kerberosVersion_V4, &principalString);
            if (err == klNoErr) {
                printf ("KLGetStringFromPrincipal returned string '%s'\n", principalString);
                KLDisposeString (principalString);
            }
            KLDisposePrincipal (outPrincipal2);
            KLDisposeString (outCredCacheName2);
            err = KLCacheHasValidTickets (outPrincipal, kerberosVersion_All, &valid, NULL, NULL);
            if (err != klNoErr) {
                printf ("KLCacheHasValidTickets returned error = %d\n", err);
            }
        }
        err = KLCacheHasValidTickets (outPrincipal, kerberosVersion_All, &valid, NULL, NULL);
        KLDisposeString (outCredCacheName);
        KLDisposePrincipal (outPrincipal);
    }

    err = KLAcquireNewInitialTickets (NULL, NULL, &outPrincipal, &outCredCacheName);
    if (err == klNoErr) {
        KLDisposeString (outCredCacheName);
        KLDisposePrincipal (outPrincipal);
    }


    err = KLCreatePrincipalFromTriplet ("nobody", "", "TEST-KERBEROS-1.3.1", &inPrincipal);
    printf ("KLCreatePrincipalFromTriplet(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLAcquireNewInitialTickets (inPrincipal, NULL, &outPrincipal, &outCredCacheName);
        printf ("KLAcquireNewInitialTickets(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
        if (err == klNoErr) {
            KLDisposeString (outCredCacheName);
            KLDisposePrincipal (outPrincipal);
        }
        err = KLDestroyTickets (inPrincipal);

        KLDisposePrincipal (inPrincipal);
    }

    err = KLCreatePrincipalFromTriplet ("nobody", "", "TEST-KERBEROS-1.3.1", &inPrincipal);
    printf ("KLCreatePrincipalFromTriplet(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLAcquireInitialTickets (inPrincipal, NULL, &outPrincipal, &outCredCacheName);
        printf ("KLAcquireInitialTickets(nobody@TEST-KERBEROS-1.3.1) (err = %d)\n", err);
        if (err == klNoErr) {
            KLDisposeString (outCredCacheName);
            KLDisposePrincipal (outPrincipal);
        }

        err = KLAcquireNewInitialTickets (inPrincipal, NULL, &outPrincipal, &outCredCacheName);
        if (err == klNoErr) {
            err = KLGetStringFromPrincipal (outPrincipal, kerberosVersion_V5, &principalString);
            if (err == klNoErr) {
                err = KLTicketExpirationTime (outPrincipal, kerberosVersion_All, &expirationTime);
                printf ("Tickets for principal '%s' expire on %s\n",
                        principalString, TimeToString(timeString, expirationTime));

                KLDisposeString (principalString);
            }
            KLDisposeString (outCredCacheName);
            KLDisposePrincipal (outPrincipal);
        }

        err = KLChangePassword (inPrincipal);
        printf ("KLChangePassword() (err = %d)\n", err);

        err = KLDestroyTickets (inPrincipal);
        printf ("KLDestroyTickets() (err = %d)\n", err);

        KLDisposePrincipal (inPrincipal);
    }

}


void TestKLPrincipal (void)
{
    KLStatus err = klNoErr;
    KLPrincipal extraLongPrincipal = NULL;
    KLPrincipal	principal = NULL;
    KLPrincipal adminPrincipal = NULL;
    KLPrincipal adminPrincipalV4 = NULL;
    KLPrincipal adminPrincipalV5 = NULL;
    char *principalString = NULL;
    char *user = NULL;
    char *instance = NULL;
    char *realm = NULL;

    printf ("Entering TestKLPrincipal()\n");
    printf ("----------------------------------------------------------------\n");

    err = KLCreatePrincipalFromString ("thisprincipalnameislongerthanissupportedbyKerberos4@TEST-KERBEROS-1.3.1",
                                       kerberosVersion_V5, &extraLongPrincipal);
    printf ("KLCreatePrincipalFromString "
            "('thisprincipalnameislongerthanissupportedbyKerberos4@TEST-KERBEROS-1.3.1') "
            "(err = %s)\n", error_message(err));

    printf ("----------------------------------------------------------------\n");

    err = KLCreatePrincipalFromTriplet ("nobody", "", "TEST-KERBEROS-1.3.1", &principal);
    printf ("KLCreatePrincipalFromTriplet ('nobody' '' 'TEST-KERBEROS-1.3.1') (err = %s)\n",
            error_message(err));

    if (err == klNoErr) {
        err = KLGetStringFromPrincipal (principal, kerberosVersion_V5, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody@TEST-KERBEROS-1.3.1, v5) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody@TEST-KERBEROS-1.3.1, v5) returned (err = %s)\n", error_message(err));
        }

        err = KLGetStringFromPrincipal (principal, kerberosVersion_V4, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody@TEST-KERBEROS-1.3.1, v4) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody@TEST-KERBEROS-1.3.1, v4) returned (err = %s)\n", error_message(err));
        }

        err = KLGetTripletFromPrincipal (principal, &user, &instance, &realm);
        if (err == klNoErr) {
            printf ("KLGetTripletFromPrincipal (nobody@TEST-KERBEROS-1.3.1) returned triplet %s' '%s' '%s'\n",
                    user, instance, realm);
            KLDisposeString (user);
            KLDisposeString (instance);
            KLDisposeString (realm);
        } else {
            printf ("KLGetTripletFromPrincipal(nobody@TEST-KERBEROS-1.3.1) returned (err = %s)\n", error_message(err));
        }
    }

    printf ("----------------------------------------------------------------\n");

    err = KLCreatePrincipalFromTriplet ("nobody", "admin", "TEST-KERBEROS-1.3.1", &adminPrincipal);
    printf ("KLCreatePrincipalFromTriplet ('nobody' 'admin' 'TEST-KERBEROS-1.3.1') (err = %d)\n", err);

    if (err == klNoErr) {
        err = KLGetStringFromPrincipal (adminPrincipal, kerberosVersion_V5, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody/admin@TEST-KERBEROS-1.3.1, v5) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody/admin@TEST-KERBEROS-1.3.1, v5) returned (err = %d)\n", err);
        }

        err = KLGetStringFromPrincipal (adminPrincipal, kerberosVersion_V4, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody/admin@TEST-KERBEROS-1.3.1, v4) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody/admin@TEST-KERBEROS-1.3.1, v4) returned (err = %d)\n", err);
        }

        err = KLGetTripletFromPrincipal (adminPrincipal, &user, &instance, &realm);
        if (err == klNoErr) {
            printf ("KLGetTripletFromPrincipal (nobody/admin@TEST-KERBEROS-1.3.1) returned triplet %s' '%s' '%s'\n",
                    user, instance, realm);
            KLDisposeString (user);
            KLDisposeString (instance);
            KLDisposeString (realm);
        } else {
            printf ("KLGetTripletFromPrincipal(lxs/admin@TEST-KERBEROS-1.3.1) returned (err = %d)\n", err);
        }
    }

    printf ("----------------------------------------------------------------\n");

    err = KLCreatePrincipalFromString ("nobody/root@TEST-KERBEROS-1.3.1", kerberosVersion_V5, &adminPrincipalV5);
    printf ("KLCreatePrincipalFromString ('nobody/root@TEST-KERBEROS-1.3.1', v5) (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLGetStringFromPrincipal (adminPrincipalV5, kerberosVersion_V5, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody/root@TEST-KERBEROS-1.3.1, v5) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody/root@TEST-KERBEROS-1.3.1, v5) returned (err = %d)\n", err);
        }

        err = KLGetStringFromPrincipal (adminPrincipalV5, kerberosVersion_V4, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody/admin@TEST-KERBEROS-1.3.1, v4) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody/admin@TEST-KERBEROS-1.3.1, v4) returned (err = %d)\n", err);
        }

        err = KLGetTripletFromPrincipal (adminPrincipalV5, &user, &instance, &realm);
        if (err == klNoErr) {
            printf ("KLGetTripletFromPrincipal (nobody/admin@TEST-KERBEROS-1.3.1) returned triplet %s' '%s' '%s'\n",
                    user, instance, realm);
            KLDisposeString (user);
            KLDisposeString (instance);
            KLDisposeString (realm);
        } else {
            printf ("KLGetTripletFromPrincipal(nobody/admin@TEST-KERBEROS-1.3.1) returned (err = %d)\n", err);
        }
    }

    printf ("----------------------------------------------------------------\n");

    err = KLCreatePrincipalFromString ("nobody.admin@TEST-KERBEROS-1.3.1", kerberosVersion_V4, &adminPrincipalV4);
    printf ("KLCreatePrincipalFromString ('nobody.admin@TEST-KERBEROS-1.3.1') (err = %d)\n", err);
    if (err == klNoErr) {
        err = KLGetStringFromPrincipal (adminPrincipalV4, kerberosVersion_V5, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody.admin@TEST-KERBEROS-1.3.1, v5) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody.admin@TEST-KERBEROS-1.3.1, v5) returned (err = %d)\n", err);
        }

        err = KLGetStringFromPrincipal (adminPrincipalV4, kerberosVersion_V4, &principalString);
        if (err == klNoErr) {
            printf ("KLGetStringFromPrincipal (nobody.admin@TEST-KERBEROS-1.3.1, v4) returned string '%s'\n", principalString);
            KLDisposeString (principalString);
        } else {
            printf ("KLGetStringFromPrincipal(nobody.admin@TEST-KERBEROS-1.3.1, v4) returned (err = %d)\n", err);
        }

        err = KLGetTripletFromPrincipal (adminPrincipalV4, &user, &instance, &realm);
        if (err == klNoErr) {
            printf ("KLGetTripletFromPrincipal (nobody.admin@TEST-KERBEROS-1.3.1) returned triplet %s' '%s' '%s'\n",
                    user, instance, realm);
            KLDisposeString (user);
            KLDisposeString (instance);
            KLDisposeString (realm);
        } else {
            printf ("KLGetTripletFromPrincipal(nobody.admin@TEST-KERBEROS-1.3.1) returned (err = %d)\n", err);
        }
    }

    printf ("----------------------------------------------------------------\n");

    if (adminPrincipalV4 != NULL && adminPrincipalV5 != NULL) {
        KLBoolean equivalent;

        err = KLComparePrincipal (adminPrincipalV5, adminPrincipalV4, &equivalent);
        if (err == klNoErr) {
            printf ("KLComparePrincipal %s comparing nobody/admin@TEST-KERBEROS-1.3.1 and nobody.admin@TEST-KERBEROS-1.3.1\n",
                    equivalent ? "passed" : "FAILED");
        } else {
            printf ("KLComparePrincipal returned (err = %d)\n", err);
        }
    }

    if (principal != NULL && adminPrincipalV5 != NULL) {
        KLBoolean equivalent;

        err = KLComparePrincipal (principal, adminPrincipalV4, &equivalent);
        if (err == klNoErr) {
            printf ("KLComparePrincipal %s comparing nobody@TEST-KERBEROS-1.3.1 and nobody.admin@TEST-KERBEROS-1.3.1\n",
                    equivalent ? "FAILED" : "passed");
        } else {
            printf ("KLComparePrincipal returned (err = %d)\n", err);
        }
    }

    if (principal != NULL && adminPrincipalV5 != NULL) {
        KLBoolean equivalent;

        err = KLComparePrincipal (principal, adminPrincipalV5, &equivalent);
        if (err == klNoErr) {
            printf ("KLComparePrincipal %s comparing nobody@TEST-KERBEROS-1.3.1 and nobody/admin@TEST-KERBEROS-1.3.1\n",
                    equivalent ? "FAILED" : "passed");
        } else {
            printf ("KLComparePrincipal returned (err = %d)\n", err);
        }
    }

    if (adminPrincipal != NULL && adminPrincipalV5 != NULL) {
        KLBoolean equivalent;

        err = KLComparePrincipal (adminPrincipalV5, principal, &equivalent);
        if (err == klNoErr) {
            printf ("KLComparePrincipal %s comparing nobody/admin@TEST-KERBEROS-1.3.1 and nobody@TEST-KERBEROS-1.3.1\n",
                    equivalent ? "FAILED" : "passed");
        } else {
            printf ("KLComparePrincipal returned (err = %d)\n", err);
        }
    }

    printf ("----------------------------------------------------------------\n\n");

    if (extraLongPrincipal != NULL) KLDisposePrincipal (extraLongPrincipal);
    if (adminPrincipalV5   != NULL) KLDisposePrincipal (adminPrincipalV5);
    if (adminPrincipalV4   != NULL) KLDisposePrincipal (adminPrincipalV4);
    if (adminPrincipal     != NULL) KLDisposePrincipal (adminPrincipal);
    if (principal          != NULL) KLDisposePrincipal (principal);
}


void TestApplicationOptions (void)
{
    KLSetIdleCallback (MyKerberosLoginIdleCallback, 101);
}

void TestKerberosRealms (void)
{
    printf ("About to test Kerberos realms\n");
    KLRemoveAllKerberosRealms ();
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLInsertKerberosRealm (realmList_End, "FOO");
    KLInsertKerberosRealm (realmList_End, "BAR");
    KLInsertKerberosRealm (realmList_End, "BAZ");
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLInsertKerberosRealm (realmList_End, "FOO");
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLSetKerberosRealm (0, "QUUX");
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLRemoveKerberosRealm (0);
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLSetKerberosRealm (2, "TEST-KERBEROS-1.3.1");
    KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);

    KLRemoveAllKerberosRealms ();
    KLInsertKerberosRealm (realmList_End, "TEST-KERBEROS-1.3.1");
    KLInsertKerberosRealm (realmList_End, "TEST-KERBEROS-1.0.6");
    KLInsertKerberosRealm (realmList_End, "TESTV5-KERBEROS-1.0.6");
    KLInsertKerberosRealm (realmList_End, "TEST-KERBEROS-1.1.1");
    KLInsertKerberosRealm (realmList_End, "TESTV5-KERBEROS-1.1.1");
    KLInsertKerberosRealm (realmList_End, "TEST-KERBEROS-1.2.0");
    KLInsertKerberosRealm (realmList_End, "TESTV5-KERBEROS-1.2.0");
    KLInsertKerberosRealm (realmList_End, "TEST-HEIMDAL-0.3D");
    KLInsertKerberosRealm (realmList_End, "TESTV5-HEIMDAL-0.3D");
    KLInsertKerberosRealm (realmList_End, "TEST-KTH-KRB-1.1");
}


void TestLoginOptions (void)
{
    KLBoolean optionSetting;
    KLStatus err = klNoErr;
    KLLifetime lifetime;

    lifetime = 10*60;
    KLSetDefaultLoginOption(loginOption_MinimalTicketLifetime, &lifetime, sizeof(KLLifetime));

    lifetime = 8*60*60;
    KLSetDefaultLoginOption(loginOption_MaximalTicketLifetime, &lifetime, sizeof(KLLifetime));

    lifetime = 8*60*60;
    KLSetDefaultLoginOption(loginOption_DefaultTicketLifetime, &lifetime, sizeof(KLLifetime));

    optionSetting = FALSE;
    KLSetDefaultLoginOption(loginOption_DefaultForwardableTicket, &optionSetting, sizeof(optionSetting));

    optionSetting = TRUE;
    KLSetDefaultLoginOption(loginOption_RememberPrincipal, &optionSetting, sizeof(optionSetting));

    optionSetting = TRUE;
    err = KLSetDefaultLoginOption(loginOption_RememberExtras, &optionSetting, sizeof(optionSetting));

    if (err == klNoErr) {
        KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);
        optionSetting = TRUE;
        KLAcquireNewInitialTickets (NULL, NULL, NULL, NULL);
    }
}


/* Lame date formatting stolen from CCacheDump, like ctime but with no \n */

static const char *day_name[] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};

static const char *month_name[] = {"January", "February", "March","April","May","June",
"July", "August",  "September", "October", "November","December"};

char* TimeToString (char* timeString, long t)
{
    /* we come in in 1970 time */
    time_t timer = (time_t) t;
    struct tm tm;

    tm = *localtime (&timer);

    sprintf(timeString, "%.3s %.3s%3d %.2d:%.2d:%.2d %d",
            day_name[tm.tm_wday],
            month_name[tm.tm_mon],
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            tm.tm_year + 1900);

    return timeString;
}


void MyKerberosLoginIdleCallback (KLRefCon inAppData)
{
    syslog (LOG_ALERT, "App got callback while waiting for Mach IPC (appData == %d)\n", inAppData);
    //    KLCancelAllDialogs ();
}

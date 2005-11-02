/*
* Copyright (c) 2004 Massachusetts Institute of Technology
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the "Software"), to deal in the Software without
* restriction, including without limitation the rights to use, copy,
* modify, merge, publish, distribute, sublicense, and/or sell copies
* of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
* BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
* ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

/* $Id$ */

/* Originally this was krb5routines.c in Leash sources.  Subsequently
modified and adapted for NetIDMgr */

#include<krbcred.h>
#include<kherror.h>

#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>

#include <string.h>
#include <time.h>
#include <assert.h>
#include <strsafe.h>



int com_addr(void)
{
    long ipAddr;
    char loc_addr[ADDR_SZ];
    CREDENTIALS cred;    
    char service[40];
    char instance[40];
    //    char addr[40];
    char realm[40];
    struct in_addr LocAddr;
    int k_errno;

    if (pkrb_get_cred == NULL)
        return(KSUCCESS);

    k_errno = (*pkrb_get_cred)(service,instance,realm,&cred);
    if (k_errno)
        return KRBERR(k_errno);

    while(1) {
        ipAddr = (*pLocalHostAddr)();
        LocAddr.s_addr = ipAddr;
        StringCbCopyA(loc_addr, sizeof(loc_addr), inet_ntoa(LocAddr));
        if ( strcmp(cred.address,loc_addr) != 0) {
            /* TODO: do something about this */
            //Leash_kdestroy ();
            break;
        }
        break;
    } // while()
    return 0;
} 


long 
khm_krb4_list_tickets(void) 
{
    char    pname[ANAME_SZ];
    char    pinst[INST_SZ];
    char    prealm[REALM_SZ];
    wchar_t wbuf[256];
    int     k_errno;
    CREDENTIALS c;
    int newtickets = 0;
    int open = 0;
    khm_handle ident = NULL;
    khm_handle cred = NULL;
    time_t tt;
    FILETIME ft;

    // Since krb_get_tf_realm will return a ticket_file error,
    // we will call tf_init and tf_close first to filter out
    // things like no ticket file.  Otherwise, the error that
    // the user would see would be
    // klist: can't find realm of ticket file: No ticket file (tf_util)
    // instead of klist: No ticket file (tf_util)
    if (ptf_init == NULL)
        return(KSUCCESS);

    com_addr();
    
    // Open ticket file
    if ((k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL)))
    {
        goto cleanup;
    }
    // Close ticket file 
    (void) (*ptf_close)();
    
    // We must find the realm of the ticket file here before calling
    // tf_init because since the realm of the ticket file is not
    // really stored in the principal section of the file, the
    // routine we use must itself call tf_init and tf_close.

    if ((k_errno = (*pkrb_get_tf_realm)((*ptkt_string)(), prealm)) != KSUCCESS)
    {
        goto cleanup;
    }
	
    // Open ticket file 
    if (k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL)) 
    {
        goto cleanup;
    }

    open = 1;

    // Get principal name and instance 
    if ((k_errno = (*ptf_get_pname)(pname)) || (k_errno = (*ptf_get_pinst)(pinst))) 
    {
        goto cleanup;
    }
	
    // You may think that this is the obvious place to get the
    // realm of the ticket file, but it can't be done here as the
    // routine to do this must open the ticket file.  This is why
    // it was done before tf_init.
    StringCbPrintf(wbuf, sizeof(wbuf), L"%S%S%S%S%S", (LPSTR)pname,
             (LPSTR)(pinst[0] ? "." : ""), (LPSTR)pinst,
             (LPSTR)(prealm[0] ? "@" : ""), (LPSTR)prealm);

    if(KHM_FAILED(kcdb_identity_create(wbuf, KCDB_IDENT_FLAG_CREATE, &ident)))
    {
        goto cleanup;
    }

    kcdb_credset_flush(krb4_credset);

    // Get KRB4 tickets
    while ((k_errno = (*ptf_get_cred)(&c)) == KSUCCESS)
    {
        StringCbPrintf(wbuf, sizeof(wbuf), L"%S%S%S%S%S",
            c.service,
            (c.instance[0] ? "." : ""),
            c.instance,
            (c.realm[0] ? "@" : ""),
            c.realm);

        if(KHM_FAILED(kcdb_cred_create(wbuf, ident, credtype_id_krb4, &cred)))
            continue;

        tt = c.issue_date + c.lifetime * 5L * 60L;
        TimetToFileTime(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_EXPIRE, &ft, sizeof(ft));

        tt = c.issue_date;
        TimetToFileTime(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_ISSUE, &ft, sizeof(ft));

        tt = c.lifetime * 5L * 60L;
        TimetToFileTimeInterval(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_LIFETIME, &ft, sizeof(ft));

        kcdb_credset_add_cred(krb4_credset, cred, -1);

    } // while

    kcdb_credset_collect(NULL, krb4_credset, ident, credtype_id_krb4, NULL);

cleanup:
    if (ptf_close == NULL)
        return(KSUCCESS);

    if (open)
        (*ptf_close)(); //close ticket file 
    
    if (k_errno == EOF)
        k_errno = 0;

    // XXX the if statement directly below was inserted to eliminate
    // an error NO_TKT_FIL on Leash startup. The error occurs from an
    // error number thrown from krb_get_tf_realm.  We believe this
    // change does not eliminate other errors, but it may.

    if (k_errno == NO_TKT_FIL)
        k_errno = 0;

    if(ident)
        kcdb_identity_release(ident);

#if 0
    /*TODO: Handle errors here */
    if (k_errno)
    {
        CHAR message[256];
        CHAR errBuf[256];
        LPCSTR errText; 

        if (!Lerror_message)
            return -1;

        errText = err_describe(errBuf, KRBERR(k_errno));

        sprintf(message, "%s\n\n%s failed", errText, functionName);
        MessageBox(NULL, message, "Kerberos Four", 
                   MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_SETFOREGROUND);
    }
#endif
    return k_errno;
}

#define KRB_FILE                "KRB.CON"
#define KRBREALM_FILE           "KRBREALM.CON"
#define KRB5_FILE               "KRB5.INI"

BOOL 
khm_get_profile_file(LPSTR confname, UINT szConfname)
{
    char **configFile = NULL;
    if (pkrb5_get_default_config_files(&configFile)) 
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';
		strncat(confname, "\\",sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
		strncat(confname, KRB5_FILE,sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
        return FALSE;
    }
    
    *confname = 0;
    
    if (configFile)
    {
        strncpy(confname, *configFile, szConfname);
        pkrb5_free_config_files(configFile); 
    }
    
    if (!*confname)
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';
		strncat(confname, "\\",sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
		strncat(confname, KRB5_FILE,sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
    }
    
    return FALSE;
}

BOOL
khm_get_krb4_con_file(LPSTR confname, UINT szConfname)
{
    if (hKrb5 && !hKrb4)
	{ // hold krb.con where krb5.ini is located
            CHAR krbConFile[MAX_PATH]="";
            LPSTR pFind;

	    //strcpy(krbConFile, CLeashApp::m_krbv5_profile->first_file->filename);
            if (khm_get_profile_file(krbConFile, sizeof(krbConFile)))	
                {
		    GetWindowsDirectoryA(krbConFile,sizeof(krbConFile));
                    krbConFile[MAX_PATH-1] = '\0';
                    strncat(krbConFile, "\\",sizeof(krbConFile)-strlen(krbConFile));
                    krbConFile[MAX_PATH-1] = '\0';
                    strncat(krbConFile, KRB5_FILE,sizeof(krbConFile)-strlen(krbConFile));
                    krbConFile[MAX_PATH-1] = '\0';
                }

            pFind = strrchr(krbConFile, '\\');
            if (pFind)
		{
                    *pFind = 0;
                    strncat(krbConFile, "\\",sizeof(krbConFile)-strlen(krbConFile));
                    krbConFile[MAX_PATH-1] = '\0';
                    strncat(krbConFile, KRB_FILE,sizeof(krbConFile)-strlen(krbConFile));
                    krbConFile[MAX_PATH-1] = '\0';
		}
            else
                krbConFile[0] = 0;
            
            strncpy(confname, krbConFile, szConfname);
            confname[szConfname-1] = '\0';
	}
    else if (hKrb4)
	{ 
            unsigned int size = szConfname;
            memset(confname, '\0', szConfname);
            if (!pkrb_get_krbconf2(confname, &size))
		{ // Error has happened
		    GetWindowsDirectoryA(confname,szConfname);
                    confname[szConfname-1] = '\0';
                    strncat(confname, "\\",szConfname-strlen(confname));
                    confname[szConfname-1] = '\0';
                    strncat(confname,KRB_FILE,szConfname-strlen(confname));
                    confname[szConfname-1] = '\0';
		}
	}
    return FALSE;
}

int
readstring(FILE * file, char * buf, int len)
{
	int  c,i;
	memset(buf, '\0', sizeof(buf));
	for (i=0, c=fgetc(file); c != EOF ; c=fgetc(file), i++)
	{	
		if (i < sizeof(buf)) {
			if (c == '\n') {
				buf[i] = '\0';
				return i;
			} else {
				buf[i] = c;
			}
		} else {
			if (c == '\n') {
				buf[len-1] = '\0';
				return(i);
			}
		}
	}
	if (c == EOF) {
		if (i > 0 && i < len) {
			buf[i] = '\0';
			return(i);
		} else {
			buf[len-1] = '\0';
			return(-1);
		}
	}
    return(-1);
}

/*! \internal
    \brief Return a list of configured realms

    The string that is returned is a set of null terminated unicode strings, 
    each of which denotes one realm.  The set is terminated by a zero length
    null terminated string.

    The caller should free the returned string using free()

    \return The string with the list of realms or NULL if the operation fails.
*/
wchar_t * khm_krb5_get_realm_list(void) 
{
    wchar_t * rlist = NULL;

    if (pprofile_get_subsection_names && pprofile_free_list) {
        const char*  rootSection[] = {"realms", NULL};
        const char** rootsec = rootSection;
        char **sections = NULL, **cpp = NULL, *value = NULL;

        char krb5_conf[MAX_PATH+1];

        if (!khm_get_profile_file(krb5_conf,sizeof(krb5_conf))) {
            profile_t profile;
            long retval;
            const char *filenames[2];
            wchar_t * d;
            size_t cbsize;
            size_t t;

            filenames[0] = krb5_conf;
            filenames[1] = NULL;
            retval = pprofile_init(filenames, &profile);
            if (!retval) {
                retval = pprofile_get_subsection_names(profile,	rootsec, &sections);

                if (!retval)
                {
                    /* first figure out how much space to allocate */
                    cbsize = 0;
                    for (cpp = sections; *cpp; cpp++) 
                    {
                        cbsize += sizeof(wchar_t) * (strlen(*cpp) + 1);
                    }
                    cbsize += sizeof(wchar_t); /* double null terminated */

                    rlist = malloc(cbsize);
                    d = rlist;
                    for (cpp = sections; *cpp; cpp++)
                    {
                        AnsiStrToUnicode(d, cbsize, *cpp);
                        t = wcslen(d) + 1;
                        d += t;
                        cbsize -= sizeof(wchar_t) * t;
                    }
                    *d = L'\0';
                }

                pprofile_free_list(sections);

#if 0
                retval = pprofile_get_string(profile, "libdefaults","noaddresses", 0, "true", &value);
                if ( value ) {
                    disable_noaddresses = config_boolean_to_int(value);
                    pprofile_release_string(value);
                }
#endif
                pprofile_release(profile);
            }
        }
    } else {
        FILE * file;
        char krb_conf[MAX_PATH+1];
        char * p;
        size_t cbsize, t;
        wchar_t * d;

        if (!khm_get_krb4_con_file(krb_conf,sizeof(krb_conf)) && 
            (file = fopen(krb_conf, "rt")))
        {
            char lineBuf[256];

            /*TODO: compute the actual required buffer size instead of hardcoding */
            cbsize = 16384; // arbitrary
            rlist = malloc(cbsize);
            d = rlist;

            // Skip the default realm
            readstring(file,lineBuf,sizeof(lineBuf));

            // Read the defined realms
            while (TRUE)
            {
                if (readstring(file,lineBuf,sizeof(lineBuf)) < 0)
                    break;

                if (*(lineBuf + strlen(lineBuf) - 1) == '\r')
                    *(lineBuf + strlen(lineBuf) - 1) = 0;

                for (p=lineBuf; *p ; p++)
                {
                    if (isspace(*p)) {
                        *p = 0;
                        break;
                    }
                }

                if ( strncmp(".KERBEROS.OPTION.",lineBuf,17) ) {
                    t = strlen(lineBuf) + 1;
                    if(cbsize > (1 + t*sizeof(wchar_t))) {
                        AnsiStrToUnicode(d, cbsize, lineBuf);
                        d += t;
                        cbsize -= t * sizeof(wchar_t);
                    } else
                        break;
                }
            }

            *d = L'\0';

            fclose(file);
        }
    }

    return rlist;
}

/*! \internal
    \brief Get the default realm

    A string will be returned that specifies the default realm.  The caller
    should free the string using free().

    Returns NULL if the operation fails.
*/
wchar_t * khm_krb5_get_default_realm(void)
{
    wchar_t * realm;
    size_t cch;
    krb5_context ctx=0;
    char * def = 0;

    pkrb5_init_context(&ctx);
    pkrb5_get_default_realm(ctx,&def);
    
    if (def) {
        cch = strlen(def) + 1;
        realm = malloc(sizeof(wchar_t) * cch);
        AnsiStrToUnicode(realm, sizeof(wchar_t) * cch, def);
        pkrb5_free_default_realm(ctx, def);
    } else
        realm = NULL;

    pkrb5_free_context(ctx);

    return realm;
}

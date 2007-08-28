/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
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

#include<krbcred.h>
#include<krb5.h>
#include<assert.h>
#include<lm.h>
#include<commctrl.h>
#include<shlwapi.h>

#include<strsafe.h>

#pragma warning(disable: 4204 4221)

typedef struct tag_k5_realm_kdc {
    wchar_t       name[K5_MAXCCH_HOST];
    khm_boolean   admin;        /* admin server? */
    khm_boolean   master;       /* master kdc? */
    khm_int32     flags;
} k5_realm_kdc;

#define K5_RKFLAG_DELETED    1
#define K5_RKFLAG_NEW        2
#define K5_RKFLAG_MOD_ADMIN  4
#define K5_RKFLAG_MOD_MASTER 8

typedef struct tag_k5_domain_map {
    wchar_t       name[K5_MAXCCH_HOST]; /* name of host that maps to a
                                           realm */
    khm_int32     flags;
} k5_domain_map;

#define K5_DMFLAG_DELETED 1
#define K5_DMFLAG_NEW     2

typedef struct tag_k5_realm_data {
    wchar_t       realm[K5_MAXCCH_REALM];
    k5_realm_kdc  kdcs[K5_MAX_KDC];
    khm_size      n_kdcs;
    k5_domain_map domain_maps[K5_MAX_DOMAIN_MAPPINGS];
    khm_size      n_domain_maps;

    khm_int32     flags;
} k5_realm_data;

#define K5_RDFLAG_DELETED 1
#define K5_RDFLAG_NEW     2
#define K5_RDFLAG_MODIFED 4

#define K5_REALMS_ALLOC_INCR 8

typedef struct tag_k5_config_data {
    wchar_t       def_realm[K5_MAXCCH_REALM];    /* default realm */

    wchar_t       config_file[MAX_PATH]; /* path to configuration file */
    khm_boolean   create_config_file; /* create config_file if missing? */
    khm_boolean   inc_realms;   /* include full realm list in new
                                   credentials dialog? */
    wchar_t       loaded_config_file[MAX_PATH]; /* path to the
                                                   configuration file
                                                   that has been
                                                   loaded into the
                                                   realm editor. */

    /* [libdefaults] */
    khm_boolean   dns_lookup_kdc;
    khm_boolean   dns_lookup_realm;
    khm_boolean   dns_fallback;

    khm_boolean   noaddresses;

    k5_lsa_import lsa_import;   /* import mslsa creds? */

    /* [realms] */
    k5_realm_data *realms;
    khm_size      n_realms;
    khm_size      nc_realms;
    khm_size      c_realm;

    khui_config_node node_main;
    khui_config_node node_realm;

    khm_int32     flags;

    /* used by the realm editor */
    HMENU         hm_realms_ctx;
    HMENU         hm_kdc_ctx;
    HMENU         hm_dmap_ctx;
} k5_config_data;

#define K5_CDFLAG_MOD_DEF_REALM      0x00000001
#define K5_CDFLAG_MOD_CONF_FILE      0x00000002
#define K5_CDFLAG_MOD_DNS_LOOKUP_KDC 0x00000004
#define K5_CDFLAG_MOD_DNS_LOOKUP_RLM 0x00000008
#define K5_CDFLAG_MOD_DNS_FALLBACK   0x00000010
#define K5_CDFLAG_MOD_NOADDRESSES    0x00000020
#define K5_CDFLAG_MOD_LSA_IMPORT     0x00000040
#define K5_CDFLAG_MOD_CREATE_CONF    0x00000080
#define K5_CDFLAG_MOD_INC_REALMS     0x00000100
#define K5_CDFLAG_MOD_REALMS         0x00001000

void
k5_init_config_data(k5_config_data * d) {
    ZeroMemory(d, sizeof(*d));
}

void
k5_free_config_data(k5_config_data * d) {
    if (d->realms)
        PFREE(d->realms);

    k5_init_config_data(d);
}

static void
k5_assert_n_realms(k5_config_data * d, khm_size n) {
    khm_size nc_realms;

    if (n <= d->nc_realms)
        return;

    nc_realms = UBOUNDSS(n, K5_REALMS_ALLOC_INCR, K5_REALMS_ALLOC_INCR);
    assert(nc_realms > d->nc_realms);

    d->realms = PREALLOC(d->realms, nc_realms * sizeof(*(d->realms)));
    d->nc_realms = nc_realms;

    ZeroMemory(&d->realms[d->n_realms],
               (d->nc_realms - d->n_realms) * sizeof(*(d->realms)));
}

void
k5_purge_config_data(k5_config_data * d,
                     khm_boolean purge_realms,
                     khm_boolean purge_kdcs,
                     khm_boolean purge_dmap) {
    khm_size r;
    khm_size k;
    khm_size m;

    for (r=0; r < d->n_realms; r++) {
        if (purge_realms &&
            (d->realms[r].flags & K5_RDFLAG_NEW) &&
            (d->realms[r].flags & K5_RDFLAG_DELETED)) {

            if (d->n_realms > r+1)
                MoveMemory(&d->realms[r], &d->realms[r+1],
                           sizeof(d->realms[0]) * (d->n_realms - (r+1)));
            r--;
            d->n_realms--;
            continue;
        }

        for (k=0; k < d->realms[r].n_kdcs; k++) {
            if (purge_kdcs &&
                (d->realms[r].kdcs[k].flags & K5_RKFLAG_NEW) &&
                (d->realms[r].kdcs[k].flags & K5_RKFLAG_DELETED)) {
                if (d->realms[r].n_kdcs > k + 1)
                    MoveMemory(&d->realms[r].kdcs[k],
                               &d->realms[r].kdcs[k+1],
                               sizeof(d->realms[0].kdcs[0]) *
                               (d->realms[r].n_kdcs - (k+1)));
                k--;
                d->realms[r].n_kdcs--;
                continue;
            }
        }

        if (K5_MAX_KDC > k+1)
            ZeroMemory(&d->realms[r].kdcs[k],
                       sizeof(d->realms[0].kdcs[0]) *
                       (K5_MAX_KDC - (k + 1)));

        for (m=0; m < d->realms[r].n_domain_maps; m++) {
            if (purge_dmap &&
                (d->realms[r].domain_maps[m].flags & K5_DMFLAG_NEW) &&
                (d->realms[r].domain_maps[m].flags & K5_DMFLAG_DELETED)) {
                if (d->realms[r].n_domain_maps > m + 1)
                    MoveMemory(&d->realms[r].domain_maps[m],
                               &d->realms[r].domain_maps[m+1],
                               sizeof(d->realms[0].domain_maps[0]) *
                               (d->realms[r].n_domain_maps - (m+1)));
                m--;
                d->realms[r].n_domain_maps--;
                continue;
            }
        }

        if (K5_MAX_DOMAIN_MAPPINGS > m+1)
            ZeroMemory(&d->realms[r].domain_maps[m],
                       sizeof(d->realms[0].domain_maps[0]) *
                       (K5_MAX_DOMAIN_MAPPINGS - (m+1)));
    }

    if (d->nc_realms > r + 1)
        ZeroMemory(&d->realms[r],
                   sizeof(d->realms[0]) *
                   (d->nc_realms - (r + 1)));
}

static khm_boolean
k5_is_profile_loaded(void) {
#ifdef DEBUG
    assert(pprofile_init);
    assert(pprofile_get_subsection_names);
    assert(pprofile_get_values);
    assert(pprofile_get_string);
    assert(pprofile_get_relation_names);
    assert(pprofile_free_list);
    assert(pprofile_release_string);
    assert(pprofile_release);
    assert(pprofile_clear_relation);
    assert(pprofile_add_relation);
    assert(pprofile_update_relation);
    assert(pprofile_flush);
    assert(pprofile_rename_section);
#endif

    if (!pprofile_init ||
        !pprofile_get_subsection_names ||
        !pprofile_get_values ||
        !pprofile_get_string ||
        !pprofile_get_relation_names ||
        !pprofile_free_list ||
        !pprofile_release_string ||
        !pprofile_release ||
        !pprofile_clear_relation ||
        !pprofile_add_relation ||
        !pprofile_update_relation ||
        !pprofile_flush ||
        !pprofile_rename_section)

        return FALSE;

    return TRUE;
}

void
k5_read_config_data(k5_config_data * d) {
    wchar_t * defrealm;
    char config_file[MAX_PATH];
    profile_t profile = NULL;
    const char *filenames[2];
    long rv;
    khm_size s;

    if (!k5_is_profile_loaded())
        return;

    defrealm = khm_krb5_get_default_realm();

    if (defrealm) {
        StringCbCopy(d->def_realm, sizeof(d->def_realm), defrealm);
        PFREE(defrealm);
    } else {
        StringCbCopy(d->def_realm, sizeof(d->def_realm), L"");
    }

    khm_krb5_get_profile_file(config_file, ARRAYLENGTH(config_file));

    AnsiStrToUnicode(d->config_file, sizeof(d->config_file), config_file);

    filenames[0] = config_file;
    filenames[1] = NULL;

    rv = pprofile_init(filenames, &profile);

    if (!rv) {
        const char * sec_realms[] = { "realms", NULL };
        const char * sec_domain_realm[] = { "domain_realm", NULL };
        char ** sections;
        char ** dr_from;
        char * boolv;

        /* first fish out a few values from [libdefaults] */

        rv = pprofile_get_string(profile, "libdefaults", "dns_lookup_kdc",
                                 NULL, NULL, &boolv);
        if (!rv && boolv) {
            khm_boolean b;

            if (!khm_krb5_parse_boolean(boolv, &b))
                d->dns_lookup_kdc = b;
            else
                d->dns_lookup_kdc = FALSE;
            pprofile_release_string(boolv);
        } else
            d->dns_lookup_kdc = FALSE;

        rv = pprofile_get_string(profile, "libdefaults", "dns_lookup_realm",
                                 NULL, NULL, &boolv);
        if (!rv && boolv) {
            khm_boolean b;

            if (!khm_krb5_parse_boolean(boolv, &b))
                d->dns_lookup_realm = b;
            else
                d->dns_lookup_realm = FALSE;
            pprofile_release_string(boolv);
        } else
            d->dns_lookup_realm = FALSE;

        rv = pprofile_get_string(profile, "libdefaults", "dns_fallback",
                                 NULL, NULL, &boolv);
        if (!rv && boolv) {
            khm_boolean b;

            if (!khm_krb5_parse_boolean(boolv, &b))
                d->dns_fallback = b;
            else
                d->dns_fallback = FALSE;
            pprofile_release_string(boolv);
        } else
            d->dns_fallback = FALSE;

        rv = pprofile_get_string(profile, "libdefaults", "noaddresses",
                                 NULL, NULL, &boolv);
        if (!rv && boolv) {
            khm_boolean b;

            if (!khm_krb5_parse_boolean(boolv, &b))
                d->noaddresses = b;
            else
                d->noaddresses = TRUE;
            pprofile_release_string(boolv);
        } else
            d->noaddresses = TRUE;

        /* now we look at the [realms] section */
        rv = pprofile_get_subsection_names(profile, sec_realms, &sections);

        /* what? no realms? whatever */
        if (rv) goto _skip_realms;

        /* get a count first */
        for (s=0; sections[s] && sections[s][0]; s++);

        k5_assert_n_realms(d, s);
        d->n_realms = s;

        /* now go through each and fish out the kdcs, admin_server
           and master_kdc. */
        for (s=0; sections[s] && sections[s][0]; s++) {
            const char * sec_kdcs[] = 
                { "realms", sections[s], "kdc", NULL };

            const char * sec_admin[] =
                { "realms", sections[s], "admin_server", NULL };

            const char * sec_master[] =
                { "realms", sections[s], "master_kdc", NULL };

            char ** values;

            AnsiStrToUnicode(d->realms[s].realm, sizeof(d->realms[s].realm),
                             sections[s]);
            d->realms[s].n_kdcs = 0;
            d->realms[s].n_domain_maps = 0;

            rv = pprofile_get_values(profile, sec_kdcs, &values);
            if (!rv) {
                khm_size i;

                for (i=0 ; values[i] && values[i][0] && i < K5_MAX_KDC; i++) {
                    AnsiStrToUnicode(d->realms[s].kdcs[i].name,
                                     sizeof(d->realms[s].kdcs[i].name),
                                     values[i]);

                }
                d->realms[s].n_kdcs = i;

                pprofile_free_list(values);
            }

            rv = pprofile_get_values(profile, sec_admin, &values);
            if (!rv) {
                khm_size i;
                khm_size j;
                wchar_t kdc_name[K5_MAXCCH_HOST];

                for (i=0; values[i] && values[i][0]; i++) {
                    AnsiStrToUnicode(kdc_name,
                                     sizeof(kdc_name), values[i]);

                    for (j=0; j < d->realms[s].n_kdcs; j++)
                        if (!_wcsicmp(kdc_name, d->realms[s].kdcs[j].name))
                            break;

                    if (j < d->realms[s].n_kdcs) {
                        d->realms[s].kdcs[j].admin = TRUE;
                    } else if (d->realms[s].n_kdcs < K5_MAX_KDC) {
                        j = d->realms[s].n_kdcs;
                        StringCbCopy(d->realms[s].kdcs[j].name,
                                     sizeof(d->realms[s].kdcs[j].name),
                                     kdc_name);
                        d->realms[s].kdcs[j].admin = TRUE;
                        d->realms[s].n_kdcs ++;
                    }
                }
                pprofile_free_list(values);
            }

            rv = pprofile_get_values(profile, sec_master, &values);
            if (!rv) {
                khm_size i;
                khm_size j;
                wchar_t kdc_name[K5_MAXCCH_HOST];

                for (i=0; values[i] && values[i][0]; i++) {
                    AnsiStrToUnicode(kdc_name, sizeof(kdc_name), values[i]);

                    for (j=0; j < d->realms[s].n_kdcs; j++)
                        if (!_wcsicmp(kdc_name, d->realms[s].kdcs[j].name))
                            break;

                    if (j < d->realms[s].n_kdcs) {
                        d->realms[s].kdcs[j].master = TRUE;
                    } else if (d->realms[s].n_kdcs < K5_MAX_KDC) {
                        j = d->realms[s].n_kdcs;
                        StringCbCopy(d->realms[s].kdcs[j].name,
                                     sizeof(d->realms[s].kdcs[j].name),
                                     kdc_name);
                        d->realms[s].kdcs[j].master = TRUE;
                        d->realms[s].n_kdcs ++;
                    }
                }

                pprofile_free_list(values);
            }
        }
        pprofile_free_list(sections);

    _skip_realms:

        rv = pprofile_get_relation_names(profile, sec_domain_realm, &dr_from);
        if (!rv) {
            khm_size i;
            khm_size j;
            char * dr_to;
            wchar_t wdr_from[K5_MAXCCH_HOST];
            wchar_t wdr_to[K5_MAXCCH_HOST];

            for (i=0; dr_from[i] && dr_from[i][0]; i++) {
                AnsiStrToUnicode(wdr_from, sizeof(wdr_from), dr_from[i]);

                rv = pprofile_get_string(profile, "domain_realm", dr_from[i],
                                         NULL, NULL, &dr_to);

                if (rv || !dr_to)
                    continue;

                AnsiStrToUnicode(wdr_to, sizeof(wdr_to), dr_to);

                for (j=0; j < d->n_realms; j++) {
                    if (!_wcsicmp(wdr_to, d->realms[j].realm))
                        break;
                }

                if (j >= d->n_realms) {
                    j = d->n_realms;
                    k5_assert_n_realms(d, j + 1);

                    StringCbCopy(d->realms[j].realm,
                                 sizeof(d->realms[j].realm),
                                 wdr_to);
                    d->realms[j].n_kdcs = 0;
                    d->realms[j].n_domain_maps = 0;

                    d->n_realms++;
                }

                if (d->realms[j].n_domain_maps < K5_MAX_DOMAIN_MAPPINGS) {
                    khm_size k;

                    k = d->realms[j].n_domain_maps;

                    StringCbCopy(d->realms[j].domain_maps[k].name,
                                 sizeof(d->realms[j].domain_maps[k].name),
                                 wdr_from);

                    d->realms[j].n_domain_maps++;
                }

                pprofile_release_string(dr_to);
            }
            pprofile_free_list(dr_from);
        }
        pprofile_release(profile);
    }

    {
        khm_int32 t;

        /* last, read the MSLSA import setting */
        if (KHM_SUCCEEDED(khc_read_int32(csp_params,
                                         L"MsLsaImport", &t))) {
            d->lsa_import = t;
        } else {
            d->lsa_import = K5_LSAIMPORT_ALWAYS;
        }

        if (KHM_SUCCEEDED(khc_read_int32(csp_params,
                                         L"UseFullRealmList", &t))) {
            d->inc_realms = !!t;
        } else {
            d->inc_realms = TRUE;
        }
    }

    d->flags = 0;
}

int
k5_write_config_data(k5_config_data * d) {
    char astr[MAX_PATH * 2];
    char config_file[MAX_PATH];
    profile_t profile = NULL;
    const char *filenames[2];
    long rv;
    khm_size s;
    int applied = FALSE;

    if (d->flags == 0)
        return FALSE;

    if (!k5_is_profile_loaded())
        return FALSE;

    /* write the MSLSA import setting */
    if (d->flags & K5_CDFLAG_MOD_LSA_IMPORT) {
        khc_write_int32(csp_params, L"MsLsaImport", d->lsa_import);
        d->flags &= ~K5_CDFLAG_MOD_LSA_IMPORT;
        applied = TRUE;
    }

    if (d->flags & K5_CDFLAG_MOD_INC_REALMS) {
        khc_write_int32(csp_params, L"UseFullRealmList", d->inc_realms);
        d->flags &= ~K5_CDFLAG_MOD_INC_REALMS;
        applied = TRUE;
    }

    if (!(d->flags & 
          (K5_CDFLAG_MOD_DEF_REALM |
           K5_CDFLAG_MOD_CONF_FILE |
           K5_CDFLAG_MOD_DNS_FALLBACK |
           K5_CDFLAG_MOD_DNS_LOOKUP_RLM |
           K5_CDFLAG_MOD_DNS_LOOKUP_KDC |
           K5_CDFLAG_MOD_NOADDRESSES |
           K5_CDFLAG_MOD_CREATE_CONF |
           K5_CDFLAG_MOD_REALMS))) {

        d->flags = 0;
        return applied;
    }

    khm_krb5_get_profile_file(config_file, ARRAYLENGTH(config_file));

    UnicodeStrToAnsi(astr, sizeof(astr), d->config_file);

    if (_stricmp(config_file, astr)) {
        assert(FALSE);
    }

    filenames[0] = config_file;
    filenames[1] = NULL;

    rv = pprofile_init(filenames, &profile);

#if FAILOVER_TO_TEMPORARY_FILE
    if (rv) {
        char temp_file[MAX_PATH];

        khm_krb5_get_temp_profile_file(temp_file,
                                       ARRAYLENGTH(temp_file));

        filenames[0] = temp_file;

        rv = pprofile_init(filenames, &profile);

            ?? TODO: Also warn if we are doing this
    }
#endif

    if (!rv) {
        const char * sec_realms[] = { "realms", NULL };
        const char * sec_domain_realm[] = { "domain_realm", NULL };
        const char * sec_libdefaults[] = { "libdefaults", NULL, NULL };
        khm_size r;

        if (d->flags & K5_CDFLAG_MOD_DEF_REALM) {
            if (SUCCEEDED(StringCbLength(d->def_realm,
                                         sizeof(d->def_realm), &s)) &&
                s > 0) {
                char defrealm[K5_MAXCCH_REALM];

                UnicodeStrToAnsi(defrealm, sizeof(defrealm), 
                                 d->def_realm);

                khm_krb5_set_default_realm(d->def_realm);

                sec_libdefaults[1] = "default_realm";

                pprofile_clear_relation(profile, sec_libdefaults);

                rv = pprofile_add_relation(profile, sec_libdefaults,
                                           defrealm);
                applied = TRUE;
            }
            d->flags &= ~K5_CDFLAG_MOD_DEF_REALM;
        }

        if (d->flags & K5_CDFLAG_MOD_DNS_LOOKUP_KDC) {

            sec_libdefaults[1] = "dns_lookup_kdc";

            pprofile_clear_relation(profile, sec_libdefaults);

            rv = pprofile_add_relation(profile, sec_libdefaults,
                                       (d->dns_lookup_kdc)?
                                       KRB5_CONF_YES:
                                       KRB5_CONF_NO);
            d->flags &= ~K5_CDFLAG_MOD_DNS_LOOKUP_KDC;
            applied = TRUE;
        }

        if (d->flags & K5_CDFLAG_MOD_DNS_LOOKUP_RLM) {

            sec_libdefaults[1] = "dns_lookup_realm";

            pprofile_clear_relation(profile, sec_libdefaults);

            rv = pprofile_add_relation(profile, sec_libdefaults,
                                       (d->dns_lookup_realm)?
                                       KRB5_CONF_YES:
                                       KRB5_CONF_NO);

            d->flags &= ~K5_CDFLAG_MOD_DNS_LOOKUP_RLM;
            applied = TRUE;
        }

        if (d->flags & K5_CDFLAG_MOD_DNS_FALLBACK) {

            sec_libdefaults[1] = "dns_fallback";

            pprofile_clear_relation(profile, sec_libdefaults);

            rv = pprofile_add_relation(profile, sec_libdefaults,
                                       (d->dns_fallback)?
                                       KRB5_CONF_YES:
                                       KRB5_CONF_NO);

            d->flags &= ~K5_CDFLAG_MOD_DNS_FALLBACK;
            applied = TRUE;
        }

        if (d->flags & K5_CDFLAG_MOD_NOADDRESSES) {

            sec_libdefaults[1] = "noaddresses";

            pprofile_clear_relation(profile, sec_libdefaults);

            rv = pprofile_add_relation(profile, sec_libdefaults,
                                       (d->noaddresses)?
                                       KRB5_CONF_YES:
                                       KRB5_CONF_NO);

            d->flags &= ~K5_CDFLAG_MOD_NOADDRESSES;
            applied = TRUE;
        }

        /* now we look at the [realms] section */

        for (r=0; r < d->n_realms; r++) {
            char realm[K5_MAXCCH_REALM];
            char host[K5_MAXCCH_HOST];

            const char * sec_kdcs[] = 
                { "realms", realm, "kdc", NULL };

            const char * sec_admin[] =
                { "realms", realm, "admin_server", NULL };

            const char * sec_master[] =
                { "realms", realm, "master_kdc", NULL };

            const char * sec_domain_map[] =
                { "domain_realm", host, NULL };

            char ** values;

            UnicodeStrToAnsi(realm, sizeof(realm),
                             d->realms[r].realm);

            if (!(d->realms[r].flags & K5_RDFLAG_DELETED) &&
                (d->realms[r].flags & K5_RDFLAG_NEW)) {

                khm_size k;
                khm_size m;

                /* this is a new realm */

                for (k=0; k < d->realms[r].n_kdcs; k++) {
                    if (!(d->realms[r].kdcs[k].flags & K5_RKFLAG_DELETED)) {
                        UnicodeStrToAnsi(host, sizeof(host),
                                         d->realms[r].kdcs[k].name);

                        if (d->realms[r].kdcs[k].master)
                            pprofile_add_relation(profile, sec_master,
                                                  host);

                        pprofile_add_relation(profile, sec_kdcs,
                                              host);

                        if (d->realms[r].kdcs[k].admin)
                            pprofile_add_relation(profile, sec_admin,
                                                  host);

                        d->realms[r].kdcs[k].flags &= ~ (K5_RKFLAG_NEW |
                                                         K5_RKFLAG_MOD_MASTER |
                                                         K5_RKFLAG_MOD_ADMIN);
                        applied = TRUE;
                    }
                }

                for (m=0; m < d->realms[r].n_domain_maps; m++) {

                    UnicodeStrToAnsi(host, sizeof(host),
                                     d->realms[r].domain_maps[m].name);

                    if ((d->realms[r].domain_maps[m].flags &
                         K5_DMFLAG_DELETED) &&
                        !(d->realms[r].domain_maps[m].flags &
                          K5_DMFLAG_NEW)) {
                        pprofile_clear_relation(profile, sec_domain_map);

                        /* setting this flag indicates that the item
                           is deleted and not in the profile file
                           anymore. */
                        d->realms[r].domain_maps[m].flags |= K5_DMFLAG_NEW;
                        applied = TRUE;
                    } else if (!(d->realms[r].domain_maps[m].flags &
                               K5_DMFLAG_DELETED) &&
                             (d->realms[r].domain_maps[m].flags &
                              K5_DMFLAG_NEW)) {
                        pprofile_add_relation(profile, sec_domain_map,
                                              realm);

                        d->realms[r].domain_maps[m].flags &= ~K5_DMFLAG_NEW;
                        applied = TRUE;
                    }
                }

                d->realms[r].flags &= ~(K5_RDFLAG_NEW |
                                        K5_RDFLAG_MODIFED);

            } else if ((d->realms[r].flags & K5_RDFLAG_DELETED) &&
                       !(d->realms[r].flags & K5_RDFLAG_NEW)) {

                const char * sec_all[] =
                    { "realms", realm, NULL, NULL };
                khm_size v;

                /* this realm should be deleted */

                rv = pprofile_get_relation_names(profile, sec_all,
                                                 &values);
                if (!rv) {
                    for (v=0; values[v] && values[v][0]; v++) {
                        sec_all[2] = values[v];
                        pprofile_clear_relation(profile, sec_all);
                    }
                    sec_all[2] = NULL;
                    pprofile_rename_section(profile, sec_all, NULL);
                    pprofile_free_list(values);
                    applied = TRUE;
                }

                rv = pprofile_get_relation_names(profile, sec_domain_realm,
                                                 &values);
                if (!rv) {
                    char * maprealm;

                    for (v=0; values[v] && values[v][0]; v++) {

                        rv = pprofile_get_string(profile, "domain_realm",
                                                 values[v], NULL, NULL,
                                                 &maprealm);

                        if (!rv) {
                            if (!strcmp(maprealm, realm)) {
                                StringCbCopyA(host, sizeof(host), 
                                              values[v]);
                                pprofile_clear_relation(profile, 
                                                        sec_domain_map);
                                applied = TRUE;
                            }
                            pprofile_release_string(maprealm);
                        }
                    }

                    pprofile_free_list(values);
                }

                /* setting this flag indicate that the realm is
                   deleted and is not in the profile file. */
                d->realms[r].flags |= K5_RDFLAG_NEW;

            } else if (!(d->realms[r].flags & K5_RDFLAG_DELETED) &&
                       (d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                khm_size k;
                khm_size m;

                /* same as before.  check if we have to update the kdc
                   list or the domain_realm mappings */

                for (k=0; k < d->realms[r].n_kdcs; k++) {

                    if ((d->realms[r].kdcs[k].flags & K5_RKFLAG_NEW) &&
                        (d->realms[r].kdcs[k].flags & K5_RKFLAG_DELETED))
                        continue;

                    UnicodeStrToAnsi(host, sizeof(host),
                                     d->realms[r].kdcs[k].name);

                    if (d->realms[r].kdcs[k].flags & K5_RKFLAG_DELETED) {
                        pprofile_update_relation(profile, sec_kdcs,
                                                 host, NULL);
                        pprofile_update_relation(profile, sec_admin,
                                                 host, NULL);
                        pprofile_update_relation(profile, sec_master,
                                                 host, NULL);

                        applied = TRUE;

                        /* as above, setting 'new' flag to indicate
                           that the item does not exist in the profile
                           file. */
                        d->realms[r].kdcs[k].flags |= K5_RKFLAG_NEW;
                        continue;
                    }

                    if (d->realms[r].kdcs[k].flags & K5_RKFLAG_NEW) {
                        if (d->realms[r].kdcs[k].master)
                            pprofile_add_relation(profile, sec_master,
                                                  host);

                        pprofile_add_relation(profile, sec_kdcs,
                                              host);

                        if (d->realms[r].kdcs[k].admin)
                            pprofile_add_relation(profile, sec_admin,
                                                  host);

                        d->realms[r].kdcs[k].flags &= ~(K5_RKFLAG_NEW |
                                                        K5_RKFLAG_MOD_ADMIN |
                                                        K5_RKFLAG_MOD_MASTER);
                        applied = TRUE;
                        continue;
                    }

                    if (d->realms[r].kdcs[k].flags & K5_RKFLAG_MOD_MASTER) {
                        if (!d->realms[r].kdcs[k].master) {
                            pprofile_update_relation(profile, sec_master,
                                                     host, NULL);
                        } else {
                            pprofile_update_relation(profile, sec_master,
                                                     host, NULL);
                            pprofile_add_relation(profile, sec_master,
                                                  host);
                        }

                        applied = TRUE;
                        d->realms[r].kdcs[k].flags &= ~K5_RKFLAG_MOD_MASTER;
                    }

                    if (d->realms[r].kdcs[k].flags & K5_RKFLAG_MOD_ADMIN) {
                        if (d->realms[r].kdcs[k].admin) {
                            pprofile_update_relation(profile, sec_admin,
                                                     host, NULL);
                            pprofile_add_relation(profile, sec_admin,
                                                  host);
                        } else {
                            pprofile_update_relation(profile, sec_admin,
                                                     host, NULL);
                        }

                        applied = TRUE;
                        d->realms[r].kdcs[k].flags &= ~K5_RKFLAG_MOD_ADMIN;
                    }
                }

                for (m=0; m < d->realms[r].n_domain_maps; m++) {

                    UnicodeStrToAnsi(host, sizeof(host),
                                     d->realms[r].domain_maps[m].name);

                    if ((d->realms[r].domain_maps[m].flags &
                         K5_DMFLAG_DELETED) &&

                        !(d->realms[r].domain_maps[m].flags &
                          K5_DMFLAG_NEW)) {

                        pprofile_clear_relation(profile, sec_domain_map);
                        d->realms[r].domain_maps[m].flags |= K5_DMFLAG_NEW;
                        applied = TRUE;

                    } else if (!(d->realms[r].domain_maps[m].flags &
                               K5_DMFLAG_DELETED) &&

                             (d->realms[r].domain_maps[m].flags &
                              K5_DMFLAG_NEW)) {

                        pprofile_add_relation(profile, sec_domain_map,
                                              realm);
                        d->realms[r].domain_maps[m].flags &= ~K5_DMFLAG_NEW;
                        applied = TRUE;

                    }
                }

                d->realms[r].flags &= ~K5_RDFLAG_MODIFED;
            }
        }

        rv = pprofile_flush(profile);

        pprofile_release(profile);
    }

    if (rv) {
        khui_alert * alert;
        wchar_t title[KHUI_MAXCCH_TITLE];
        wchar_t fmsg[KHUI_MAXCCH_MESSAGE];
        wchar_t msg[KHUI_MAXCCH_MESSAGE];
        wchar_t sugg[KHUI_MAXCCH_SUGGESTION];

        LoadString(hResModule, IDS_K5ERR_CANTWRITEPROFILE,
                   title, ARRAYLENGTH(title));
        if (rv)
            LoadString(hResModule, IDS_K5ERR_PROFNOWRITE,
                       fmsg, ARRAYLENGTH(fmsg));

        LoadString(hResModule, IDS_K5ERR_PROFSUGGEST,
                   sugg, ARRAYLENGTH(sugg));

        StringCbPrintf(msg, sizeof(msg), fmsg, config_file);

        khui_alert_create_empty(&alert);
        khui_alert_set_severity(alert, (rv)?KHERR_ERROR:KHERR_WARNING);
        khui_alert_set_title(alert, title);
        khui_alert_set_message(alert, msg);
        khui_alert_set_suggestion(alert, sugg);
        
        khui_alert_show(alert);
    }

    d->flags = 0;

    return applied;
}

/* actual dialog stuff */

#define IDX_NORMAL   1
#define IDX_MODIFIED 2
#define IDX_NEW      3
#define IDX_DELETED  4

static k5_config_data k5_config_dlg_data;
static khm_boolean    k5_dlg_data_valid = FALSE;

INT_PTR CALLBACK 
k5_config_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    switch(uMsg) {
    case WM_INITDIALOG:
        {
            HWND hw;
            khm_size i;
            k5_config_data * d;

            wchar_t * t;
            wchar_t importopts[256];
            WKSTA_INFO_100 * winfo100;

#ifdef DEBUG
            assert(!k5_dlg_data_valid);
#endif

            k5_init_config_data(&k5_config_dlg_data);
            k5_read_config_data(&k5_config_dlg_data);

            k5_dlg_data_valid = TRUE;

            d = &k5_config_dlg_data;

            d->node_main = (khui_config_node) lParam;

            CheckDlgButton(hwnd, IDC_CFG_INCREALMS,
                           (d->inc_realms)? BST_CHECKED: BST_UNCHECKED);

            hw = GetDlgItem(hwnd, IDC_CFG_DEFREALM);
#ifdef DEBUG
            assert(hw);
#endif

            SendMessage(hw, CB_RESETCONTENT, 0, 0);

            for (i=0; i < d->n_realms; i++) {
                SendMessage(hw, CB_ADDSTRING, 0,
                            (LPARAM) d->realms[i].realm);
            }

            SendMessage(hw, CB_SELECTSTRING, (WPARAM) -1,
                        (LPARAM) d->def_realm);
            SetDlgItemText(hwnd, IDC_CFG_DEFREALM, d->def_realm);
            SendDlgItemMessage(hwnd, IDC_CFG_DEFREALM, CB_LIMITTEXT,
                               ARRAYLENGTH(d->def_realm) - 1, 0);

            SetDlgItemText(hwnd, IDC_CFG_CFGFILE, d->config_file);
            SendDlgItemMessage(hwnd, IDC_CFG_CFGFILE, EM_LIMITTEXT,
                               ARRAYLENGTH(d->config_file) - 1, 0);

            /* hostname/domain */
            if (NetWkstaGetInfo(NULL, 100, (LPBYTE *) &winfo100) == NERR_Success) {
                SetDlgItemText(hwnd, IDC_CFG_HOSTNAME, winfo100->wki100_computername);
                SetDlgItemText(hwnd, IDC_CFG_DOMAIN, winfo100->wki100_langroup);
                NetApiBufferFree(winfo100);
            }

            /* and the import ticket options */
            {
                wchar_t csvstring[256];
                khm_size cb;

                csvstring[0] = L'\0';

                LoadString(hResModule, IDS_K5CFG_IMPORT_OPTIONS,
                           csvstring, ARRAYLENGTH(csvstring));

                cb = sizeof(importopts);
                csv_to_multi_string(importopts, &cb, csvstring);
            }

            hw = GetDlgItem(hwnd, IDC_CFG_IMPORT);
#ifdef DEBUG
            assert(hw);
#endif
            SendMessage(hw, CB_RESETCONTENT, 0, 0);

            for (t=importopts; 
                 t && *t && *t != L' ' &&
                     t < importopts + ARRAYLENGTH(importopts);
                 t = multi_string_next(t)) {

                SendMessage(hw, CB_ADDSTRING, 0, (LPARAM) t);
            }

            SendMessage(hw, CB_SETCURSEL, 0, d->lsa_import);
            t = importopts;
            SendMessage(hw, CB_GETLBTEXT, d->lsa_import,(LPARAM) t);
            SendMessage(hw, CB_SELECTSTRING, (WPARAM) -1, (LPARAM) t);
        }
        break;

    case WM_COMMAND:
        {
            k5_config_data * d;

            d = &k5_config_dlg_data;

            if (d == NULL)
                return FALSE;

            if (wParam == MAKEWPARAM(IDC_CFG_IMPORT, CBN_SELCHANGE)) {
                int idx;
                int modified = FALSE;

                idx = (int) SendDlgItemMessage(hwnd, IDC_CFG_IMPORT,
                                               CB_GETCURSEL, 0, 0);
                if (idx != CB_ERR && idx != d->lsa_import) {
                    d->lsa_import = idx;
                    d->flags |= K5_CDFLAG_MOD_LSA_IMPORT;
                    modified = TRUE;
                }

                khui_cfg_set_flags(d->node_main,
                                   (modified)?KHUI_CNFLAG_MODIFIED:0,
                                   KHUI_CNFLAG_MODIFIED);
                return TRUE;
            }

            if (wParam == MAKEWPARAM(IDC_CFG_INCREALMS, BN_CLICKED)) {
                if (IsDlgButtonChecked(hwnd, IDC_CFG_INCREALMS) ==
                    BST_CHECKED) {
                    d->inc_realms = TRUE;
                } else {
                    d->inc_realms = FALSE;
                }
                d->flags |= K5_CDFLAG_MOD_INC_REALMS;

                khui_cfg_set_flags(d->node_main,
                                   KHUI_CNFLAG_MODIFIED,
                                   KHUI_CNFLAG_MODIFIED);
                return TRUE;
            }

            if (wParam == MAKEWPARAM(IDC_CFG_DEFREALM, CBN_EDITCHANGE)) {
                wchar_t defrealm[K5_MAXCCH_REALM];
                int t;

                t = GetDlgItemText(hwnd, IDC_CFG_DEFREALM,
                                   defrealm, ARRAYLENGTH(defrealm));
                if (t == 0) {
                    /* we failed to get the default realm from the
                       control for some reason. */
                    SetDlgItemText(hwnd, IDC_CFG_DEFREALM, L"");
                    StringCbCopy(d->def_realm, sizeof(d->def_realm),
                                 L"");
                } else {
                    StringCbCopy(d->def_realm, sizeof(d->def_realm),
                                 defrealm);
                }

                d->flags |= K5_CDFLAG_MOD_DEF_REALM;

                khui_cfg_set_flags(d->node_main,
                                   KHUI_CNFLAG_MODIFIED,
                                   KHUI_CNFLAG_MODIFIED);
                return TRUE;
            }

            if (wParam == MAKEWPARAM(IDC_CFG_DEFREALM, CBN_SELCHANGE)) {
                wchar_t defrealm[K5_MAXCCH_REALM];
                LRESULT cursel, lr;

                cursel = SendDlgItemMessage(hwnd, IDC_CFG_DEFREALM, CB_GETCURSEL,
                                            0, 0);
                if (cursel == CB_ERR)
                    return TRUE;

                lr = SendDlgItemMessage(hwnd, IDC_CFG_DEFREALM, CB_GETLBTEXTLEN,
                                        cursel, 0);
#ifdef DEBUG
                assert(lr < ARRAYLENGTH(defrealm));
#endif
                if (lr >= ARRAYLENGTH(defrealm)) {
                    /* we really shouldn't have any string here that
                       exceeds that many characters.  But if we do, we
                       ignore that since we don't consider it
                       valid. */
                    return TRUE;
                }

                lr = SendDlgItemMessage(hwnd, IDC_CFG_DEFREALM, CB_GETLBTEXT,
                                        cursel, (LPARAM) defrealm);
                if (lr == CB_ERR) {
                    /* somehow we failed to copy the value anyway
                       after all those checks.  */
#ifdef DEBUG
                    assert(FALSE);
#endif
                    return TRUE;
                }

                StringCbCopy(d->def_realm, sizeof(d->def_realm),
                             defrealm);

                d->flags |= K5_CDFLAG_MOD_DEF_REALM;

                khui_cfg_set_flags(d->node_main,
                                   KHUI_CNFLAG_MODIFIED,
                                   KHUI_CNFLAG_MODIFIED);

                return TRUE;
            }

#ifdef ALLOW_CHANGING_KRB5_CONFIG_FILE
            if (wParam == MAKEWPARAM(IDC_CFG_CFGFILE, EN_CHANGE)) {
                wchar_t cfgfile[MAX_PATH];
                int t;

                t = GetDlgItemText(hwnd, IDC_CFG_CFGFILE,
                                   cfgfile, ARRAYLENGTH(cfgfile));

                if (t == 0) {
                    StringCbCopy(d->config_file, sizeof(d->config_file),
                                 L"");
                } else {
                    StringCbCopy(d->config_file, sizeof(d->config_file),
                                 cfgfile);
                }

                d->flags |= K5_CDFLAG_MOD_CONF_FILE;

                khui_cfg_set_flags(d->node_main,
                                   KHUI_CNFLAG_MODIFIED,
                                   KHUI_CNFLAG_MODIFIED);
            }
#endif
        }
        break;

    case KHUI_WM_CFG_NOTIFY:
        {
            k5_config_data * d;

            d = &k5_config_dlg_data;

            if (HIWORD(wParam) == WMCFG_APPLY) {
                khm_int32 oflags;
                int applied;

                oflags = d->flags;
                applied = k5_write_config_data(d);

                if (d->flags != oflags) {
                    khui_cfg_set_flags(d->node_main,
                                       (applied ? KHUI_CNFLAG_APPLIED : 0),
                                       KHUI_CNFLAG_APPLIED |
                                       KHUI_CNFLAG_MODIFIED);
                }
                return TRUE;
            }
        }
        break;

    case WM_DESTROY:
        {
            k5_free_config_data(&k5_config_dlg_data);
            k5_dlg_data_valid = FALSE;
        }
        break;
    }
    return FALSE;
}

static HIMAGELIST
k5_get_state_image_list(void) {
    HIMAGELIST hil;
    HICON hicon;

    hil = ImageList_Create(GetSystemMetrics(SM_CXSMICON),
                           GetSystemMetrics(SM_CYSMICON),
                           ILC_COLOR | ILC_MASK,
                           4,
                           2);

    hicon = LoadImage(hResModule,
                      MAKEINTRESOURCE(IDI_NORMAL),
                      IMAGE_ICON,
                      GetSystemMetrics(SM_CXSMICON),
                      GetSystemMetrics(SM_CYSMICON),
                      LR_DEFAULTCOLOR);

    ImageList_AddIcon(hil, hicon);

    DestroyIcon(hicon);

    hicon = LoadImage(hResModule,
                      MAKEINTRESOURCE(IDI_MODIFIED),
                      IMAGE_ICON,
                      GetSystemMetrics(SM_CXSMICON),
                      GetSystemMetrics(SM_CYSMICON),
                      LR_DEFAULTCOLOR);

    ImageList_AddIcon(hil, hicon);

    DestroyIcon(hicon);

    hicon = LoadImage(hResModule,
                      MAKEINTRESOURCE(IDI_NEW),
                      IMAGE_ICON,
                      GetSystemMetrics(SM_CXSMICON),
                      GetSystemMetrics(SM_CYSMICON),
                      LR_DEFAULTCOLOR);

    ImageList_AddIcon(hil, hicon);

    DestroyIcon(hicon);

    hicon = LoadImage(hResModule,
                      MAKEINTRESOURCE(IDI_DELETED),
                      IMAGE_ICON,
                      GetSystemMetrics(SM_CXSMICON),
                      GetSystemMetrics(SM_CYSMICON),
                      LR_DEFAULTCOLOR);

    ImageList_AddIcon(hil, hicon);

    DestroyIcon(hicon);

    return hil;
}

static void
k5_update_realms_display(HWND hw_list, k5_config_data * d) {
    khm_size i;
    LVITEM lvi;
    wchar_t buf[64];

    ListView_DeleteAllItems(hw_list);

    for (i=0; i < d->n_realms; i++) {
        if ((d->realms[i].flags & K5_RDFLAG_DELETED) &&
            (d->realms[i].flags & K5_RDFLAG_NEW))
            continue;

        ZeroMemory(&lvi, sizeof(lvi));
        lvi.mask = LVIF_PARAM | LVIF_STATE | LVIF_TEXT;
        lvi.iItem = 0;
        lvi.iSubItem = 0;
        lvi.pszText = d->realms[i].realm;
        lvi.lParam = i;

        if (d->realms[i].flags & K5_RDFLAG_DELETED) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_DELETED);
        } else if (d->realms[i].flags & K5_RDFLAG_NEW) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
        } else if (d->realms[i].flags & K5_RDFLAG_MODIFED) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_MODIFIED);
        } else {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NORMAL);
        }
        lvi.stateMask = LVIS_STATEIMAGEMASK;

        ListView_InsertItem(hw_list, &lvi);
    }

    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_PARAM | LVIF_STATE | LVIF_TEXT;
    lvi.iItem = 0;
    lvi.iSubItem = 0;
    lvi.pszText = buf;
    lvi.lParam = (LPARAM) -1;

    LoadString(hResModule, IDS_CFG_RE_NEWREALM,
               buf, ARRAYLENGTH(buf));

    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
    lvi.stateMask = LVIS_STATEIMAGEMASK;

    ListView_InsertItem(hw_list, &lvi);

    if (d->flags & K5_CDFLAG_MOD_REALMS) {
        khui_cfg_set_flags(d->node_realm, KHUI_CNFLAG_MODIFIED,
                           KHUI_CNFLAG_MODIFIED);
    } else {
        khui_cfg_set_flags(d->node_realm, 0,
                           KHUI_CNFLAG_MODIFIED);
    }
}

#define K5_KDCSI_ADMIN 1
#define K5_KDCSI_MASTER 2

static void
k5_update_kdcs_display(HWND hw_kdc, k5_config_data * d, khm_size idx_rlm) {
    khm_size k;
    LVITEM lvi;
    int idx_item;
    k5_realm_kdc * pkdc;
    wchar_t wyes[8];
    wchar_t wno[8];
    wchar_t wbuf[64];

    ListView_DeleteAllItems(hw_kdc);

    if (d == NULL)
        return;

#ifdef DEBUG
    assert(idx_rlm < d->n_realms);
#endif
    LoadString(hResModule, IDS_YES, wyes, ARRAYLENGTH(wyes));
    LoadString(hResModule, IDS_NO, wno, ARRAYLENGTH(wno));

    for (k=0; k < d->realms[idx_rlm].n_kdcs; k++) {
        if ((d->realms[idx_rlm].kdcs[k].flags & K5_RKFLAG_DELETED) &&
            (d->realms[idx_rlm].kdcs[k].flags & K5_RKFLAG_NEW))
            continue;

        pkdc = &(d->realms[idx_rlm].kdcs[k]);

        ZeroMemory(&lvi, sizeof(lvi));
        lvi.mask = LVIF_PARAM | LVIF_STATE | LVIF_TEXT;
        lvi.iItem = K5_MAX_KDC;
        lvi.iSubItem = 0;
        lvi.lParam = k;
        lvi.pszText = pkdc->name;
        if (pkdc->flags & K5_RKFLAG_DELETED) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_DELETED);
        } else if (pkdc->flags & K5_RKFLAG_NEW) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
        } else if ((pkdc->flags & K5_RKFLAG_MOD_ADMIN) ||
                   (pkdc->flags & K5_RKFLAG_MOD_MASTER)) {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_MODIFIED);
        } else {
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NORMAL);
        }
        lvi.stateMask = LVIS_STATEIMAGEMASK;

        idx_item = ListView_InsertItem(hw_kdc, &lvi);

        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx_item;
        lvi.iSubItem = K5_KDCSI_ADMIN;
        if (pkdc->admin)
            lvi.pszText = wyes;
        else
            lvi.pszText = wno;
        ListView_SetItem(hw_kdc, &lvi);

        lvi.iSubItem = K5_KDCSI_MASTER;
        if (pkdc->master)
            lvi.pszText = wyes;
        else
            lvi.pszText = wno;
        ListView_SetItem(hw_kdc, &lvi);
    }

    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
    lvi.iItem = 0;
    lvi.iSubItem = 0;
    lvi.pszText = wbuf;
    lvi.lParam = (LPARAM) -1;
    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
    lvi.stateMask = LVIS_STATEIMAGEMASK;

    LoadString(hResModule, IDS_CFG_RE_NEWSERVER,
               wbuf, ARRAYLENGTH(wbuf));

    ListView_InsertItem(hw_kdc, &lvi);
}

static void
k5_update_dmap_display(HWND hw_dm, k5_config_data * d, khm_size idx_rlm) {
    khm_size m;
    LVITEM lvi;
    k5_domain_map * map;
    wchar_t wbuf[64];

    ListView_DeleteAllItems(hw_dm);

    if (d == NULL)
        return;

#ifdef DEBUG
    assert(idx_rlm < d->n_realms);
#endif

    for (m=0; m < d->realms[idx_rlm].n_domain_maps; m++) {
        map = &(d->realms[idx_rlm].domain_maps[m]);

        if ((map->flags & K5_DMFLAG_NEW) &&
            (map->flags & K5_DMFLAG_DELETED))
            continue;

        ZeroMemory(&lvi, sizeof(lvi));

        lvi.mask = LVIF_TEXT | LVIF_STATE | LVIF_PARAM;
        lvi.pszText = map->name;
        if (map->flags & K5_DMFLAG_DELETED)
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_DELETED);
        else if (map->flags & K5_DMFLAG_NEW)
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
        else
            lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NORMAL);
        lvi.stateMask = LVIS_STATEIMAGEMASK;
        lvi.lParam = m;

        lvi.iItem = K5_MAX_DOMAIN_MAPPINGS;
        lvi.iSubItem = 0;

        ListView_InsertItem(hw_dm, &lvi);
    }

    ZeroMemory(&lvi, sizeof(lvi));
    lvi.mask = LVIF_PARAM | LVIF_TEXT | LVIF_STATE;
    lvi.pszText = wbuf;
    lvi.lParam = (LPARAM) -1;
    lvi.state = INDEXTOSTATEIMAGEMASK(IDX_NEW);
    lvi.stateMask = LVIS_STATEIMAGEMASK;
    lvi.iItem = 0;
    lvi.iSubItem = 0;

    LoadString(hResModule, IDS_CFG_RE_NEWDMAP,
               wbuf, ARRAYLENGTH(wbuf));

    ListView_InsertItem(hw_dm, &lvi);
}

#define CMD_BASE 3000
#define CMD_NEW_REALM    (CMD_BASE + 1)
#define CMD_DEL_REALM    (CMD_BASE + 2)
#define CMD_NEW_SERVER   (CMD_BASE + 3)
#define CMD_DEL_SERVER   (CMD_BASE + 4)
#define CMD_MAKE_ADMIN   (CMD_BASE + 5)
#define CMD_MAKE_MASTER  (CMD_BASE + 6)
#define CMD_NEW_DMAP     (CMD_BASE + 7)
#define CMD_DEL_DMAP     (CMD_BASE + 8)

struct k5_menu_def {
    UINT string;
    UINT id;
    UINT type;
    UINT state;
};

struct k5_menu_def k5_menu_realms[] = {
    {IDS_CFG_RE_MNR, CMD_NEW_REALM, MFT_STRING, 0},
    {IDS_CFG_RE_MDR, CMD_DEL_REALM, MFT_STRING, 0}
};

struct k5_menu_def k5_menu_kdc[] = {
    {IDS_CFG_RE_MNK, CMD_NEW_SERVER, MFT_STRING, 0},
    {IDS_CFG_RE_MDK, CMD_DEL_SERVER, MFT_STRING, 0},
    {IDS_CFG_RE_MAK, CMD_MAKE_ADMIN, MFT_STRING, 0},
    {IDS_CFG_RE_MMK, CMD_MAKE_MASTER, MFT_STRING, 0}
};

struct k5_menu_def k5_menu_dmap[] = {
    {IDS_CFG_RE_MND, CMD_NEW_DMAP, MFT_STRING, 0},
    {IDS_CFG_RE_MDD, CMD_DEL_DMAP, MFT_STRING, 0}
};

HMENU
k5_menu_from_def(struct k5_menu_def * def, khm_size n) {
    HMENU menu;
    MENUITEMINFO mii;
    khm_size i;
    khm_size cch;
    wchar_t buf[1024];

    menu = CreatePopupMenu();

    for (i=0; i < n; i++) {
        ZeroMemory(&mii, sizeof(mii));

        mii.cbSize = sizeof(mii);

        if (def[i].type == MFT_STRING) {
            LoadString(hResModule, def[i].string,
                       buf, ARRAYLENGTH(buf));
            StringCchLength(buf, ARRAYLENGTH(buf), &cch);

            mii.fMask = MIIM_STRING | MIIM_ID;
            mii.fType = MFT_STRING;

            mii.fState = def[i].state;
            mii.wID = def[i].id;
            mii.cch = (UINT) cch;
            mii.dwTypeData = buf;

            InsertMenuItem(menu, (UINT) i, TRUE, &mii);
        } else {
#ifdef DEBUG
            assert(FALSE);
#endif
        }
    }

    return menu;
}

void
k5_delete_realms(HWND hwnd, k5_config_data * d) {
    LVITEM lvi;
    int idx;
    HWND hw_rlm;
    BOOL modified = FALSE;
    khm_size r;

    hw_rlm = GetDlgItem(hwnd, IDC_CFG_REALMS);

    idx = -1;
    while((idx = ListView_GetNextItem(hw_rlm, idx,
                                      LVNI_SELECTED))
          != -1) {
        ZeroMemory(&lvi, sizeof(lvi));
        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;
        
        ListView_GetItem(hw_rlm, &lvi);

        if (lvi.lParam != -1 &&
            (r = lvi.lParam) < d->n_realms) {
            d->realms[r].flags ^= K5_RDFLAG_DELETED;
            modified = TRUE;
        }
    }

    if (modified) {
        d->flags |= K5_CDFLAG_MOD_REALMS;
        
        k5_purge_config_data(d, TRUE, TRUE, TRUE);
        k5_update_realms_display(hw_rlm, d);
        k5_update_dmap_display(GetDlgItem(hwnd, IDC_CFG_DMAP), NULL, 0);
        k5_update_kdcs_display(GetDlgItem(hwnd, IDC_CFG_KDC), NULL, 0);
    }
}

void
k5_delete_servers(HWND hwnd, k5_config_data * d) {
    HWND hw_kdc;
    LVITEM lvi;
    khm_size r;
    khm_size k;
    int idx;
    BOOL modified = FALSE;

    hw_kdc = GetDlgItem(hwnd, IDC_CFG_KDC);
    r = d->c_realm;
    
    idx = -1;
    while((idx = ListView_GetNextItem(hw_kdc, idx,
                                      LVNI_SELECTED))
          != -1) {
        ZeroMemory(&lvi, sizeof(lvi));
        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;

        ListView_GetItem(hw_kdc, &lvi);

        if (lvi.lParam != -1 &&
            (k = lvi.lParam) < d->n_realms) {
            d->realms[r].kdcs[k].flags ^= K5_RKFLAG_DELETED;
            modified = TRUE;
        }
    }

    if (modified) {
        d->flags |= K5_CDFLAG_MOD_REALMS;
        d->realms[r].flags |= K5_RDFLAG_MODIFED;
        
        k5_purge_config_data(d, TRUE, TRUE, TRUE);
        k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
        k5_update_kdcs_display(hw_kdc, d, r);
    }
}

void
k5_delete_dmap(HWND hwnd, k5_config_data * d) {
    HWND hw_dmp;
    LVITEM lvi;
    khm_size r;
    khm_size m;
    int idx;
    BOOL modified = FALSE;

    hw_dmp = GetDlgItem(hwnd, IDC_CFG_DMAP);
    r = d->c_realm;

    idx = -1;
    while((idx = ListView_GetNextItem(hw_dmp, idx,
                                      LVNI_SELECTED))
          != -1) {
        ZeroMemory(&lvi, sizeof(lvi));
        lvi.iItem = idx;
        lvi.iSubItem = 0;
        lvi.mask = LVIF_PARAM;
        
        ListView_GetItem(hw_dmp, &lvi);

        if (lvi.lParam != -1 &&
            (m = lvi.lParam) < d->n_realms) {
            d->realms[r].domain_maps[m].flags ^= K5_DMFLAG_DELETED;
            modified = TRUE;
        }
    }

    if (modified) {
        d->flags |= K5_CDFLAG_MOD_REALMS;
        k5_purge_config_data(d, FALSE, FALSE, TRUE);
        
        if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
            d->realms[r].flags |= K5_RDFLAG_MODIFED;

            k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
        }

        k5_update_dmap_display(hw_dmp, d, r);
    }
}

INT_PTR CALLBACK 
k5_realms_dlgproc(HWND hwnd,
                  UINT uMsg,
                  WPARAM wParam,
                  LPARAM lParam) {
    k5_config_data * d;

    d = &k5_config_dlg_data;

    switch(uMsg) {
    case WM_INITDIALOG:
        {
            LVCOLUMN lvc;
            HWND hw;
            RECT r;
            wchar_t buf[256];

            assert(k5_dlg_data_valid);

            d->node_realm = (khui_config_node) lParam;

            /* set up columns for the Realms list */
            hw = GetDlgItem(hwnd, IDC_CFG_REALMS);
#ifdef DEBUG
            assert(hw);
#endif
            GetWindowRect(hw, &r);
            r.right -= 5;       /* shave a few pixels off the width */
            ZeroMemory(&lvc, sizeof(lvc));
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = buf;
            lvc.cx = (r.right - r.left);
            LoadString(hResModule, IDS_CFG_RE_REALMS,
                       buf, ARRAYLENGTH(buf));

            ListView_InsertColumn(hw, 0, &lvc);

            ListView_SetImageList(hw,
                                  k5_get_state_image_list(),
                                  LVSIL_STATE);

            k5_update_realms_display(hw, d);

            /* set up columns for the servers list */
            hw = GetDlgItem(hwnd, IDC_CFG_KDC);
#ifdef DEBUG
            assert(hw);
#endif
            GetWindowRect(hw, &r);
            r.right -= 5;
            ZeroMemory(&lvc, sizeof(lvc));
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = buf;
            lvc.cx = (r.right - r.left) * 2 / 4;
            LoadString(hResModule, IDS_CFG_RE_HEAD_SVR,
                       buf, ARRAYLENGTH(buf));

            ListView_InsertColumn(hw, 0, &lvc);

            lvc.cx = (r.right - r.left) * 1 / 4;
            LoadString(hResModule, IDS_CFG_RE_HEAD_ADMIN,
                       buf, ARRAYLENGTH(buf));
            ListView_InsertColumn(hw, 1, &lvc);

            LoadString(hResModule, IDS_CFG_RE_HEAD_MASTER,
                       buf, ARRAYLENGTH(buf));
            ListView_InsertColumn(hw, 2, &lvc);

            ListView_SetImageList(hw,
                                  k5_get_state_image_list(),
                                  LVSIL_STATE);

            /* set up columns for the domain/host mapping list */
            hw = GetDlgItem(hwnd, IDC_CFG_DMAP);
#ifdef DEBUG
            assert(hw);
#endif
            GetWindowRect(hw, &r);
            r.right -= 5;
            ZeroMemory(&lvc, sizeof(lvc));
            lvc.mask = LVCF_TEXT | LVCF_WIDTH;
            lvc.pszText = buf;
            lvc.cx = (r.right - r.left);
            LoadString(hResModule, IDS_CFG_RE_HEAD_DOMAIN,
                       buf, ARRAYLENGTH(buf));

            ListView_InsertColumn(hw, 0, &lvc);


            ListView_SetImageList(hw,
                                  k5_get_state_image_list(),
                                  LVSIL_STATE);

            /* Now set up the context menus */
            d->hm_realms_ctx = k5_menu_from_def(k5_menu_realms, ARRAYLENGTH(k5_menu_realms));
            d->hm_kdc_ctx = k5_menu_from_def(k5_menu_kdc, ARRAYLENGTH(k5_menu_kdc));
            d->hm_dmap_ctx = k5_menu_from_def(k5_menu_dmap, ARRAYLENGTH(k5_menu_dmap));
        }
        break;

    case WM_CONTEXTMENU:
        {
            UINT id;
            HMENU hm = NULL;
            int x,y;

            id = GetDlgCtrlID((HWND) wParam);

            if (id == IDC_CFG_REALMS) {
                HWND hw_realms;
                int n;
                MENUITEMINFO mii;

                hm = d->hm_realms_ctx;

                hw_realms = GetDlgItem(hwnd, IDC_CFG_REALMS);
#ifdef DEBUG
                assert(hw_realms);
#endif
                n = ListView_GetSelectedCount(hw_realms);
                ZeroMemory(&mii, sizeof(mii));
                mii.cbSize = sizeof(mii);

                if (n == 0) {
                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_DISABLED;

                    SetMenuItemInfo(hm, CMD_DEL_REALM, FALSE, &mii);
                } else {

                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_ENABLED;

                    SetMenuItemInfo(hm, CMD_DEL_REALM, FALSE, &mii);
                }
                
            } else if (id == IDC_CFG_KDC) {
                HWND hw_kdc;
                int n;
                MENUITEMINFO mii;

                hm = d->hm_kdc_ctx;

                hw_kdc = GetDlgItem(hwnd, IDC_CFG_KDC);
#ifdef DEBUG
                assert(hw_kdc);
#endif
                n = ListView_GetSelectedCount(hw_kdc);
                ZeroMemory(&mii, sizeof(mii));
                mii.cbSize = sizeof(mii);

                if (n == 1) {
                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_ENABLED;

                    SetMenuItemInfo(hm, CMD_DEL_SERVER, FALSE, &mii);
                    SetMenuItemInfo(hm, CMD_MAKE_ADMIN, FALSE, &mii);
                    SetMenuItemInfo(hm, CMD_MAKE_MASTER, FALSE, &mii);
                } else if (n == 0) {

                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_DISABLED;

                    SetMenuItemInfo(hm, CMD_DEL_SERVER, FALSE, &mii);
                    SetMenuItemInfo(hm, CMD_MAKE_ADMIN, FALSE, &mii);
                    SetMenuItemInfo(hm, CMD_MAKE_MASTER,FALSE, &mii);
                } else {

                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_ENABLED;

                    SetMenuItemInfo(hm, CMD_DEL_SERVER, FALSE, &mii);
                    
                    mii.fState = MFS_DISABLED;

                    SetMenuItemInfo(hm, CMD_MAKE_ADMIN, FALSE, &mii);
                    SetMenuItemInfo(hm, CMD_MAKE_MASTER,FALSE, &mii);
                }

            } else if (id == IDC_CFG_DMAP) {
                HWND hw_dmap;
                MENUITEMINFO mii;
                int n;

                hm = d->hm_dmap_ctx;

                hw_dmap = GetDlgItem(hwnd, IDC_CFG_DMAP);
#ifdef DEBUG
                assert(hw_dmap);
#endif

                n = ListView_GetSelectedCount(hw_dmap);
                ZeroMemory(&mii, sizeof(mii));
                mii.cbSize = sizeof(mii);

                if (n == 0) {
                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_DISABLED;

                    SetMenuItemInfo(hm, CMD_DEL_DMAP, FALSE, &mii);
                } else {
                    mii.fMask = MIIM_STATE;
                    mii.fState = MFS_ENABLED;

                    SetMenuItemInfo(hm, CMD_DEL_DMAP, FALSE, &mii);
                }
            }

            if (hm) {
                if (LOWORD(lParam) == 0xffff) {
                    HWND hw;
                    RECT r;

                    hw = GetDlgItem(hwnd, id);
#ifdef DEBUG
                    assert(hw);
#endif
                    GetWindowRect(hw, &r);
                    x = r.left;
                    y = r.top;
                } else {
                    x = LOWORD(lParam);
                    y = HIWORD(lParam);
                }

                TrackPopupMenu(hm,
                               TPM_LEFTALIGN | TPM_TOPALIGN,
                               x, y,
                               0, hwnd, NULL);
            }

            return TRUE;
        }
        break;

    case WM_NOTIFY:
        {
            LPNMHDR pnmh;
            HWND hw_rlm = NULL;
            HWND hw_kdc = NULL;
            HWND hw_dmp = NULL;
            int i;

            pnmh = (LPNMHDR) lParam;

            /* catchalls for all three list views */
            switch (pnmh->code) {
            case NM_DBLCLK:
                {
                    HWND hw_ctl;
                    LVITEM lvi;
                    LVHITTESTINFO hti;
                    LPNMITEMACTIVATE pnmi;

                    if (pnmh->idFrom != IDC_CFG_REALMS &&
                        pnmh->idFrom != IDC_CFG_KDC &&
                        pnmh->idFrom != IDC_CFG_DMAP)
                        break;

                    /* if the user double clicks on the 'new
                       [something]' item, we start editing it. */
                    hw_ctl = pnmh->hwndFrom;
                    pnmi = (LPNMITEMACTIVATE) lParam;

                    ZeroMemory(&hti, sizeof(hti));
                    hti.pt = pnmi->ptAction;

                    ListView_SubItemHitTest(hw_ctl, &hti);
                    if (hti.flags & LVHT_ONITEM) {
                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.mask = LVIF_PARAM;
                        lvi.iItem = hti.iItem;

                        ListView_GetItem(hw_ctl, &lvi);

                        if (lvi.lParam == -1)
                            ListView_EditLabel(hw_ctl, hti.iItem);
                    }

                    return TRUE;
                }
                break;
            }

            if (pnmh->idFrom == IDC_CFG_REALMS) {

                hw_rlm = pnmh->hwndFrom;

                switch(pnmh->code) {
                case LVN_ITEMCHANGED:
                    i = ListView_GetSelectedCount(hw_rlm);
                    hw_kdc = GetDlgItem(hwnd, IDC_CFG_KDC);
                    hw_dmp = GetDlgItem(hwnd, IDC_CFG_DMAP);

                    d->c_realm = (khm_size) -1;

                    if (i == 1) {
                        LVITEM lvi;
                        wchar_t fmt[256];
                        wchar_t buf[K5_MAXCCH_REALM + 256];

                        i = ListView_GetNextItem(hw_rlm, -1,
                                                 LVNI_SELECTED);
                        if (i == -1)
                            goto _no_selection;

                        ZeroMemory(&lvi, sizeof(lvi));

                        lvi.iItem = i;
                        lvi.iSubItem = 0;
                        lvi.mask = LVIF_PARAM;

                        ListView_GetItem(hw_rlm, &lvi);

                        if (lvi.lParam == -1)
                            goto _no_selection;

                        d->c_realm = lvi.lParam;

                        k5_update_kdcs_display(hw_kdc, d, lvi.lParam);
                        k5_update_dmap_display(hw_dmp, d, lvi.lParam);

                        LoadString(hResModule, IDS_CFG_RE_KDCS_R,
                                   fmt, ARRAYLENGTH(fmt));
                        StringCbPrintf(buf, sizeof(buf), fmt,
                                       d->realms[d->c_realm].realm);

                        SetDlgItemText(hwnd, IDC_CFG_SERVERSGRP, buf);

                        LoadString(hResModule, IDS_CFG_RE_DMAPS_R,
                                   fmt, ARRAYLENGTH(fmt));
                        StringCbPrintf(buf, sizeof(buf), fmt,
                                       d->realms[d->c_realm].realm);

                        SetDlgItemText(hwnd, IDC_CFG_DOMAINGRP, buf);
                        return TRUE;
                    }

                _no_selection:
                    {
                        wchar_t buf[256];

                        k5_update_kdcs_display(hw_kdc, NULL, 0);
                        k5_update_dmap_display(hw_dmp, NULL, 0);

                        LoadString(hResModule, IDS_CFG_RE_KDCS,
                                   buf, ARRAYLENGTH(buf));
                        SetDlgItemText(hwnd, IDC_CFG_SERVERSGRP, buf);

                        LoadString(hResModule, IDS_CFG_RE_DMAPS,
                                   buf, ARRAYLENGTH(buf));
                        SetDlgItemText(hwnd, IDC_CFG_DOMAINGRP, buf);
                    }
                    break;

                case LVN_BEGINLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        LVITEM lvi;

                        pdisp = (NMLVDISPINFO *) lParam;

                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.iItem = pdisp->item.iItem;
                        lvi.mask = LVIF_PARAM;

                        ListView_GetItem(hw_rlm, &lvi);

                        if (pdisp->item.iItem == -1 ||
                            lvi.lParam != -1) {
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, TRUE);
                        } else {
                            /* allow editing */
                            HWND hw_edit;

                            hw_edit = ListView_GetEditControl(hw_rlm);
                            if (hw_edit != NULL) {
                                SendMessage(hw_edit,
                                            EM_SETLIMITTEXT,
                                            K5_MAXCCH_REALM - 1,
                                            0);
                            }
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                        }

                        return TRUE;
                    }
                    break;

                case LVN_ENDLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        khm_size n;

                        pdisp = (NMLVDISPINFO *) lParam;

                        if (pdisp->item.pszText && pdisp->item.pszText[0]) {
                            khm_size i;

                            /* first find out whether this is actually
                               a new realm */

                            for (i=0; i < d->n_realms; i++) {
                                if ((d->realms[i].flags & K5_RDFLAG_NEW) &&
                                    (d->realms[i].flags & K5_RDFLAG_DELETED))
                                    continue;

                                if (!_wcsicmp(d->realms[i].realm, pdisp->item.pszText))
                                    break;
                            }

                            if (i < d->n_realms) {
                                khui_alert * alert = NULL;
                                wchar_t buf[KHUI_MAXCCH_MESSAGE];
                                wchar_t fmt[KHUI_MAXCCH_MESSAGE];

                                khui_alert_create_empty(&alert);

                                LoadString(hResModule, IDS_CFG_RE_ARNUT,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText);
                                khui_alert_set_title(alert, buf);

                                LoadString(hResModule, IDS_CFG_RE_ARNUM,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText);
                                khui_alert_set_message(alert, buf);

                                khui_alert_add_command(alert, KHUI_PACTION_CLOSE);
                                khui_alert_set_severity(alert, KHERR_INFO);

                                khui_alert_show_modal(alert);
                                khui_alert_release(alert);

                                return TRUE;
                            }

                            n = d->n_realms;
                            k5_assert_n_realms(d, n+1);
                            StringCbCopy(d->realms[n].realm,
                                         sizeof(d->realms[n].realm),
                                         pdisp->item.pszText);
                            d->realms[n].flags = K5_RDFLAG_NEW;
                            d->n_realms++;

                            d->flags |= K5_CDFLAG_MOD_REALMS;

                            k5_update_realms_display(hw_rlm, d);
                        }

                        return TRUE;
                    }
                    break;

                case LVN_KEYDOWN:
                    {
                        NMLVKEYDOWN * pnmk;

                        pnmk = (NMLVKEYDOWN *) lParam;

                        if (pnmk->wVKey == VK_DELETE) {
                            k5_delete_realms(hwnd, d);
                            return TRUE;
                        }
                    }
                    break;
                }
            } else if (pnmh->idFrom == IDC_CFG_KDC) {
                hw_kdc = pnmh->hwndFrom;

                switch (pnmh->code) {
                case LVN_BEGINLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        LVITEM lvi;

                        pdisp = (NMLVDISPINFO *) lParam;

                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.iItem = pdisp->item.iItem;
                        lvi.mask = LVIF_PARAM;

                        ListView_GetItem(hw_kdc, &lvi);

                        /* Only allow editing if the user is trying to
                           edit the <New server> entry. */
                        if (pdisp->item.iItem == -1 ||
                            lvi.lParam != -1) {
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, TRUE);
                        } else {
                            HWND hw_edit;

                            hw_edit = ListView_GetEditControl(hw_kdc);
                            if (hw_edit != NULL) {
                                SendMessage(hw_edit,
                                            EM_SETLIMITTEXT,
                                            K5_MAXCCH_HOST - 1,
                                            0);
                            }
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                        }
                        return TRUE;
                    }
                    break;

                case LVN_ENDLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        khm_size r;
                        khm_size k;

                        r = d->c_realm;

                        pdisp = (NMLVDISPINFO *) lParam;

                        if (pdisp->item.pszText && pdisp->item.pszText[0]) {

                            /* first of all, check if we already have
                               a KDC by this name... */
                            for (k=0; k < d->realms[r].n_kdcs; k++) {
                                if ((d->realms[r].kdcs[k].flags & K5_RKFLAG_NEW) &&
                                    (d->realms[r].kdcs[k].flags & K5_RKFLAG_DELETED))
                                    continue;

                                if (!_wcsicmp(d->realms[r].kdcs[k].name,
                                             pdisp->item.pszText))
                                    break;
                            }

                            if (k < d->realms[r].n_kdcs) {
                                khui_alert * alert = NULL;
                                wchar_t buf[K5_MAXCCH_HOST + 256];
                                wchar_t fmt[256];

                                khui_alert_create_empty(&alert);

                                LoadString(hResModule, IDS_CFG_RE_ASNUT,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText,
                                               d->realms[r].realm);
                                khui_alert_set_title(alert, buf);

                                LoadString(hResModule, IDS_CFG_RE_ASNUM,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText,
                                               d->realms[r].realm);
                                khui_alert_set_message(alert, buf);

                                khui_alert_set_severity(alert, KHERR_INFO);
                                khui_alert_show_modal(alert);

                                khui_alert_release(alert);

                                SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                                return TRUE;
                            }

                            if (k >= K5_MAX_KDC) {
                                SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                                /* TODO: show a message box saying
                                   there are too many KDC's
                                   already. */
                                return TRUE;
                            }

                            StringCbCopy(d->realms[r].kdcs[k].name,
                                         sizeof(d->realms[0].kdcs[0].name),
                                         pdisp->item.pszText);
                            d->realms[r].kdcs[k].flags = K5_RKFLAG_NEW;
                            d->realms[r].n_kdcs++;

                            k5_update_kdcs_display(hw_kdc, d, d->c_realm);

                            if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                                d->flags |= K5_CDFLAG_MOD_REALMS;
                                d->realms[r].flags |= K5_RDFLAG_MODIFED;
                                k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
                            }
                        }
                        return TRUE;
                    }
                    break;

                case LVN_KEYDOWN:
                    {
                        NMLVKEYDOWN * pnmk;

                        pnmk = (NMLVKEYDOWN *) lParam;

                        if (pnmk->wVKey == VK_DELETE) {
                            k5_delete_servers(hwnd, d);
                        }
                        return TRUE;
                    }
                    break;

                case NM_CLICK:
                    {
                        LPNMITEMACTIVATE lpnmi;
                        LVHITTESTINFO hti;
                        LVITEM lvi;
                        khm_size r;
                        khm_size k;

                        r = d->c_realm;

                        lpnmi = (LPNMITEMACTIVATE) lParam;

                        ZeroMemory(&hti, sizeof(hti));
                        hti.pt = lpnmi->ptAction;
                        ListView_SubItemHitTest(hw_kdc, &hti);

                        if (hti.iSubItem != 0) {

                            ZeroMemory(&lvi, sizeof(lvi));

                            lvi.mask = LVIF_PARAM;
                            lvi.iItem = hti.iItem;
                            ListView_GetItem(hw_kdc, &lvi);

                            if (lvi.lParam < 0 || lvi.lParam >= (int) d->realms[r].n_kdcs)
                                return TRUE;

                            k = lvi.lParam;

                            if (hti.iSubItem == K5_KDCSI_ADMIN) {
                                d->realms[r].kdcs[k].admin = !d->realms[r].kdcs[k].admin;
                                d->realms[r].kdcs[k].flags |= K5_RKFLAG_MOD_ADMIN;
                            } else if (hti.iSubItem == K5_KDCSI_MASTER) {
                                if (d->realms[r].kdcs[k].master) {
                                    d->realms[r].kdcs[k].master = FALSE;
                                    d->realms[r].kdcs[k].flags |= K5_RKFLAG_MOD_MASTER;
                                } else {
                                    khm_size i;

                                    for (i=0; i < d->realms[r].n_kdcs; i++) {
                                        if ((d->realms[r].kdcs[i].flags & K5_RKFLAG_DELETED) &&
                                            (d->realms[r].kdcs[i].flags & K5_RKFLAG_NEW))
                                            continue;
                                        if (d->realms[r].kdcs[i].master) {
                                            d->realms[r].kdcs[i].master = FALSE;
                                            d->realms[r].kdcs[i].flags |= K5_RKFLAG_MOD_MASTER;
                                        }
                                    }

                                    d->realms[r].kdcs[k].master = TRUE;
                                    d->realms[r].kdcs[k].flags |= K5_RKFLAG_MOD_MASTER;
                                }
                            } else {
#ifdef DEBUG
                                assert(FALSE);
#endif
                            }

                            if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                                d->realms[r].flags |= K5_RDFLAG_MODIFED;
                                d->flags |= K5_CDFLAG_MOD_REALMS;
                                k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
                            }

                            k5_update_kdcs_display(hw_kdc, d, r);
                        }
                    }
                    break;
                }
            } else if (pnmh->idFrom == IDC_CFG_DMAP) {
                hw_dmp = pnmh->hwndFrom;

                switch (pnmh->code) {
                case LVN_BEGINLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        LVITEM lvi;

                        pdisp = (NMLVDISPINFO *) lParam;

                        ZeroMemory(&lvi, sizeof(lvi));
                        lvi.iItem = pdisp->item.iItem;
                        lvi.mask = LVIF_PARAM;

                        ListView_GetItem(hw_dmp, &lvi);

                        /* Only allow editing if the user is trying to
                           edit the <New domain mapping> entry. */
                        if (pdisp->item.iItem == -1 ||
                            lvi.lParam != -1) {
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, TRUE);
                        } else {
                            HWND hw_edit;

                            hw_edit = ListView_GetEditControl(hw_dmp);
                            if (hw_edit != NULL) {
                                SendMessage(hw_edit,
                                            EM_SETLIMITTEXT,
                                            K5_MAXCCH_HOST - 1,
                                            0);
                            }
                            SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                        }
                        return TRUE;
                    }
                    break;

                case LVN_ENDLABELEDIT:
                    {
                        NMLVDISPINFO * pdisp;
                        khm_size r;
                        khm_size m;

                        r = d->c_realm;

                        pdisp = (NMLVDISPINFO *) lParam;

                        if (pdisp->item.pszText && pdisp->item.pszText[0]) {

                            /* first check if this is unique */
                            for (m=0; m < d->realms[r].n_domain_maps; m++) {
                                if ((d->realms[r].domain_maps[m].flags & K5_DMFLAG_NEW) &&
                                    (d->realms[r].domain_maps[m].flags & K5_DMFLAG_DELETED))
                                    continue;

                                if (!_wcsicmp(d->realms[r].domain_maps[m].name,
                                              pdisp->item.pszText))
                                    break;
                            }

                            if (m < d->realms[r].n_domain_maps) {
                                khui_alert * alert;
                                wchar_t buf[K5_MAXCCH_HOST + 256];
                                wchar_t fmt[256];

                                khui_alert_create_empty(&alert);

                                LoadString(hResModule, IDS_CFG_RE_DMNUT,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText,
                                               d->realms[r].realm);
                                khui_alert_set_title(alert, buf);

                                LoadString(hResModule, IDS_CFG_RE_DMNUM,
                                           fmt, ARRAYLENGTH(fmt));
                                StringCbPrintf(buf, sizeof(buf), fmt,
                                               pdisp->item.pszText,
                                               d->realms[r].realm);
                                khui_alert_set_message(alert, buf);

                                khui_alert_set_severity(alert, KHERR_INFO);
                                khui_alert_show_modal(alert);

                                khui_alert_release(alert);

                                SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                                return TRUE;
                            }

                            if (m >= K5_MAX_DOMAIN_MAPPINGS) {
                                SetWindowLongPtr(hwnd, DWLP_MSGRESULT, FALSE);
                                /* TODO: show a message box saying
                                   there are too many domain mappings
                                   already. */
                                return TRUE;
                            }

                            StringCbCopy(d->realms[r].domain_maps[m].name,
                                         sizeof(d->realms[0].domain_maps[0].name),
                                         pdisp->item.pszText);
                            d->realms[r].domain_maps[m].flags = K5_DMFLAG_NEW;
                            d->realms[r].n_domain_maps++;

                            k5_update_dmap_display(hw_dmp, d, d->c_realm);

                            if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                                d->flags |= K5_CDFLAG_MOD_REALMS;
                                d->realms[r].flags |= K5_RDFLAG_MODIFED;
                                k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
                            }
                        }
                        return TRUE;
                    }
                    break;

                case LVN_KEYDOWN:
                    {
                        NMLVKEYDOWN * pnmk;

                        pnmk = (NMLVKEYDOWN *) lParam;

                        if (pnmk->wVKey == VK_DELETE) {
                            k5_delete_dmap(hwnd, d);
                            return TRUE;
                        }
                    }
                    break;
                }
            } /* end of handling DMAP notifications */
        }
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam)) {
        case CMD_NEW_REALM:
            {
                ListView_EditLabel(GetDlgItem(hwnd, IDC_CFG_REALMS), 0);

                return TRUE;
            }
            break;

        case CMD_DEL_REALM:
            {
                k5_delete_realms(hwnd, d);

                return TRUE;
            }
            break;

        case CMD_NEW_SERVER:
            {
                ListView_EditLabel(GetDlgItem(hwnd, IDC_CFG_KDC), 0);

                return TRUE;
            }
            break;

        case CMD_DEL_SERVER:
            {
                k5_delete_servers(hwnd, d);

                return TRUE;
            }
            break;

        case CMD_MAKE_ADMIN:
            {
                HWND hw_kdc;
                int idx;
                khm_size r;
                khm_size k;
                BOOL modified = FALSE;

                r = d->c_realm;

                hw_kdc = GetDlgItem(hwnd, IDC_CFG_KDC);

                if (ListView_GetSelectedCount(hw_kdc) != 1)
                    return TRUE;
                
                idx = -1;
                while ((idx = ListView_GetNextItem(hw_kdc, idx,
                                                   LVNI_SELECTED)) != -1) {
                    LVITEM lvi;

                    ZeroMemory(&lvi, sizeof(lvi));

                    lvi.mask = LVIF_PARAM;
                    lvi.iItem = idx;
                    ListView_GetItem(hw_kdc, &lvi);

                    k = lvi.lParam;

                    if (lvi.lParam >= 0 && lvi.lParam < (int) d->realms[r].n_kdcs) {
                        d->realms[r].kdcs[k].admin = !d->realms[r].kdcs[k].admin;
                        d->realms[r].kdcs[k].flags |= K5_RKFLAG_MOD_ADMIN;
                        modified = TRUE;

                        break;
                    }
                }

                if (modified) {
                    if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                        d->flags |= K5_CDFLAG_MOD_REALMS;
                        d->realms[r].flags |= K5_RDFLAG_MODIFED;
                        k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
                    }
                }

                k5_update_kdcs_display(hw_kdc, d, r);

                return TRUE;
            }
            break;

        case CMD_MAKE_MASTER:
            {
                HWND hw_kdc;
                int idx;
                khm_size r;
                khm_size k;
                BOOL modified = FALSE;

                r = d->c_realm;

                hw_kdc = GetDlgItem(hwnd, IDC_CFG_KDC);

                if (ListView_GetSelectedCount(hw_kdc) != 1)
                    return TRUE;
                
                idx = -1;
                while ((idx = ListView_GetNextItem(hw_kdc, idx,
                                                   LVNI_SELECTED)) != -1) {
                    LVITEM lvi;

                    ZeroMemory(&lvi, sizeof(lvi));

                    lvi.mask = LVIF_PARAM;
                    lvi.iItem = idx;
                    ListView_GetItem(hw_kdc, &lvi);

                    k = lvi.lParam;

                    if (lvi.lParam >= 0 && lvi.lParam < (int) d->realms[r].n_kdcs) {
                        if (d->realms[r].kdcs[k].master) {
                            d->realms[r].kdcs[k].master = FALSE;
                        } else {
                            khm_size i;

                            for (i=0; i < d->realms[r].n_kdcs; i++) {
                                if ((d->realms[r].kdcs[i].flags & K5_RKFLAG_NEW) &&
                                    (d->realms[r].kdcs[i].flags & K5_RKFLAG_DELETED))
                                    continue;

                                if (d->realms[r].kdcs[i].master) {
                                    d->realms[r].kdcs[i].master = FALSE;
                                    d->realms[r].kdcs[i].flags |= K5_RKFLAG_MOD_MASTER;
                                }
                            }

                            d->realms[r].kdcs[k].master = TRUE;
                        }
                        d->realms[r].kdcs[k].flags |= K5_RKFLAG_MOD_MASTER;
                        modified = TRUE;

                        break;
                    }
                }

                if (modified) {
                    if (!(d->realms[r].flags & K5_RDFLAG_MODIFED)) {
                        d->flags |= K5_CDFLAG_MOD_REALMS;
                        d->realms[r].flags |= K5_RDFLAG_MODIFED;
                        k5_update_realms_display(hwnd, d);
                    }
                }

                k5_update_kdcs_display(hw_kdc, d, r);

                return TRUE;
            }
            break;

        case CMD_NEW_DMAP:
            {
                ListView_EditLabel(GetDlgItem(hwnd, IDC_CFG_DMAP), 0);

                return TRUE;
            }
            break;

        case CMD_DEL_DMAP:
            {
                k5_delete_dmap(hwnd, d);

                return TRUE;
            }
            break;
        }
        break;

    case WM_DESTROY:
        if (d->hm_realms_ctx)
            DestroyMenu(d->hm_realms_ctx);
        if (d->hm_kdc_ctx)
            DestroyMenu(d->hm_kdc_ctx);
        if (d->hm_dmap_ctx)
            DestroyMenu(d->hm_dmap_ctx);

        d->hm_realms_ctx = NULL;
        d->hm_kdc_ctx = NULL;
        d->hm_dmap_ctx = NULL;
        break;

    case KHUI_WM_CFG_NOTIFY:
        /* the realms dialog receives this notification after the top
           level krb5 configuration panel has received it. */
        if (HIWORD(wParam) == WMCFG_APPLY) {
            int applied;

            applied = k5_write_config_data(d);
            k5_purge_config_data(d, TRUE, TRUE, TRUE);
            k5_update_realms_display(GetDlgItem(hwnd, IDC_CFG_REALMS), d);
            if (d->c_realm != -1) {
                k5_update_kdcs_display(GetDlgItem(hwnd, IDC_CFG_KDC), d, d->c_realm);
                k5_update_dmap_display(GetDlgItem(hwnd, IDC_CFG_DMAP), d, d->c_realm);
            } else {
                k5_update_kdcs_display(GetDlgItem(hwnd, IDC_CFG_KDC), NULL, 0);
                k5_update_dmap_display(GetDlgItem(hwnd, IDC_CFG_DMAP), NULL, 0);
            }
            khui_cfg_set_flags(d->node_realm,
                               (applied ? KHUI_CNFLAG_APPLIED : 0),
                               KHUI_CNFLAG_APPLIED);

        }
        break;
    }
    return FALSE;
}

void
k5_register_config_panels(void) {
    khui_config_node node;
    khui_config_node_reg reg;
    wchar_t wshort[KHUI_MAXCCH_SHORT_DESC];
    wchar_t wlong[KHUI_MAXCCH_LONG_DESC];

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"Kerberos5";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CONFIG);
    reg.dlg_proc = k5_config_dlgproc;
    reg.flags = 0;

    khui_cfg_register(NULL, &reg);

    if (KHM_FAILED(khui_cfg_open(NULL, L"Kerberos5", &node))) {
        node = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5RLM_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5RLM_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosRealms";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_REALMS);
    reg.dlg_proc = k5_realms_dlgproc;
    reg.flags = 0;

    khui_cfg_register(node, &reg);

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CCC_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CCC_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosCCaches";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_CACHES);
    reg.dlg_proc = k5_ccconfig_dlgproc;
    reg.flags = 0;

    khui_cfg_register(node, &reg);

    khui_cfg_release(node);

    if (KHM_FAILED(khui_cfg_open(NULL, L"KhmIdentities", &node))) {
        node = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_IDS_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_IDS_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosIdentities";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_IDS_TAB);
    reg.dlg_proc = k5_ids_tab_dlgproc;
    reg.flags = KHUI_CNFLAG_SUBPANEL;

    khui_cfg_register(node, &reg);

    ZeroMemory(&reg, sizeof(reg));

    LoadString(hResModule, IDS_K5CFG_ID_SHORT_DESC,
               wshort, ARRAYLENGTH(wshort));
    LoadString(hResModule, IDS_K5CFG_ID_LONG_DESC,
               wlong, ARRAYLENGTH(wlong));

    reg.name = L"KerberosIdentitiesPlural";
    reg.short_desc = wshort;
    reg.long_desc = wlong;
    reg.h_module = hResModule;
    reg.dlg_template = MAKEINTRESOURCE(IDD_CFG_ID_TAB);
    reg.dlg_proc = k5_id_tab_dlgproc;
    reg.flags = KHUI_CNFLAG_SUBPANEL | KHUI_CNFLAG_PLURAL;

    khui_cfg_register(node, &reg);

    khui_cfg_release(node);
}

void
k5_unregister_config_panels(void) {
    khui_config_node node_main;
    khui_config_node node_realms;
    khui_config_node node_ids;
    khui_config_node node_tab;
    khui_config_node node_ccaches;

    if (KHM_FAILED(khui_cfg_open(NULL, L"Kerberos5", &node_main))) {
        node_main = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (KHM_SUCCEEDED(khui_cfg_open(node_main, L"KerberosRealms", 
                                    &node_realms))) {
        khui_cfg_remove(node_realms);
        khui_cfg_release(node_realms);
    } else {
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (KHM_SUCCEEDED(khui_cfg_open(node_main, L"KerberosCCaches",
                                    &node_ccaches))) {
        khui_cfg_remove(node_ccaches);
        khui_cfg_release(node_ccaches);
    }
#ifdef DEBUG
    else
        assert(FALSE);
#endif

    if (node_main) {
        khui_cfg_remove(node_main);
        khui_cfg_release(node_main);
    }

    if (KHM_FAILED(khui_cfg_open(NULL, L"KhmIdentities", &node_ids))) {
        node_ids = NULL;
#ifdef DEBUG
        assert(FALSE);
#endif
    }

    if (KHM_SUCCEEDED(khui_cfg_open(node_ids, L"KerberosIdentities", &node_tab))) {
        khui_cfg_remove(node_tab);
        khui_cfg_release(node_tab);
    }
    if (KHM_SUCCEEDED(khui_cfg_open(node_ids, L"KerberosIdentitiesPlural", &node_tab))) {
        khui_cfg_remove(node_tab);
        khui_cfg_release(node_tab);
    }

    if (node_ids)
        khui_cfg_release(node_ids);
}

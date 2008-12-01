#include "ktest.h"
#include "utility.h"
#include <stdlib.h>

char *sample_principal_name = "hftsai/extra@ATHENA.MIT.EDU";

krb5_error_code ktest_make_sample_authenticator(a)
    krb5_authenticator * a;
{
    krb5_error_code retval;

    retval = ktest_make_sample_principal(&(a->client));
    if (retval) return retval;
    a->checksum = (krb5_checksum*)calloc(1,sizeof(krb5_checksum));
    if (a->checksum == NULL) return ENOMEM;
    retval = ktest_make_sample_checksum(a->checksum);
    if (retval) return retval;
    a->cusec = SAMPLE_USEC;
    a->ctime = SAMPLE_TIME;
    a->subkey = (krb5_keyblock*)calloc(1,sizeof(krb5_keyblock));
    if (a->subkey == NULL) return ENOMEM;
    retval = ktest_make_sample_keyblock(a->subkey);
    if (retval) return retval;
    a->seq_number = SAMPLE_SEQ_NUMBER;
    retval = ktest_make_sample_authorization_data(&(a->authorization_data));
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_principal(p)
    krb5_principal * p;
{
    krb5_error_code retval;

    retval = krb5_parse_name(test_context, sample_principal_name, p);
    return retval;
}

krb5_error_code ktest_make_sample_checksum(cs)
    krb5_checksum * cs;
{
    cs->checksum_type = 1;
    cs->length = 4;
    cs->contents = (krb5_octet*)calloc(4,sizeof(krb5_octet));
    if (cs->contents == NULL) return ENOMEM;
    memcpy(cs->contents,"1234",4);

    return 0;
}

krb5_error_code ktest_make_sample_keyblock(kb)
    krb5_keyblock * kb;
{
    kb->magic = KV5M_KEYBLOCK;
    kb->enctype = 1;
    kb->length = 8;
    kb->contents = (krb5_octet*)calloc(8,sizeof(krb5_octet));
    if (kb->contents == NULL) return ENOMEM;
    memcpy(kb->contents,"12345678",8);

    return 0;
}

krb5_error_code ktest_make_sample_ticket(tkt)
    krb5_ticket * tkt;
{
    krb5_error_code retval;

    retval = ktest_make_sample_principal(&(tkt->server));
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(tkt->enc_part));
    if (retval) return retval;
    tkt->enc_part2 = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_enc_data(ed)
    krb5_enc_data * ed;
{
    krb5_error_code retval;

    ed->kvno = 5;
    ed->enctype = 0;
    retval = krb5_data_parse(&(ed->ciphertext),"krbASN.1 test message");
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_enc_tkt_part(etp)
    krb5_enc_tkt_part * etp;
{
    krb5_error_code retval;

    etp->flags = SAMPLE_FLAGS;
    etp->session = (krb5_keyblock*)calloc(1,sizeof(krb5_keyblock));
    if (etp->session == NULL) return ENOMEM;
    retval = ktest_make_sample_keyblock(etp->session);
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(etp->client));
    if (retval) return retval;
    retval = ktest_make_sample_transited(&(etp->transited));
    if (retval) return retval;
    retval = ktest_make_sample_ticket_times(&(etp->times));
    if (retval) return retval;
    retval = ktest_make_sample_addresses(&(etp->caddrs));
    if (retval) return retval;
    retval = ktest_make_sample_authorization_data(&(etp->authorization_data));
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_addresses(caddrs)
    krb5_address *** caddrs;
{
    asn1_error_code retval;
    int i;

    *caddrs = (krb5_address**)calloc(3,sizeof(krb5_address*));
    if (*caddrs == NULL) return ENOMEM;
    for (i=0; i<2; i++) {
	(*caddrs)[i] = (krb5_address*)calloc(1,sizeof(krb5_address));
	if ((*caddrs)[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_address((*caddrs)[i]);
	if (retval) return retval;
    }
    (*caddrs)[2] = NULL;
    return 0;
}

krb5_error_code ktest_make_sample_authorization_data(ad)
    krb5_authdata *** ad;
{
    krb5_error_code retval;
    int i;

    *ad = (krb5_authdata**)calloc(3,sizeof(krb5_authdata*));
    if (*ad == NULL) return ENOMEM;

    for (i=0; i<=1; i++) {
	(*ad)[i] = (krb5_authdata*)calloc(1,sizeof(krb5_authdata));
	if ((*ad)[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_authdata((*ad)[i]);
	if (retval) return retval;
    }
    (*ad)[2] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_transited(t)
    krb5_transited * t;
{
    t->tr_type = 1;
    return krb5_data_parse(&(t->tr_contents),
			   "EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.");
}

krb5_error_code ktest_make_sample_ticket_times(tt)
    krb5_ticket_times * tt;
{
    tt->authtime = SAMPLE_TIME;
    tt->starttime = SAMPLE_TIME;
    tt->endtime = SAMPLE_TIME;
    tt->renew_till = SAMPLE_TIME;
    return 0;
}

krb5_error_code ktest_make_sample_address(a)
    krb5_address * a;
{
    a->addrtype = ADDRTYPE_INET;
    a->length = 4;
    a->contents = (krb5_octet*)calloc(4,sizeof(krb5_octet));
    if (a->contents == NULL) return ENOMEM;
    a->contents[0] = 18;
    a->contents[1] = 208;
    a->contents[2] = 0;
    a->contents[3] = 35;

    return 0;
}

krb5_error_code ktest_make_sample_authdata(ad)
    krb5_authdata * ad;
{
    ad->ad_type = 1;
    ad->length = 6;
    ad->contents = (krb5_octet*)calloc(6,sizeof(krb5_octet));
    if (ad->contents == NULL) return ENOMEM;
    memcpy(ad->contents,"foobar",6);
    return 0;
}

krb5_error_code ktest_make_sample_enc_kdc_rep_part(ekr)
    krb5_enc_kdc_rep_part * ekr;
{
    krb5_error_code retval;

    ekr->session = (krb5_keyblock*)calloc(1,sizeof(krb5_keyblock));
    if (ekr->session == NULL) return ENOMEM;
    retval = ktest_make_sample_keyblock(ekr->session);
    if (retval) return retval;
    retval = ktest_make_sample_last_req(&(ekr->last_req));
    if (retval) return retval;
    ekr->nonce = SAMPLE_NONCE;
    ekr->key_exp = SAMPLE_TIME;
    ekr->flags = SAMPLE_FLAGS;
    ekr->times.authtime = SAMPLE_TIME;
    ekr->times.starttime = SAMPLE_TIME;
    ekr->times.endtime = SAMPLE_TIME;
    ekr->times.renew_till = SAMPLE_TIME;
    retval = ktest_make_sample_principal(&(ekr->server));
    if (retval) return retval;
    retval = ktest_make_sample_addresses(&(ekr->caddrs));
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_last_req(lr)
    krb5_last_req_entry *** lr;
{
    krb5_error_code retval;
    int i;

    *lr = (krb5_last_req_entry**)calloc(3,sizeof(krb5_last_req_entry*));
    if (*lr == NULL) return ENOMEM;
    for (i=0; i<=1; i++) {
	retval = ktest_make_sample_last_req_entry(&((*lr)[i]));
	if (retval) return retval;
    }
    (*lr)[2] = NULL;
    return 0;
}

krb5_error_code ktest_make_sample_last_req_entry(lre)
    krb5_last_req_entry ** lre;
{
    *lre = (krb5_last_req_entry*)calloc(1,sizeof(krb5_last_req_entry));
    if (*lre == NULL) return ENOMEM;
    (*lre)->lr_type = -5;
    (*lre)->value = SAMPLE_TIME;
    return 0;
}

krb5_error_code ktest_make_sample_kdc_rep(kdcr)
    krb5_kdc_rep * kdcr;
{
    krb5_error_code retval;

    retval = ktest_make_sample_pa_data_array(&(kdcr->padata));
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(kdcr->client));
    if (retval) return retval;
    kdcr->ticket = (krb5_ticket*)calloc(1,sizeof(krb5_ticket));
    if (kdcr->ticket == NULL) return ENOMEM;
    retval = ktest_make_sample_ticket(kdcr->ticket);
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(kdcr->enc_part));
    if (retval) return retval;
    kdcr->enc_part2 = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_pa_data_array(pad)
    krb5_pa_data *** pad;
{
    krb5_error_code retval;
    int i;

    *pad = (krb5_pa_data**)calloc(3,sizeof(krb5_pa_data*));
    if (*pad == NULL) return ENOMEM;

    for (i=0; i<=1; i++) {
	(*pad)[i] = (krb5_pa_data*)calloc(1,sizeof(krb5_pa_data));
	if ((*pad)[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_pa_data((*pad)[i]);
	if (retval) return retval;
    }
    (*pad)[2] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_empty_pa_data_array(pad)
    krb5_pa_data *** pad;
{
    *pad = (krb5_pa_data**)calloc(1,sizeof(krb5_pa_data*));
    if (*pad == NULL) return ENOMEM;

    (*pad)[0] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_pa_data(pad)
    krb5_pa_data * pad;
{
    pad->pa_type = 13;
    pad->length = 7;
    pad->contents = (krb5_octet*)calloc(7,sizeof(krb5_octet));
    if (pad->contents == NULL) return ENOMEM;
    memcpy(pad->contents,"pa-data",7);
    return 0;
}

krb5_error_code ktest_make_sample_ap_req(ar)
    krb5_ap_req * ar;
{
    krb5_error_code retval;
    ar->ap_options = SAMPLE_FLAGS;
    ar->ticket = (krb5_ticket*)calloc(1,sizeof(krb5_ticket));
    if (ar->ticket == NULL) return ENOMEM;
    retval = ktest_make_sample_ticket(ar->ticket);
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(ar->authenticator));
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_ap_rep(ar)
    krb5_ap_rep * ar;
{
    return ktest_make_sample_enc_data(&(ar->enc_part));
}

krb5_error_code ktest_make_sample_ap_rep_enc_part(arep)
    krb5_ap_rep_enc_part * arep;
{
    krb5_error_code retval;

    arep->ctime = SAMPLE_TIME;
    arep->cusec = SAMPLE_USEC;
    arep->subkey = (krb5_keyblock*)calloc(1,sizeof(krb5_keyblock));
    if (arep->subkey == NULL) return ENOMEM;
    retval = ktest_make_sample_keyblock(arep->subkey);
    if (retval) return retval;
    arep->seq_number = SAMPLE_SEQ_NUMBER;

    return 0;
}

krb5_error_code ktest_make_sample_kdc_req(kr)
    krb5_kdc_req * kr;
{
    krb5_error_code retval;

    /* msg_type is left up to the calling procedure */
    retval = ktest_make_sample_pa_data_array(&(kr->padata));
    if (retval) return retval;
    kr->kdc_options = SAMPLE_FLAGS;
    retval = ktest_make_sample_principal(&(kr->client));
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(kr->server));
    if (retval) return retval;
    kr->from = SAMPLE_TIME;
    kr->till = SAMPLE_TIME;
    kr->rtime = SAMPLE_TIME;
    kr->nonce = SAMPLE_NONCE;
    kr->nktypes = 2;
    kr->ktype = (krb5_enctype*)calloc(2,sizeof(krb5_enctype));
    kr->ktype[0] = 0;
    kr->ktype[1] = 1;
    retval = ktest_make_sample_addresses(&(kr->addresses));
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(kr->authorization_data));
    if (retval) return retval;
    retval = ktest_make_sample_authorization_data(&(kr->unenc_authdata));
    if (retval) return retval;
    retval = ktest_make_sample_sequence_of_ticket(&(kr->second_ticket));
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_kdc_req_body(krb)
    krb5_kdc_req * krb;
{
    krb5_error_code retval;

    krb->kdc_options = SAMPLE_FLAGS;
    retval = ktest_make_sample_principal(&(krb->client));
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(krb->server));
    if (retval) return retval;
    krb->from = SAMPLE_TIME;
    krb->till = SAMPLE_TIME;
    krb->rtime = SAMPLE_TIME;
    krb->nonce = SAMPLE_NONCE;
    krb->nktypes = 2;
    krb->ktype = (krb5_enctype*)calloc(2,sizeof(krb5_enctype));
    krb->ktype[0] = 0;
    krb->ktype[1] = 1;
    retval = ktest_make_sample_addresses(&(krb->addresses));
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(krb->authorization_data));
    if (retval) return retval;
    retval = ktest_make_sample_authorization_data(&(krb->unenc_authdata));
    if (retval) return retval;
    retval = ktest_make_sample_sequence_of_ticket(&(krb->second_ticket));
    if (retval) return retval;
    return 0;
}
  
krb5_error_code ktest_make_sample_safe(s)
    krb5_safe * s;
{
    krb5_error_code retval;

    retval = ktest_make_sample_data(&(s->user_data));
    if (retval) return retval;
    s->timestamp = SAMPLE_TIME;
    s->usec = SAMPLE_USEC;
    s->seq_number = SAMPLE_SEQ_NUMBER;
    s->s_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (s->s_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(s->s_address);
    if (retval) return retval;
    s->r_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (s->r_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(s->r_address);
    if (retval) return retval;
    s->checksum = (krb5_checksum*)calloc(1,sizeof(krb5_checksum));
    if (s->checksum == NULL) return ENOMEM;
    retval = ktest_make_sample_checksum(s->checksum);
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_priv(p)
    krb5_priv * p;
{
    return ktest_make_sample_enc_data(&(p->enc_part));
}

krb5_error_code ktest_make_sample_priv_enc_part(pep)
    krb5_priv_enc_part * pep;
{
    krb5_error_code retval;
    retval = ktest_make_sample_data(&(pep->user_data));
    if (retval) return retval;
    pep->timestamp = SAMPLE_TIME;
    pep->usec = SAMPLE_USEC;
    pep->seq_number = SAMPLE_SEQ_NUMBER;
    pep->s_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (pep->s_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(pep->s_address);
    if (retval) return retval;
    pep->r_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (pep->r_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(pep->r_address);
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_cred(c)
    krb5_cred * c;
{
    krb5_error_code retval;
    retval = ktest_make_sample_sequence_of_ticket(&(c->tickets));
    if (retval) return retval;
    retval = ktest_make_sample_enc_data(&(c->enc_part));
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_sequence_of_ticket(sot)
    krb5_ticket *** sot;
{
    krb5_error_code retval;
    int i;

    *sot = (krb5_ticket**)calloc(3,sizeof(krb5_ticket*));
    if (*sot == NULL) return ENOMEM;
    for (i=0; i<2; i++) {
	(*sot)[i] = (krb5_ticket*)calloc(1,sizeof(krb5_ticket));
	if ((*sot)[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_ticket((*sot)[i]);
	if (retval) return retval;
    }
    (*sot)[2] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_cred_enc_part(cep)
    krb5_cred_enc_part * cep;
{
    krb5_error_code retval;

    cep->nonce = SAMPLE_NONCE;
    cep->timestamp = SAMPLE_TIME;
    cep->usec = SAMPLE_USEC;
    cep->s_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (cep->s_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(cep->s_address);
    if (retval) return retval;
    cep->r_address = (krb5_address*)calloc(1,sizeof(krb5_address));
    if (cep->r_address == NULL) return ENOMEM;
    retval = ktest_make_sample_address(cep->r_address);
    if (retval) return retval;
    retval = ktest_make_sequence_of_cred_info(&(cep->ticket_info));
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sequence_of_cred_info(soci)
    krb5_cred_info *** soci;
{
    krb5_error_code retval;
    int i;

    *soci = (krb5_cred_info**)calloc(3,sizeof(krb5_cred_info*));
    if (*soci == NULL) return ENOMEM;
    for (i=0; i<2; i++) {
	(*soci)[i] = (krb5_cred_info*)calloc(1,sizeof(krb5_cred_info));
	if ((*soci)[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_cred_info((*soci)[i]);
	if (retval) return retval;
    }
    (*soci)[2] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_cred_info(ci)
    krb5_cred_info * ci;
{
    krb5_error_code retval;

    ci->session = (krb5_keyblock*)calloc(1,sizeof(krb5_keyblock));
    if (ci->session == NULL) return ENOMEM;
    retval = ktest_make_sample_keyblock(ci->session);
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(ci->client));
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(ci->server));
    if (retval) return retval;
    ci->flags = SAMPLE_FLAGS;
    ci->times.authtime = SAMPLE_TIME;
    ci->times.starttime = SAMPLE_TIME;
    ci->times.endtime = SAMPLE_TIME;
    ci->times.renew_till = SAMPLE_TIME;
    retval = ktest_make_sample_addresses(&(ci->caddrs));
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_error(kerr)
    krb5_error * kerr;
{
    krb5_error_code retval;

    kerr->ctime = SAMPLE_TIME;
    kerr->cusec = SAMPLE_USEC;
    kerr->susec = SAMPLE_USEC;
    kerr->stime = SAMPLE_TIME;
    kerr->error = SAMPLE_ERROR;
    retval = ktest_make_sample_principal(&(kerr->client));
    if (retval) return retval;
    retval = ktest_make_sample_principal(&(kerr->server));
    if (retval) return retval;
    retval = ktest_make_sample_data(&(kerr->text));
    if (retval) return retval;
    retval = ktest_make_sample_data(&(kerr->e_data));
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_data(d)
    krb5_data * d;
{
    d->data = (char*)calloc(8,sizeof(char));
    if (d->data == NULL) return ENOMEM;
    d->length = 8;
    memcpy(d->data,"krb5data",8);

    return 0;
}

krb5_error_code ktest_make_sample_passwd_phrase_element(ppe)
    passwd_phrase_element * ppe;
{
    krb5_error_code retval;

    ppe->passwd = (krb5_data*)calloc(1,sizeof(krb5_data));
    if (ppe->passwd == NULL) return ENOMEM;
    retval = ktest_make_sample_data(ppe->passwd);
    if (retval) return retval;
    ppe->phrase = (krb5_data*)calloc(1,sizeof(krb5_data));
    if (ppe->phrase == NULL) return ENOMEM;
    retval = ktest_make_sample_data(ppe->phrase);
    if (retval) return retval;
    return 0;
}

krb5_error_code ktest_make_sample_krb5_pwd_data(pd)
    krb5_pwd_data * pd;
{
    krb5_error_code retval;
    int i;

    pd->sequence_count = 2;

    pd->element = (passwd_phrase_element**)calloc(3,sizeof(passwd_phrase_element*));
    if (pd->element == NULL) return ENOMEM;

    for (i=0; i<=1; i++) {
	pd->element[i] = (passwd_phrase_element*)calloc(1,sizeof(passwd_phrase_element));
	if (pd->element[i] == NULL) return ENOMEM;
	retval = ktest_make_sample_passwd_phrase_element(pd->element[i]);
	if (retval) return retval;
    }
    pd->element[2] = NULL;

    return 0;
}

krb5_error_code ktest_make_sample_alt_method(p)
    krb5_alt_method * p;
{
    p->method = 42;
    p->data = (krb5_octet *) strdup("secret");
    if (p->data == NULL) return ENOMEM;
    p->length = strlen((char *) p->data);
    return 0;
}

krb5_error_code ktest_make_sample_etype_info(p)
    krb5_etype_info_entry *** p;
{
    krb5_etype_info_entry **info;
    int	i, len;
    char *str;

    info = malloc(sizeof(krb5_etype_info_entry *) * 4);
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(krb5_etype_info_entry *) * 4);

    for (i=0; i < 3; i++) {
	info[i] = malloc(sizeof(krb5_etype_info_entry));
	if (info[i] == 0)
	    goto memfail;
	info[i]->etype = i;
	len = asprintf(&str, "Morton's #%d", i);
	if (len < 0)
	    goto memfail;
	info[i]->salt = (krb5_octet *) str;
	info[i]->length = len;
	info[i]->s2kparams.data = NULL;
	info[i]->s2kparams.length = 0;
	info[i]->magic = KV5M_ETYPE_INFO_ENTRY;
    }
    free(info[1]->salt);
    info[1]->length = KRB5_ETYPE_NO_SALT;
    info[1]->salt = 0;
    *p = info;
    return 0;
memfail:
    ktest_destroy_etype_info(info);
    return ENOMEM;
}


krb5_error_code ktest_make_sample_etype_info2(p)
    krb5_etype_info_entry *** p;
{
    krb5_etype_info_entry **info;
    int	i, len;
    char *str;

    info = malloc(sizeof(krb5_etype_info_entry *) * 4);
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(krb5_etype_info_entry *) * 4);

    for (i=0; i < 3; i++) {
	info[i] = malloc(sizeof(krb5_etype_info_entry));
	if (info[i] == 0)
	    goto memfail;
	info[i]->etype = i;
	len = asprintf(&str, "Morton's #%d", i);
	if (len < 0)
	    goto memfail;
	info[i]->salt = (krb5_octet *) str;
	info[i]->length = (unsigned int) len;
	len = asprintf(&info[i]->s2kparams.data, "s2k: %d", i);
	if (len < 0)
	    goto memfail;
	info[i]->s2kparams.length = (unsigned int) len;
	info[i]->magic = KV5M_ETYPE_INFO_ENTRY;
    }
    free(info[1]->salt);
    info[1]->length = KRB5_ETYPE_NO_SALT;
    info[1]->salt = 0;
    *p = info;
    return 0;
memfail:
    ktest_destroy_etype_info(info);
    return ENOMEM;
}


krb5_error_code ktest_make_sample_pa_enc_ts(pa_enc)
    krb5_pa_enc_ts * pa_enc;
{
    pa_enc->patimestamp = SAMPLE_TIME;
    pa_enc->pausec = SAMPLE_USEC;

    return 0;
}

krb5_error_code ktest_make_sample_sam_challenge(p)
    krb5_sam_challenge * p;
{
    krb5_error_code retval;

    p->magic = KV5M_SAM_CHALLENGE;
    p->sam_type = 42; /* information */
    p->sam_flags = KRB5_SAM_USE_SAD_AS_KEY; /* KRB5_SAM_* values */
    p->sam_type_name.data = strdup("type name");
    if (p->sam_type_name.data == NULL) return ENOMEM;
    p->sam_type_name.length = strlen(p->sam_type_name.data);
    p->sam_track_id.data = 0;
    p->sam_track_id.length = 0;
    p->sam_challenge_label.data = strdup("challenge label");
    if (p->sam_challenge_label.data == NULL) return ENOMEM;
    p->sam_challenge_label.length = strlen(p->sam_challenge_label.data);
    p->sam_challenge.data = strdup("challenge ipse");
    if (p->sam_challenge.data == NULL) return ENOMEM;
    p->sam_challenge.length = strlen(p->sam_challenge.data);
    p->sam_response_prompt.data = strdup("response_prompt ipse");
    if (p->sam_response_prompt.data == NULL) return ENOMEM;
    p->sam_response_prompt.length = strlen(p->sam_response_prompt.data);
    p->sam_pk_for_sad.data = 0;
    p->sam_pk_for_sad.length = 0;
    p->sam_nonce = 0x543210;
    retval = ktest_make_sample_checksum(&p->sam_cksum);
    if (retval) return retval;

    return 0;
}

krb5_error_code ktest_make_sample_sam_response(p)
    krb5_sam_response * p;
{
    p->magic = KV5M_SAM_RESPONSE;
    p->sam_type = 42; /* information */
    p->sam_flags = KRB5_SAM_USE_SAD_AS_KEY; /* KRB5_SAM_* values */
    p->sam_track_id.data = strdup("track data");
    if (p->sam_track_id.data == NULL) return ENOMEM;
    p->sam_track_id.length = strlen(p->sam_track_id.data);
    p->sam_enc_key.ciphertext.data = strdup("key");
    if (p->sam_enc_key.ciphertext.data == NULL) return ENOMEM;
    p->sam_enc_key.ciphertext.length = strlen(p->sam_enc_key.ciphertext.data);
    p->sam_enc_key.enctype = ENCTYPE_DES_CBC_CRC;
    p->sam_enc_key.kvno = 1942;
    p->sam_enc_nonce_or_ts.ciphertext.data = strdup("nonce or ts");
    if (p->sam_enc_nonce_or_ts.ciphertext.data == NULL) return ENOMEM;
    p->sam_enc_nonce_or_ts.ciphertext.length = 
	strlen(p->sam_enc_nonce_or_ts.ciphertext.data);
    p->sam_enc_nonce_or_ts.enctype = ENCTYPE_DES_CBC_CRC;
    p->sam_enc_nonce_or_ts.kvno = 3382;
    p->sam_nonce = 0x543210;
    p->sam_patimestamp = SAMPLE_TIME;

    return 0;
}
krb5_error_code ktest_make_sample_sam_response_2(p)
    krb5_sam_response_2 * p;
{
    p->magic = KV5M_SAM_RESPONSE;
    p->sam_type = 43; /* information */
    p->sam_flags = KRB5_SAM_USE_SAD_AS_KEY; /* KRB5_SAM_* values */
    p->sam_track_id.data = strdup("track data");
    if (p->sam_track_id.data == NULL) return ENOMEM;
    p->sam_track_id.length = strlen(p->sam_track_id.data);
    p->sam_enc_nonce_or_sad.ciphertext.data = strdup("nonce or sad");
    if (p->sam_enc_nonce_or_sad.ciphertext.data == NULL) return ENOMEM;
    p->sam_enc_nonce_or_sad.ciphertext.length = 
	strlen(p->sam_enc_nonce_or_sad.ciphertext.data);
    p->sam_enc_nonce_or_sad.enctype = ENCTYPE_DES_CBC_CRC;
    p->sam_enc_nonce_or_sad.kvno = 3382;
    p->sam_nonce = 0x543210;

    return 0;
}

krb5_error_code ktest_make_sample_sam_key(p)
    krb5_sam_key *p;
{
    p->magic = 99;
    return ktest_make_sample_keyblock(&p->sam_key);
}

krb5_error_code ktest_make_sample_enc_sam_response_enc(p)
    krb5_enc_sam_response_enc *p;
{
    p->magic = 78;
    p->sam_nonce = 78634;
    p->sam_timestamp = 99999;
    p->sam_usec = 399;
    p->sam_sad.data = strdup("enc_sam_response_enc");
    if (p->sam_sad.data == NULL) return ENOMEM;
    p->sam_sad.length = strlen(p->sam_sad.data);
    return 0;
}

krb5_error_code ktest_make_sample_enc_sam_response_enc_2(p)
    krb5_enc_sam_response_enc_2 *p;
{
    p->magic = 83;
    p->sam_nonce = 88;
    p->sam_sad.data = strdup("enc_sam_response_enc_2");
    if (p->sam_sad.data == NULL) return ENOMEM;
    p->sam_sad.length = strlen(p->sam_sad.data);
    return 0;
}

#ifdef ENABLE_LDAP
static krb5_error_code ktest_make_sample_key_data(krb5_key_data *p, int i)
{
    char *str;
    int len;
    p->key_data_ver = 2;
    p->key_data_kvno = 42;
    len = asprintf(&str, "key%d", i);
    p->key_data_type[0] = 2;
    p->key_data_length[0] = (unsigned int) len;
    p->key_data_contents[0] = (krb5_octet *) str;
    len = asprintf(&str, "salt%d", i);
    p->key_data_type[1] = i;
    p->key_data_length[1] = (unsigned int) len;
    p->key_data_contents[1] = (krb5_octet *) str;
    if (p->key_data_contents[0] == NULL || p->key_data_contents[1] == NULL)
	return ENOMEM;
    return 0;
}

krb5_error_code ktest_make_sample_ldap_seqof_key_data(p)
    ldap_seqof_key_data *p;
{
    int i;
    p->mkvno = 14;
    p->n_key_data = 3;
    p->key_data = calloc(3,sizeof(krb5_key_data));
    for (i = 0; i < 3; i++) {
	krb5_error_code ret;
	ret = ktest_make_sample_key_data(&p->key_data[i], i);
	if (ret) return ret;
    }
    return 0;
}
#endif

krb5_error_code ktest_make_sample_predicted_sam_response(p)
    krb5_predicted_sam_response *p;
{
    krb5_error_code retval;

    p->magic = 79;
    retval = ktest_make_sample_keyblock(&p->sam_key);
    if (retval) return retval;
    p->sam_flags = 9;
    p->stime = 17;
    p->susec = 18;
    retval = ktest_make_sample_principal(&p->client);
    if (retval) return retval;
    retval = krb5_data_parse(&p->msd, "hello");
    if (retval) return retval;
    return 0;
}


/****************************************************************/
/* destructors */

void ktest_destroy_data(d)
    krb5_data ** d;
{
    if (*d != NULL) {
	if ((*d)->data != NULL) free((*d)->data);
	free(*d);
	*d = NULL;
    }
}

void ktest_empty_data(d)
    krb5_data * d;
{
    if (d->data != NULL) {
	free(d->data);
	d->data = NULL;
	d->length = 0;
    }
}  

void ktest_destroy_checksum(cs)
    krb5_checksum ** cs;
{
    if (*cs != NULL) {
	if ((*cs)->contents != NULL) free((*cs)->contents);
	free(*cs);
	*cs = NULL;
    }
}

void ktest_empty_keyblock(kb)
    krb5_keyblock * kb;
{
    if (kb != NULL) {
	if (kb->contents) {
	    free (kb->contents);
	    kb->contents = NULL;
	}
    }
}

void ktest_destroy_keyblock(kb)
    krb5_keyblock ** kb;
{
    if (*kb != NULL) {
	if ((*kb)->contents != NULL) free((*kb)->contents);
	free(*kb);
	*kb = NULL;
    }
}

void ktest_empty_authorization_data(ad)
    krb5_authdata ** ad;
{
    int i;

    if (*ad != NULL) {
	for (i=0; ad[i] != NULL; i++)
	    ktest_destroy_authdata(&(ad[i]));
    }
}

void ktest_destroy_authorization_data(ad)
    krb5_authdata *** ad;
{
    ktest_empty_authorization_data(*ad);
    free(*ad);
    *ad = NULL;
}

void ktest_destroy_authdata(ad)
    krb5_authdata ** ad;
{
    if (*ad != NULL) {
	if ((*ad)->contents != NULL) free((*ad)->contents);
	free(*ad);
	*ad = NULL;
    }
}

void ktest_empty_pa_data_array(pad)
    krb5_pa_data ** pad;
{
    int i;

    for (i=0; pad[i] != NULL; i++)
	ktest_destroy_pa_data(&(pad[i]));
}

void ktest_destroy_pa_data_array(pad)
    krb5_pa_data *** pad;
{
    ktest_empty_pa_data_array(*pad);
    free(*pad);
    *pad = NULL;
}

void ktest_destroy_pa_data(pad)
    krb5_pa_data ** pad;
{
    if (*pad != NULL) {
	if ((*pad)->contents != NULL) free((*pad)->contents);
	free(*pad);
	*pad = NULL;
    }
}


void ktest_destroy_address(a)
    krb5_address ** a;
{
    if (*a != NULL) {
	if ((*a)->contents != NULL) free((*a)->contents);
	free(*a);
	*a = NULL;
    }
}

void ktest_empty_addresses(a)
    krb5_address ** a;
{
    int i;

    for (i=0; a[i] != NULL; i++)
	ktest_destroy_address(&(a[i]));
}  

void ktest_destroy_addresses(a)
    krb5_address *** a;
{
    ktest_empty_addresses(*a);
    free(*a);
    *a = NULL;
}

void ktest_destroy_principal(p)
    krb5_principal * p;
{
    int i;

    for (i=0; i<(*p)->length; i++)
	ktest_empty_data(&(((*p)->data)[i]));
    ktest_empty_data(&((*p)->realm));
    free((*p)->data);
    free(*p);
    *p = NULL;
}

void ktest_destroy_sequence_of_integer(soi)
    long ** soi;
{
    free(*soi);
    *soi = NULL;
}

#if 0
void ktest_destroy_sequence_of_enctype(soi)
    krb5_enctype ** soi;
{
    free(*soi);
    *soi = NULL;
}
#endif

void ktest_destroy_sequence_of_ticket(sot)
    krb5_ticket *** sot;
{
    int i;

    for (i=0; (*sot)[i] != NULL; i++)
	ktest_destroy_ticket(&((*sot)[i]));
    free(*sot);
    *sot = NULL;
}

void ktest_destroy_ticket(tkt)
    krb5_ticket ** tkt;
{
    ktest_destroy_principal(&((*tkt)->server));
    ktest_destroy_enc_data(&((*tkt)->enc_part));
    /*  ktest_empty_enc_tkt_part(((*tkt)->enc_part2));*/
    free(*tkt);
    *tkt = NULL;
}  

void ktest_empty_ticket(tkt)
    krb5_ticket * tkt;
{
    if (tkt->server)
	ktest_destroy_principal(&((tkt)->server));
    ktest_destroy_enc_data(&((tkt)->enc_part));
    if (tkt->enc_part2) {
	ktest_destroy_enc_tkt_part(&(tkt->enc_part2));
    }
}  

void ktest_destroy_enc_data(ed)
    krb5_enc_data * ed;
{
    ktest_empty_data(&(ed->ciphertext));
    ed->kvno = 0;
}

void ktest_destroy_etype_info_entry(i)
    krb5_etype_info_entry *i;
{
    if (i->salt)
	free(i->salt);
    ktest_empty_data(&(i->s2kparams));
    free(i);
}

void ktest_destroy_etype_info(info)
    krb5_etype_info_entry **info;
{
    int i;

    for (i=0; info[i] != NULL; i++)
	ktest_destroy_etype_info_entry(info[i]);
    free(info);
}
    

void ktest_empty_kdc_req(kr)
    krb5_kdc_req *kr;
{
    if (kr->padata)
	ktest_destroy_pa_data_array(&(kr->padata));

    if (kr->client)
	ktest_destroy_principal(&(kr->client));

    if (kr->server)
	ktest_destroy_principal(&(kr->server));
    if (kr->ktype)
	free(kr->ktype);
    if (kr->addresses)
	ktest_destroy_addresses(&(kr->addresses));
    ktest_destroy_enc_data(&(kr->authorization_data));
    if (kr->unenc_authdata)
	ktest_destroy_authorization_data(&(kr->unenc_authdata));
    if (kr->second_ticket)
	ktest_destroy_sequence_of_ticket(&(kr->second_ticket));

}

void ktest_empty_kdc_rep(kr)
    krb5_kdc_rep *kr;
{
    if (kr->padata)
	ktest_destroy_pa_data_array(&(kr->padata));

    if (kr->client)
	ktest_destroy_principal(&(kr->client));

    if (kr->ticket)
	ktest_destroy_ticket(&(kr->ticket));

    ktest_destroy_enc_data(&kr->enc_part);

    if (kr->enc_part2) {
	ktest_empty_enc_kdc_rep_part(kr->enc_part2);
	free(kr->enc_part2);
	kr->enc_part2 = NULL;
    }
}


void ktest_empty_authenticator(a)
    krb5_authenticator * a;
{

    if (a->client) 
	ktest_destroy_principal(&(a->client));
    if (a->checksum)
	ktest_destroy_checksum(&(a->checksum));
    if (a->subkey)
	ktest_destroy_keyblock(&(a->subkey));
    if (a->authorization_data)
	ktest_destroy_authorization_data(&(a->authorization_data));
}

void ktest_empty_enc_tkt_part(etp)
    krb5_enc_tkt_part * etp;
{

    if (etp->session)
	ktest_destroy_keyblock(&(etp->session));
    if (etp->client) 
	ktest_destroy_principal(&(etp->client));
    if (etp->caddrs)
	ktest_destroy_addresses(&(etp->caddrs));
    if (etp->authorization_data)
	ktest_destroy_authorization_data(&(etp->authorization_data));
    ktest_destroy_transited(&(etp->transited));
}

void ktest_destroy_enc_tkt_part(etp)
    krb5_enc_tkt_part ** etp;
{
    if (*etp) {
	ktest_empty_enc_tkt_part(*etp);
	free(*etp);
	*etp = NULL;
    }
}

void ktest_empty_enc_kdc_rep_part(ekr)
    krb5_enc_kdc_rep_part * ekr;
{

    if (ekr->session)
	ktest_destroy_keyblock(&(ekr->session));

    if (ekr->server) 
	ktest_destroy_principal(&(ekr->server));

    if (ekr->caddrs)
	ktest_destroy_addresses(&(ekr->caddrs));
    ktest_destroy_last_req(&(ekr->last_req));
}


void ktest_destroy_transited(t)
    krb5_transited * t;
{
    if (t->tr_contents.data)
	ktest_empty_data(&(t->tr_contents));
}


void ktest_empty_ap_rep(ar)
    krb5_ap_rep * ar;
{
    ktest_destroy_enc_data(&ar->enc_part);
}

void ktest_empty_ap_req(ar)
    krb5_ap_req * ar;
{

    if (ar->ticket)
	ktest_destroy_ticket(&(ar->ticket));
    ktest_destroy_enc_data(&(ar->authenticator));
}

void ktest_empty_cred_enc_part(cep)
    krb5_cred_enc_part * cep;
{
    if (cep->s_address)
	ktest_destroy_address(&(cep->s_address));
    if (cep->r_address)
	ktest_destroy_address(&(cep->r_address));
    if (cep->ticket_info)
	ktest_destroy_sequence_of_cred_info(&(cep->ticket_info));
}

void ktest_destroy_cred_info(ci)
    krb5_cred_info ** ci;
{
    if ((*ci)->session)
	ktest_destroy_keyblock(&((*ci)->session));
    if ((*ci)->client) 
	ktest_destroy_principal(&((*ci)->client));
    if ((*ci)->server) 
	ktest_destroy_principal(&((*ci)->server));
    if ((*ci)->caddrs)
	ktest_destroy_addresses(&((*ci)->caddrs));
    free(*ci);
    *ci = NULL;
}

void ktest_destroy_sequence_of_cred_info(soci)
    krb5_cred_info *** soci;
{
    int i;

    for (i=0; (*soci)[i] != NULL; i++)
	ktest_destroy_cred_info(&((*soci)[i]));
    free(*soci);
    *soci = NULL;
}


void ktest_empty_safe(s)
    krb5_safe * s;
{
    ktest_empty_data(&(s->user_data));
    ktest_destroy_address(&(s->s_address));
    ktest_destroy_address(&(s->r_address));
    ktest_destroy_checksum(&(s->checksum));
}

void ktest_empty_priv_enc_part(pep)
    krb5_priv_enc_part * pep;
{
    ktest_empty_data(&(pep->user_data));
    ktest_destroy_address(&(pep->s_address));
    ktest_destroy_address(&(pep->r_address));
}

void ktest_empty_priv(p)
    krb5_priv * p;
{
    ktest_destroy_enc_data(&(p->enc_part));
}

void ktest_empty_cred(c)
    krb5_cred * c;
{

    ktest_destroy_sequence_of_ticket(&(c->tickets));
    ktest_destroy_enc_data(&(c->enc_part));
    /* enc_part2 */

}

void ktest_destroy_last_req(lr)
    krb5_last_req_entry *** lr;
{
    int i;

    if (*lr) {
	for (i=0; (*lr)[i] != NULL; i++) {
	    free((*lr)[i]);
	}
	free(*lr);
    }
}

void ktest_empty_error(kerr)
    krb5_error * kerr;
{
    if (kerr->client)
	ktest_destroy_principal(&(kerr->client));
    if (kerr->server)
	ktest_destroy_principal(&(kerr->server));
    ktest_empty_data(&(kerr->text));
    ktest_empty_data(&(kerr->e_data));
}

void ktest_empty_ap_rep_enc_part(arep)
    krb5_ap_rep_enc_part * arep;
{
    ktest_destroy_keyblock(&((arep)->subkey));
}

void ktest_empty_passwd_phrase_element(ppe)
    passwd_phrase_element * ppe;
{
    ktest_destroy_data(&(ppe->passwd));
    ktest_destroy_data(&(ppe->phrase));
}

void ktest_empty_pwd_data(pd)
    krb5_pwd_data * pd;
{
    int i;

    for (i=0; i <= pd->sequence_count; i++) {
	if (pd->element[i]) {
	    ktest_empty_passwd_phrase_element(pd->element[i]);
	    free(pd->element[i]);
	    pd->element[i] = NULL;
	}
    }
    free(pd->element);
  
}

void ktest_empty_alt_method(am)
    krb5_alt_method *am;
{
    if (am->data) {
	free(am->data);
	am->data = NULL;
    }
}

void ktest_empty_sam_challenge(p)
    krb5_sam_challenge * p;
{
    ktest_empty_data(&(p->sam_type_name));
    ktest_empty_data(&(p->sam_track_id));
    ktest_empty_data(&(p->sam_challenge_label));
    ktest_empty_data(&(p->sam_challenge));
    ktest_empty_data(&(p->sam_response_prompt));
    ktest_empty_data(&(p->sam_pk_for_sad));

    if (p->sam_cksum.contents != NULL) {
	free(p->sam_cksum.contents);
	p->sam_cksum.contents = NULL;
    }

}

void ktest_empty_sam_response(p)
    krb5_sam_response * p;
{
    ktest_empty_data(&(p->sam_track_id));
    ktest_empty_data(&(p->sam_enc_key.ciphertext));
    ktest_empty_data(&(p->sam_enc_nonce_or_ts.ciphertext));
}

void ktest_empty_sam_key(p)
    krb5_sam_key *p;
{
    if (p->sam_key.contents)
	free(p->sam_key.contents);
}

void ktest_empty_sam_response_2(p)
    krb5_sam_response_2 *p;
{
}
void ktest_empty_enc_sam_response_enc_2(p)
    krb5_enc_sam_response_enc_2 *p;
{
}

#ifdef ENABLE_LDAP
void ktest_empty_ldap_seqof_key_data(ctx, p)
    krb5_context ctx;
    ldap_seqof_key_data *p;
{
    int i;
    for (i = 0; i < p->n_key_data; i++) {
	free(p->key_data[i].key_data_contents[0]);
	free(p->key_data[i].key_data_contents[1]);
    }
}
#endif

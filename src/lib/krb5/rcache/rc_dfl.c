/*
 * lib/krb5/rcache/rc_dfl.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */


/*
 * An implementation for the default replay cache type.
 */
#define FREE(x) ((void) free((char *) (x)))
#include "rc_base.h"
#include "rc_dfl.h"
#include "rc_io.h"
#include <k5-int.h>

/*
If NOIOSTUFF is defined at compile time, dfl rcaches will be per-process.
*/

/*
Local stuff:

static int hash(krb5_donot_replay *rep,int hsize)
  returns hash value of *rep, between 0 and hsize - 1
HASHSIZE
  size of hash table (constant), can be preset
static int cmp(krb5_donot_replay *old,krb5_donot_replay *new,krb5_deltat t)
  compare old and new; return CMP_REPLAY or CMP_HOHUM
static int alive (krb5_context, krb5_donot_replay *new,krb5_deltat t)
  see if new is still alive; return CMP_EXPIRED or CMP_HOHUM
CMP_MALLOC, CMP_EXPIRED, CMP_REPLAY, CMP_HOHUM
  return codes from cmp(), alive(), and store()
struct dfl_data
  data stored in this cache type, namely "dfl"
struct authlist
  multilinked list of reps
static int rc_store(context, krb5_rcache id,krb5_donot_replay *rep)
  store rep in cache id; return CMP_REPLAY if replay, else CMP_MALLOC/CMP_HOHUM

*/

#ifndef HASHSIZE
#define HASHSIZE 997 /* a convenient prime */
#endif

#ifndef EXCESSREPS
#define EXCESSREPS 30
#endif
/* The rcache will be automatically expunged when the number of expired
krb5_donot_replays encountered incidentally in searching exceeds the number
of live krb5_donot_replays by EXCESSREPS. With the defaults here, a typical
cache might build up some 10K of expired krb5_donot_replays before an automatic
expunge, with the waste basically independent of the number of stores per
minute. */

static int hash(rep, hsize)
krb5_donot_replay *rep;
int hsize;
{
 return (int) ((((rep->cusec + rep->ctime + *rep->server + *rep->client)
	 % hsize) + hsize) % hsize);
 /* We take this opportunity to once again complain about C's idiotic %. */
}

#define CMP_MALLOC -3
#define CMP_EXPIRED -2
#define CMP_REPLAY -1
#define CMP_HOHUM 0

/*ARGSUSED*/
static int cmp(old, new, t)
krb5_donot_replay *old;
krb5_donot_replay *new;
krb5_deltat t;
{
 if ((old->cusec == new->cusec) && /* most likely to distinguish */
     (old->ctime == new->ctime) &&
     (strcmp(old->client,new->client) == 0) &&
     (strcmp(old->server,new->server) == 0)) /* always true */
   return CMP_REPLAY;
 return CMP_HOHUM;
}

static int alive(context, new, t)
    krb5_context context;
    krb5_donot_replay *new;
    krb5_deltat t;
{
 krb5_int32 time;

 if (krb5_timeofday(context, &time))
   return CMP_HOHUM; /* who cares? */
 if (new->ctime + t < time) /* I hope we don't have to worry about overflow */
   return CMP_EXPIRED;
 return CMP_HOHUM;
}

struct dfl_data
 {
  char *name;
  krb5_deltat lifespan;
  int hsize;
  int numhits;
  int nummisses;
  struct authlist **h;
  struct authlist *a;
#ifndef NOIOSTUFF
  krb5_rc_iostuff d;
#endif
 }
;

struct authlist
 {
  krb5_donot_replay rep;
  struct authlist *na;
  struct authlist *nh;
 }
;

/* of course, list is backwards from file */
/* hash could be forwards since we have to search on match, but naaaah */

static int rc_store(context, id, rep)
    krb5_context context;
    krb5_rcache id;
    krb5_donot_replay *rep;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 int rephash;
 struct authlist *ta;

 rephash = hash(rep,t->hsize);

 for (ta = t->h[rephash];ta;ta = ta->nh)
   switch(cmp(&ta->rep,rep,t->lifespan))
    {
     case CMP_REPLAY: return CMP_REPLAY;
     case CMP_HOHUM: if (alive(context, &ta->rep,t->lifespan) == CMP_EXPIRED)
		       t->nummisses++;
		     else
		       t->numhits++;
		     break;
     default: ; /* wtf? */
    }

 if (!(ta = (struct authlist *) malloc(sizeof(struct authlist))))
   return CMP_MALLOC;
 ta->na = t->a; t->a = ta;
 ta->nh = t->h[rephash]; t->h[rephash] = ta;
 ta->rep = *rep;
 if (!(ta->rep.client = strdup(rep->client))) {
     FREE(ta);
     return CMP_MALLOC;
 }
 if (!(ta->rep.server = strdup(rep->server))) {
     FREE(ta->rep.client);
     FREE(ta);
     return CMP_MALLOC;
 }

 return CMP_HOHUM;
}

char * krb5_rc_dfl_get_name(context, id)
    krb5_context context;
    krb5_rcache id;
{
 return ((struct dfl_data *) (id->data))->name;
}

krb5_error_code krb5_rc_dfl_get_span(context, id, lifespan)
    krb5_context context;
    krb5_rcache id;
    krb5_deltat *lifespan;
{
 *lifespan = ((struct dfl_data *) (id->data))->lifespan;
 return 0;
}

krb5_error_code krb5_rc_dfl_init(context, id, lifespan)
    krb5_context context;
krb5_rcache id;
krb5_deltat lifespan;
{
    struct dfl_data *t = (struct dfl_data *)id->data;
    krb5_error_code retval;

    t->lifespan = lifespan;
#ifndef NOIOSTUFF
    if ((retval = krb5_rc_io_creat(context, &t->d,&t->name)))
	return retval;
    if ((krb5_rc_io_write(context, &t->d,
			  (krb5_pointer) &t->lifespan, sizeof(t->lifespan))
	 || krb5_rc_io_sync(context, &t->d)))
	return KRB5_RC_IO;
#endif
    return 0;
}

krb5_error_code krb5_rc_dfl_close_no_free(context, id)
    krb5_context context;
    krb5_rcache id;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 struct authlist *q;

 FREE(t->h);
 if (t->name)
     FREE(t->name);
 while ((q = t->a))
  {
   t->a = q->na;
   FREE(q->rep.client);
   FREE(q->rep.server);
   FREE(q);
  }
#ifndef NOIOSTUFF
 if (t->d.fd >= 0)
    (void) krb5_rc_io_close(context, &t->d);
#endif
 FREE(t);
 return 0;
}

krb5_error_code krb5_rc_dfl_close(context, id)
    krb5_context context;
    krb5_rcache id;
{
    krb5_rc_dfl_close_no_free(context, id);
    free(id);
    return 0;
}

krb5_error_code krb5_rc_dfl_destroy(context, id)
    krb5_context context;
krb5_rcache id;
{
#ifndef NOIOSTUFF
 if (krb5_rc_io_destroy(context, &((struct dfl_data *) (id->data))->d))
   return KRB5_RC_IO;
#endif
 return krb5_rc_dfl_close(context, id);
}

krb5_error_code krb5_rc_dfl_resolve(context, id, name)
    krb5_context context;
    krb5_rcache id;
    char *name;
{
    struct dfl_data *t = 0;
    krb5_error_code retval;

    /* allocate id? no */
    if (!(t = (struct dfl_data *) malloc(sizeof(struct dfl_data))))
	return KRB5_RC_MALLOC;
    id->data = (krb5_pointer) t;
    memset(t, 0, sizeof(struct dfl_data));
    if (name) {
	t->name = malloc(strlen(name)+1);
	if (!t->name) {
	    retval = KRB5_RC_MALLOC;
	    goto cleanup;
	}
	strcpy(t->name, name);
    } else
	t->name = 0;
    t->numhits = t->nummisses = 0;
    t->hsize = HASHSIZE; /* no need to store---it's memory-only */
    t->h = (struct authlist **) malloc(t->hsize*sizeof(struct authlist *));
    if (!t->h) {
	retval = KRB5_RC_MALLOC;
	goto cleanup;
    }
    memset(t->h, 0, t->hsize*sizeof(struct authlist *));
    t->a = (struct authlist *) 0;
#ifndef NOIOSTUFF
    t->d.fd = -1;
#endif
    return 0;
    
cleanup:
    if (t) {
	if (t->name)
	    krb5_xfree(t->name);
	if (t->h)
	    krb5_xfree(t->h);
	krb5_xfree(t);
    }
    return retval;
}

void krb5_rc_free_entry (context, rep)
    krb5_context context;
    krb5_donot_replay **rep;
{
    krb5_donot_replay *rp = *rep;
    
    *rep = NULL;
    if (rp) 
    {
	if (rp->client)
	    free(rp->client);

	if (rp->server)
	    free(rp->server);
	rp->client = NULL;
	rp->server = NULL;
	free(rp);
    }
}

static krb5_error_code krb5_rc_io_fetch(context, t, rep, maxlen) 
    krb5_context context;
    struct dfl_data *t;
    krb5_donot_replay *rep;
    int maxlen;
{
    int len;
    krb5_error_code retval;

    rep->client = rep->server = 0;
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) &len, sizeof(len));
    if (retval) 
	return retval;
    
    if ((len <= 0) || (len >= maxlen))
	return KRB5_RC_IO_EOF;

    rep->client = malloc (len);
    if (!rep->client)
	return KRB5_RC_MALLOC;
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) rep->client, len);
    if (retval)
	goto errout;
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) &len, sizeof(len));
    if (retval)
	goto errout;
    
    if ((len <= 0) || (len >= maxlen)) {
	retval = KRB5_RC_IO_EOF;
	goto errout;
    }

    rep->server = malloc (len);
    if (!rep->server) {
	retval = KRB5_RC_MALLOC;
	goto errout;
    }
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) rep->server, len);
    if (retval)
	goto errout;
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) &rep->cusec, sizeof(rep->cusec));
    if (retval)
	goto errout;
    
    retval = krb5_rc_io_read (context, &t->d, (krb5_pointer) &rep->ctime, sizeof(rep->ctime));
    if (retval)
	goto errout;

    return 0;
    
errout:
    if (rep->client)
	krb5_xfree(rep->client);
    if (rep->server)
	krb5_xfree(rep->server);
    return retval;
}
    


krb5_error_code krb5_rc_dfl_recover(context, id)
    krb5_context context;
krb5_rcache id;
{
#ifdef NOIOSTUFF
    return KRB5_RC_NOIO;
#else

    struct dfl_data *t = (struct dfl_data *)id->data;
    krb5_donot_replay *rep;
    krb5_error_code retval;
    long max_size;

    if ((retval = krb5_rc_io_open(context, &t->d, t->name)))
	return retval;
 
    max_size = krb5_rc_io_size(context, &t->d);
 
    rep = NULL;
    if (krb5_rc_io_read(context, &t->d,(krb5_pointer) &t->lifespan,sizeof(t->lifespan))) {
	retval = KRB5_RC_IO;
	goto io_fail;
    }

    if (!(rep = (krb5_donot_replay *) malloc(sizeof(krb5_donot_replay)))) {
	retval = KRB5_RC_MALLOC;
	goto io_fail;
    }
    rep->client = NULL;
    rep->server = NULL;

    /* now read in each auth_replay and insert into table */
    for (;;) {
	if (krb5_rc_io_mark(context, &t->d)) {
	    retval = KRB5_RC_IO;
	    goto io_fail;
	}
	
	retval = krb5_rc_io_fetch (context, t, rep, (int) max_size);

	if (retval == KRB5_RC_IO_EOF)
	    break;
	else if (retval != 0)
	    goto io_fail;

	
	if (alive(context, rep,t->lifespan) != CMP_EXPIRED) {
	    if (rc_store(context, id, rep) == CMP_MALLOC) {
		retval = KRB5_RC_MALLOC; goto io_fail;
	    } 
	}
	/*
	 *  free fields allocated by rc_io_fetch
	 */
	FREE(rep->server);
	FREE(rep->client);
	rep->server = 0;
	rep->client = 0;
    }
    retval = 0;
    krb5_rc_io_unmark(context, &t->d);
    /*
     *  An automatic expunge here could remove the need for
     *  mark/unmark but that would be inefficient.
     */
io_fail:
    krb5_rc_free_entry(context, &rep);
    if (retval)
	krb5_rc_io_close(context, &t->d);
    return retval;
    
#endif
}

static krb5_error_code
krb5_rc_io_store (context, t, rep)
    krb5_context context;
    struct dfl_data *t;
    krb5_donot_replay *rep;
{
    int clientlen, serverlen, len;
    char *buf, *ptr;
    unsigned long ret;

    clientlen = strlen (rep->client) + 1;
    serverlen = strlen (rep->server) + 1;
    len = sizeof(clientlen) + clientlen + sizeof(serverlen) + serverlen +
	sizeof(rep->cusec) + sizeof(rep->ctime);
    buf = malloc (len);
    if (buf == 0)
	return KRB5_RC_MALLOC;
    ptr = buf;
    memcpy(ptr, &clientlen, sizeof(clientlen)); ptr += sizeof(clientlen);
    memcpy(ptr, rep->client, clientlen); ptr += clientlen;
    memcpy(ptr, &serverlen, sizeof(serverlen)); ptr += sizeof(serverlen);
    memcpy(ptr, rep->server, serverlen); ptr += serverlen;
    memcpy(ptr, &rep->cusec, sizeof(rep->cusec)); ptr += sizeof(rep->cusec);
    memcpy(ptr, &rep->ctime, sizeof(rep->ctime)); ptr += sizeof(rep->ctime);

    ret = krb5_rc_io_write(context, &t->d, buf, len);
    free(buf);
    return ret;
}

krb5_error_code krb5_rc_dfl_store(context, id, rep)
    krb5_context context;
krb5_rcache id;
krb5_donot_replay *rep;
{
    unsigned long ret;
    struct dfl_data *t = (struct dfl_data *)id->data;

    switch(rc_store(context, id,rep)) {
    case CMP_MALLOC:
	return KRB5_RC_MALLOC; 
    case CMP_REPLAY:
	return KRB5KRB_AP_ERR_REPEAT; 
    case 0: break;
    default: /* wtf? */ ;
    }
#ifndef NOIOSTUFF
    ret = krb5_rc_io_store (context, t, rep);
    if (ret)
	return ret;
#endif
 /* Shall we automatically expunge? */
 if (t->nummisses > t->numhits + EXCESSREPS)
    {
   return krb5_rc_dfl_expunge(context, id);
    }
#ifndef NOIOSTUFF
    else
    {
	if (krb5_rc_io_sync(context, &t->d))
	    return KRB5_RC_IO;
    }
#endif
 return 0;
}

krb5_error_code krb5_rc_dfl_expunge(context, id)
    krb5_context context;
krb5_rcache id;
{
    struct dfl_data *t = (struct dfl_data *)id->data;
#ifdef NOIOSTUFF
    int i;
    struct authlist **q;
    struct authlist **qt;
    struct authlist *r;
    struct authlist *rt;

    for (q = &t->a;*q;q = qt) {
	qt = &(*q)->na;
	if (alive(context, &(*q)->rep,t->lifespan) == CMP_EXPIRED) {
	    FREE((*q)->rep.client);
	    FREE((*q)->rep.server);
	    FREE(*q);
	    *q = *qt; /* why doesn't this feel right? */
	}
    }
    for (i = 0;i < t->hsize;i++)
	t->h[i] = (struct authlist *) 0;
    for (r = t->a;r;r = r->na) {
	i = hash(&r->rep,t->hsize);
	rt = t->h[i];
	t->h[i] = r;
	r->nh = rt;
    }
  
#else
    struct authlist *q;
    char *name;
    krb5_error_code retval;
    krb5_rcache tmp;
    krb5_deltat lifespan = t->lifespan;  /* save original lifespan */

    name = t->name;
    t->name = 0;		/* Clear name so it isn't freed */
    (void) krb5_rc_dfl_close_no_free(context, id);
    retval = krb5_rc_dfl_resolve(context, id, name);
    free(name);
    if (retval)
	return retval;
    retval = krb5_rc_dfl_recover(context, id);
    if (retval)
	return retval;
    t = (struct dfl_data *)id->data; /* point to recovered cache */
    tmp = (krb5_rcache) malloc(sizeof(*tmp));
    if (!tmp)
	return ENOMEM;
    retval = krb5_rc_resolve_type(context, &tmp, "dfl");
    if (retval)
	return retval;
    retval = krb5_rc_resolve(context, tmp, 0);
    if (retval)
	return retval;
    retval = krb5_rc_initialize(context, tmp, lifespan);
    if (retval)
	return retval;
    for (q = t->a;q;q = q->na) {
	if (krb5_rc_io_store (context, (struct dfl_data *)tmp->data, &q->rep))
	    return KRB5_RC_IO;
    }
    if (krb5_rc_io_sync(context, &t->d))
	return KRB5_RC_IO;
    if (krb5_rc_io_move(context, &t->d, &((struct dfl_data *)tmp->data)->d))
	return KRB5_RC_IO;
     (void) krb5_rc_dfl_close(context, tmp);
#endif
    return 0;
}

/*
Copyright 1990, Daniel J. Bernstein. All rights reserved.

Please address any questions or comments to the author at brnstnd@acf10.nyu.edu.
*/

#define FREE(x) ((void) free((char *) (x)))
#include "rc_base.h"
#include "rc_dfl.h"
#include "rc_io.h"
#include <krb5/libos-proto.h>

/*
If NOIOSTUFF is defined at compile time, dfl rcaches will be per-process.
*/

/*
Local stuff:

struct auth_replay
  exactly that info which must not be replayed---by this cache type, that is
static int hash(struct auth_replay *rep,int hsize)
  returns hash value of *rep, between 0 and hsize - 1
HASHSIZE
  size of hash table (constant), can be preset
static int auth_to_rep(krb5_tkt_authent *auth,struct auth_replay *rep)
  given auth, take important information and make rep; return -1 if failed
static int cmp(struct auth_replay *old,struct auth_replay *new,krb5_deltat t)
  compare old and new; return CMP_REPLAY or CMP_HOHUM
static int alive(struct auth_replay *new,krb5_deltat t)
  see if new is still alive; return CMP_EXPIRED or CMP_HOHUM
CMP_MALLOC, CMP_EXPIRED, CMP_REPLAY, CMP_HOHUM
  return codes from cmp(), alive(), and store()
struct dfl_data
  data stored in this cache type, namely "dfl"
struct authlist
  multilinked list of reps
static int store(krb5_rcache id,struct auth_replay *rep)
  store rep in cache id; return CMP_REPLAY if replay, else CMP_MALLOC/CMP_HOHUM

*/

#ifndef HASHSIZE
#define HASHSIZE 997 /* a convenient prime */
#endif

#ifndef EXCESSREPS
#define EXCESSREPS 30
#endif
/* The rcache will be automatically expunged when the number of expired
auth_replays encountered incidentally in searching exceeds the number
of live auth_replays by EXCESSREPS. With the defaults here, a typical
cache might build up some 10K of expired auth_replays before an automatic
expunge, with the waste basically independent of the number of stores per
minute. */

struct auth_replay
 {
  char *server; /* null-terminated */
  char *client; /* null-terminated */
  krb5_ui_2 cmsec;
  krb5_timestamp ctime;
 }
;

static int hash(rep, hsize)
struct auth_replay *rep;
int hsize;
{
 return (((rep->cmsec + rep->ctime + *rep->server + *rep->client)
	 % hsize) + hsize) % hsize;
 /* We take this opportunity to once again complain about C's idiotic %. */
}

static krb5_error_code auth_to_rep(auth, rep)
krb5_tkt_authent *auth;
struct auth_replay *rep;
{
 krb5_error_code retval;
 rep->cmsec = auth->authenticator->cmsec;
 rep->ctime = auth->authenticator->ctime;
 if (retval = krb5_unparse_name(auth->ticket->server,&rep->server))
   return retval; /* shouldn't happen */
 if (retval = krb5_unparse_name(auth->authenticator->client,&rep->client)) {
     FREE(rep->server);
     return retval; /* shouldn't happen. */
 }
 return 0;
}

#define CMP_MALLOC -3
#define CMP_EXPIRED -2
#define CMP_REPLAY -1
#define CMP_HOHUM 0

/*ARGSUSED*/
static int cmp(old, new, t)
struct auth_replay *old;
struct auth_replay *new;
krb5_deltat t;
{
 if ((old->cmsec == new->cmsec) && /* most likely to distinguish */
     (old->ctime == new->ctime) &&
     (strcmp(old->client,new->client) == 0) &&
     (strcmp(old->server,new->server) == 0)) /* always true */
   return CMP_REPLAY;
 return CMP_HOHUM;
}

static int alive(new, t)
struct auth_replay *new;
krb5_deltat t;
{
 krb5_int32 time;

 if (krb5_timeofday(&time))
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
  struct auth_replay rep;
  struct authlist *na;
  struct authlist *nh;
 }
;

/* of course, list is backwards from file */
/* hash could be forwards since we have to search on match, but naaaah */

static int store(id, rep)
krb5_rcache id;
struct auth_replay *rep;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 int rephash;
 struct authlist *ta;

 rephash = hash(rep,t->hsize);

 for (ta = t->h[rephash];ta;ta = ta->nh)
   switch(cmp(&ta->rep,rep,t->lifespan))
    {
     case CMP_REPLAY: return CMP_REPLAY;
     case CMP_HOHUM: if (alive(&ta->rep,t->lifespan) == CMP_EXPIRED)
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
 
 return CMP_HOHUM;
}

char *krb5_rc_dfl_get_name(id)
krb5_rcache id;
{
 return ((struct dfl_data *) (id->data))->name;
}

krb5_error_code krb5_rc_dfl_get_span(id, lifespan)
krb5_rcache id;
krb5_deltat *lifespan;
{
 *lifespan = ((struct dfl_data *) (id->data))->lifespan;
 return 0;
}

krb5_error_code krb5_rc_dfl_init(id, lifespan)
krb5_rcache id;
krb5_deltat lifespan;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 int i;

 t->lifespan = lifespan;
#ifndef NOIOSTUFF
 if (krb5_rc_io_creat(&t->d,&t->name))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) &t->lifespan,sizeof(t->lifespan)))
   return KRB5_RC_IO;
#endif
 t->numhits = t->nummisses = 0;
 t->hsize = HASHSIZE; /* could be variable, but naaaah */
 if (!(t->h = (struct authlist **) malloc(t->hsize*sizeof(struct authlist *))))
   return KRB5_RC_MALLOC;
 for (i = 0;i < t->hsize;i++)
   t->h[i] = (struct authlist *) 0;
 t->a = (struct authlist *) 0;
 return 0;
}

krb5_error_code krb5_rc_dfl_close(id)
krb5_rcache id;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 struct authlist *q;

 FREE(t->h);
 while (q = t->a)
  {
   t->a = q->na;
   FREE(q->rep.client);
   FREE(q->rep.server);
   FREE(q);
  }
#ifndef NOIOSTUFF
 (void) krb5_rc_io_close(&t->d);
#endif
 FREE(t);
 return 0;
}

krb5_error_code krb5_rc_dfl_destroy(id)
krb5_rcache id;
{
#ifndef NOIOSTUFF
 if (krb5_rc_io_destroy(&((struct dfl_data *) (id->data))->d))
   return KRB5_RC_IO;
#endif
 return krb5_rc_dfl_close(id);
}

krb5_error_code krb5_rc_dfl_resolve(id, name)
krb5_rcache id;
char *name;
{
 struct dfl_data *t;

 /* allocate id? no */
 if (!(t = (struct dfl_data *) malloc(sizeof(struct dfl_data))))
   return KRB5_RC_MALLOC;
 id->data = (krb5_pointer) t;
 t->name = name; /* gee, difficult... */
 return 0;
}

krb5_error_code krb5_rc_dfl_recover(id)
krb5_rcache id;
{
#ifdef NOIOSTUFF
 return KRB5_RC_NOIO;
#else

 struct dfl_data *t = (struct dfl_data *)id->data;
 int i;
 struct auth_replay *rep;

 if (krb5_rc_io_open(&t->d,t->name))
   return KRB5_RC_IO;
 if (krb5_rc_io_read(&t->d,(krb5_pointer) &t->lifespan,sizeof(t->lifespan)))
   return KRB5_RC_IO;
 t->numhits = t->nummisses = 0;
 t->hsize = HASHSIZE; /* no need to store---it's memory-only */
 if (!(t->h = (struct authlist **) malloc(t->hsize*sizeof(struct authlist *))))
   return KRB5_RC_MALLOC;
 for (i = 0;i < t->hsize;i++)
   t->h[i] = (struct authlist *) 0;
 t->a = (struct authlist *) 0;

 /* now read in each auth_replay and insert into table */
 for (;;)
  {
#define FREE1 FREE(rep);
#define FREE2 FREE(rep->client); FREE(rep);
#define FREE3 FREE(rep->server); FREE(rep->client); FREE(rep);
   if (krb5_rc_io_mark(&t->d))
     return KRB5_RC_IO;
   if (!(rep = (struct auth_replay *) malloc(sizeof(struct auth_replay))))
     return KRB5_RC_MALLOC;
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) &i,sizeof(i)))
    {
     case KRB5_RC_IO_EOF: FREE1; goto end_loop;
     case 0: break; default: FREE1; return KRB5_RC_IO; break;
    }
   if (!(rep->client = malloc(i)))
    { FREE1; return KRB5_RC_MALLOC; }
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) rep->client,i))
    {
     case KRB5_RC_IO_EOF: FREE2; goto end_loop;
     case 0: break; default: FREE2; return KRB5_RC_IO; break;
    }
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) &i,sizeof(i)))
    {
     case KRB5_RC_IO_EOF: FREE2; goto end_loop;
     case 0: break; default: FREE2; return KRB5_RC_IO; break;
    }
   if (!(rep->server = malloc(i)))
    { FREE2; return KRB5_RC_MALLOC; }
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) rep->server,i))
    {
     case KRB5_RC_IO_EOF: FREE3; goto end_loop;
     case 0: break; default: FREE3; return KRB5_RC_IO; break;
    }
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) &rep->cmsec,sizeof(rep->cmsec))) 
    {
     case KRB5_RC_IO_EOF: FREE3; goto end_loop;
     case 0: break; default: FREE3; return KRB5_RC_IO; break;
    }
   switch(krb5_rc_io_read(&t->d,(krb5_pointer) &rep->ctime,sizeof(rep->ctime)))
    {
     case KRB5_RC_IO_EOF: FREE3; goto end_loop;
     case 0: break; default: FREE3; return KRB5_RC_IO; break;
    }
   if (alive(rep,t->lifespan) != CMP_EXPIRED)
     if (store(id,rep) == CMP_MALLOC) /* can't be a replay */
       return KRB5_RC_MALLOC; 
  }
 end_loop: krb5_rc_io_unmark(&t->d);
/* An automatic expunge here could remove the need for mark/unmark but
would be inefficient. */
 return 0;
#endif
}

krb5_error_code krb5_rc_dfl_store(id, auth)
krb5_rcache id;
krb5_tkt_authent *auth;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 struct auth_replay *rep;
 int i;
 krb5_error_code retval;

 if (!(rep = (struct auth_replay *) malloc(sizeof(struct auth_replay))))
   return KRB5_RC_MALLOC;
 if (retval = auth_to_rep(auth,rep))
  { FREE(rep); return retval; }
 switch(store(id,rep))
  {
   case CMP_MALLOC: FREE(rep->client); FREE(rep->server); FREE(rep);
       return KRB5_RC_MALLOC; break;
   case CMP_REPLAY: FREE(rep->client); FREE(rep->server); FREE(rep);
       return KRB5KRB_AP_ERR_REPEAT; break;
   case 0: break;
   default: /* wtf? */ ;
  }
#ifndef NOIOSTUFF
 i = strlen(rep->client) + 1;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) &i,sizeof(i)))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) rep->client,i))
   return KRB5_RC_IO;
 i = strlen(rep->server) + 1;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) &i,sizeof(i)))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) rep->server,i))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) &rep->cmsec,sizeof(rep->cmsec)))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&t->d,(krb5_pointer) &rep->ctime,sizeof(rep->ctime)))
   return KRB5_RC_IO;
#endif
 /* Shall we automatically expunge? */
 if (t->nummisses > t->numhits + EXCESSREPS)
   return krb5_rc_dfl_expunge(id);
 return 0;
}

krb5_error_code krb5_rc_dfl_expunge(id)
krb5_rcache id;
{
 struct dfl_data *t = (struct dfl_data *)id->data;
 int i;
#ifdef NOIOSTUFF
 struct authlist **q;
 struct authlist **qt;
 struct authlist *r;
 struct authlist *rt;

 for (q = &t->a;*q;q = qt)
  {
   qt = &(*q)->na;
   if (alive(&(*q)->rep,t->lifespan) == CMP_EXPIRED)
    {
     FREE((*q)->rep.client);
     FREE((*q)->rep.server);
     FREE(*q);
     *q = *qt; /* why doesn't this feel right? */
    }
  }
 for (i = 0;i < t->hsize;i++)
   t->h[i] = (struct authlist *) 0;
 for (r = t->a;r;r = r->na)
  {
   i = hash(&r->rep,t->hsize);
   rt = t->h[i];
   t->h[i] = r;
   r->nh = rt;
  }
  
#else
 struct krb5_rc_iostuff tmp;
 struct authlist *q;
 char *name = t->name;

 (void) krb5_rc_dfl_close(id);
 switch(krb5_rc_dfl_resolve(id, name)) {
   case KRB5_RC_MALLOC: return KRB5_RC_MALLOC;
   default: ;
 }
 switch(krb5_rc_dfl_recover(id))
  {
   case KRB5_RC_MALLOC: return KRB5_RC_MALLOC;
   case KRB5_RC_IO: return KRB5_RC_IO;
   default: ;
  }
 if (krb5_rc_io_creat(&tmp,(char **) 0))
   return KRB5_RC_IO;
 if (krb5_rc_io_write(&tmp,(krb5_pointer) &t->lifespan,sizeof(t->lifespan)))
   return KRB5_RC_IO;
 for (q = t->a;q;q = q->na)
  {
   i = strlen(q->rep.client) + 1;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) &i,sizeof(i)))
     return KRB5_RC_IO;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) q->rep.client,i))
     return KRB5_RC_IO;
   i = strlen(q->rep.server) + 1;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) &i,sizeof(i)))
     return KRB5_RC_IO;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) q->rep.server,i))
     return KRB5_RC_IO;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) &q->rep.cmsec,sizeof(q->rep.cmsec)))
     return KRB5_RC_IO;
   if (krb5_rc_io_write(&tmp,(krb5_pointer) &q->rep.ctime,sizeof(q->rep.ctime)))
     return KRB5_RC_IO;
  }
 if (krb5_rc_io_move(&t->d,&tmp))
   return KRB5_RC_IO;
#endif
 return 0;
}

/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)pop_stat.c  1.5 7/13/90";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include "popper.h"

/* 
 *  stat:   Display the status of a POP maildrop to its client
 */

int pop_stat (p)
POP     *   p;
{
    return (pop_msg (p,POP_SUCCESS,
        "%u %u",p->msg_count-p->msgs_deleted,p->drop_size-p->bytes_deleted));
}

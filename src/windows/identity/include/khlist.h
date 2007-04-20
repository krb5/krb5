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

/* Not exported */
#ifndef _KHIMAIRA_KHLIST_H
#define _KHIMAIRA_KHLIST_H

/* Note that most of these are "unsafe" macros.  Not for general use */

/* LIFO lists */
#define LDCL(type)                              \
    type * next;                                \
    type * prev

#define LINIT(pe)                               \
    do {                                        \
    (pe)->next = NULL;                          \
    (pe)->prev = NULL; } while(0)

#define LPUSH(pph,pe)                           \
    do {                                        \
    (pe)->next = *pph;                          \
    (pe)->prev = NULL;                          \
    if(*(pph)) (*(pph))->prev = (pe);           \
    (*(pph)) = (pe); } while(0)

#define LPOP(pph,ppe)                           \
    do {                                        \
    *(ppe) = *(pph);                            \
    if(*(pph)) *(pph) = (*(pph))->next;         \
    if(*(pph)) (*(pph))->prev = NULL;           \
    if(*(ppe)) (*(ppe))->next = NULL;           \
    } while(0)

#define LDELETE(pph,pe)                                 \
    do {                                                \
    if((pe)->prev) (pe)->prev->next = (pe)->next;       \
    if((pe)->next) (pe)->next->prev = (pe)->prev;       \
    if(*(pph) == (pe)) *(pph) = (pe)->next;             \
    (pe)->next = (pe)->prev = NULL;                     \
    } while(0)

#define LEMPTY(pph) (*(pph) == NULL)

#define LNEXT(pe) ((pe)?(pe)->next:NULL)

#define LPREV(pe) ((pe)?(pe)->prev:NULL)

/* Trees with LIFO child lists */
#define TDCL(type)                              \
    LDCL(type);                                 \
    type * children;                            \
    type * parent

#define TINIT(pe)                               \
    do {                                        \
    (pe)->children = NULL;                      \
    (pe)->parent = NULL; } while(0)

#define TADDCHILD(pt,pe)                        \
    do {                                        \
    LPUSH(&((pt)->children),(pe));              \
    (pe)->parent = (pt); } while(0)

#define TFIRSTCHILD(pt) ((pt)?(pt)->children:NULL)

#define TPOPCHILD(pt, ppe)                      \
    do {                                        \
    LPOP(&((pt)->children), ppe);               \
    if(*(ppe)) (*(ppe))->parent = NULL;         \
    } while(0)

#define TDELCHILD(pt, pe)                       \
    do {                                        \
    LDELETE(&((pt)->children), (pe));           \
    (pe)->parent = NULL; } while(0)

#define TPARENT(pe) ((pe)?(pe)->parent:NULL)

/* FIFO lists */
#define QDCL(type)                              \
    type * head;                                \
    type * tail

#define QINIT(pq)                               \
    do {                                        \
    (pq)->head = (pq)->tail = NULL;             \
    } while(0)

#define QPUT(pq, pe)                            \
    do {                                        \
    LPUSH(&(pq)->tail, (pe));                   \
    if(!(pq)->head) (pq)->head = (pe);          \
    } while(0)

#define QPUSH(pq, pe)                           \
    do {                                        \
    (pe)->next = NULL;                          \
    (pe)->prev = (pq)->head;                    \
    if((pq)->head) (pq)->head->next = (pe);     \
    if(!(pq)->tail) (pq)->tail = (pe);          \
    (pq)->head = (pe);                          \
    } while (0)

#define QGET(pq, ppe)                                           \
    do {                                                        \
    *(ppe) = (pq)->head;                                        \
    if(*(ppe)) {                                                \
        (pq)->head = (*(ppe))->prev;                            \
        if( (*(ppe))->prev ) (*(ppe))->prev->next = NULL;       \
        (*(ppe))->prev = NULL;                                  \
        if( (pq)->tail == *(ppe)) (pq)->tail = NULL;            \
    }                                                           \
    } while(0)

#define QDEL(pq, pe)                                    \
    do {                                                \
        if((pq)->head == (pe)) (pq)->head = LPREV(pe);  \
        LDELETE(&((pq)->tail), (pe));                   \
    } while(0)


#define QGETT(pq,ppe)                                           \
    do {                                                        \
    *(ppe) = (pq)->tail;                                        \
    if(*(ppe)) {                                                \
        (pq)->tail = (*(ppe))->next;                            \
        if( (*(ppe))->next ) (*(ppe))->next->prev = NULL;       \
        (*(ppe))->next = NULL;                                  \
        if( (pq)->head == *(ppe)) (pq)->head = NULL;            \
    }                                                           \
    } while(0)

#define QTOP(pq) ((pq)->head)
#define QBOTTOM(pq) ((pq)->tail)
#define QNEXT(pe) ((pe)->prev)
#define QPREV(pe) ((pe)->next)

#define QINSERT(pt, pre, pe)                    \
    do {                                        \
    if ((pre) == NULL ||                        \
        QNEXT(pre) == NULL) { QPUT(pt, pe); }   \
    else {                                      \
        (pe)->prev = (pre)->prev;               \
        (pe)->next = (pre);                     \
        (pre)->prev->next = (pe);               \
        (pre)->prev = (pe);                     \
    }} while(0)

/* Trees with FIFO child lists */
#define TQDCL(type)                             \
    LDCL(type);                                 \
    QDCL(type);                                 \
    type * parent

#define TQINIT(pe)                              \
    do {                                        \
    LINIT(pe);                                  \
    QINIT(pe);                                  \
    (pe)->parent = NULL; } while(0)

#define TQPUTCHILD(pt,pe)                       \
    do {                                        \
    QPUT((pt), (pe));                           \
    (pe)->parent = (pt); } while(0)

#define TQINSERT(pt, pre, pe)                   \
    do {                                        \
    QINSERT(pt, pre, pe);                       \
    (pe)->parent = (pt); } while(0)

#define TQGETCHILD(pt,ppe)                      \
    do {                                        \
    QGET(pt, ppe);                              \
    if (*(ppe)) { *(ppe)->parent = NULL; }      \
    } while(0)

#define TQDELCHILD(pt, pe)                      \
    do {                                        \
    QDEL(pt, pe);                               \
    (pe)->parent = NULL; } while(0)

#define TQFIRSTCHILD(pt) ((pt)?QTOP(pt):NULL)

#define TQNEXTCHILD(pe) QNEXT(pe)

#define TQPREVCHILD(pe) QPREV(pe)

#define TQPARENT(pe) ((pe)?(pe)->parent:NULL)

#endif

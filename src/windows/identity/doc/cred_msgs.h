/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
 * Copyright (c) 2007 Secure Endpoints Inc.
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

/*! \page cred_msgs Handling credentials provider messages

A credentials provider plug-in receives a number of messages during the
course of execution.  This section describes the appropriate ways of
handling these messages.

\section pi_credmsg_system System mesages

There are only two system messages that a credentials provider needs
to handle.  Both of these are explained elsewhere as they deal with
initialization and uninitialization of the plug-in.  See the following
two sections for details on handling these messages.

- <::KMSG_SYSTEM,::KMSG_SYSTEM_INIT> \ref pi_pt_cred_init
- <::KMSG_SYSTEM,::KMSG_SYSTEM_EXIT> \ref pi_pt_cred_exit

\section pi_credmsg_cred Credential messages



*/

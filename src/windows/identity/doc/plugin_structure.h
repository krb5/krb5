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

/*!

\page pi_structure Structure of a module

A Network Identity Manager module is a dynamically loadable library
with a specific set of exported symbols.  Each export symbol and
general notes about writing a plug-in module are documented below.

\section pi_str_reg  Registration and Version Information

[TODO]

\section pi_str_init Initialization

Do not use DllMain or other system specific callback routines to
perform intilization tasks other than creating mutexes, initializing
thread local storage and other tasks that must be performed at that
stage.  Specifically, do not call any Network Identity Manager API functions from
within DllMain.

\section pi_str_cb Callbacks

The callbacks that must be implemented by a module are:

- init_module()
- exit_module()

 */

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

/*! \mainpage NetIDMgr

    \image html khimaira_logo.png

    \section main_dev Documentation for Developers

    NetIDMgr is a credentials manager, which currently manages
    Kerberos IV, Kerberos V and AFS credentials.  This document
    describes the API that is implemented by the NetIDMgr system.

    See the following sections for more information :
    - \subpage license
    - \subpage bugs
    - \subpage releases

    &copy; 2004-2007 Massachusetts Institute of Technology
*/

/*!
    \page license License agreement and credits

    NetIDMgr is distributed under the MIT License.

    \section license_l MIT License

    Copyright &copy; 2004,2005,2006,2007 Massachusetts Institute of Technology
 
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy,
    modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

    \section license_credits Credits

    NetIDMgr was developed at the Massachusetts Institute of
    Technology.

    <a href="http://web.mit.edu/is">Information Services and
    Technology</a> at <a href="http://web.mit.edu">Massachusetts
    Institute of Technology</a>
*/

/*! \page bugs Reporting bugs

    NetIDMgr bugs can be reported to 
    <a href="mailto:kfw-bugs@mit.edu">kfw-bugs@mit.edu</a> for now.

    In the future, there will actually be a place to track NetIDMgr bugs.

    When reporting bugs, please include as much information as
    possible to help diagnose the problem.  More guidelines about
    reporting bugs will appear here at some point in time.

    \image html khimaira_logo_small.png
*/

/*! \page releases Prior releases

    - <b>0.1.1</b> First Alpha release <em>Nov 01, 2005</em>\n
      Released along with Kerberos for Windows 3.0.0 beta.

    - <b>0.1.2</b> Second Alpha release <em>Nov 30, 2005</em>\n
      Released along with Kerberos for Windows 3.0.0 beta 2.
*/

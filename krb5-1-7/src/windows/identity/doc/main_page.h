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

/*! \mainpage Network Identity Manager

    \image html khimaira_logo.png

    \section main_dev Documentation for Developers

    Network Identity Manager is a credentials manager, which is
    capable of managing Kerberos v5, Kerberos v4, Andrew File System,
    and Kerberized Certificate Authority credentials.  This document
    describes the API that is implemented by the Khimaira framework
    upon which Network Identity Manager is based.

    See the following sections for more information :
    - \subpage license
    - \subpage bugs
    - \subpage releases

    &copy; 2004-2007 Massachusetts Institute of Technology

    &copy; 2005-2007 Secure Endpoints Inc.
*/

/*!
    \page license License agreement and credits

    Network Identity Manager is distributed under the MIT License.

    \section license_l MIT License

    Copyright &copy; 2004,2005,2006,2007 Massachusetts Institute of Technology

    Copyright &copy; 2005,2006,2007 Secure Endpoints Inc.
 
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

    Network Identity Manager was developed at the Massachusetts Institute of
    Technology in partnership with Secure Endpoints Inc.

    <a href="http://web.mit.edu/is">Information Services and
    Technology</a> at <a href="http://web.mit.edu">Massachusetts
    Institute of Technology</a>

    <a href="http://www.secure-endpoints.com">Secure Endpoints Inc.</a>
*/

/*! \page bugs Reporting bugs

    Network Identity Manager bugs can be reported to 
    <a href="mailto:kfw-bugs@mit.edu">kfw-bugs@mit.edu</a> or 
    <a href="mailto:netidmgr@secure-endpoints.com">netidmgr@secure-endpoints.com</a>

    When reporting bugs, please include as much information as
    possible to help reproduce the problem.

    \image html khimaira_logo_small.png
*/

/*! \page releases Prior releases

    The following is a list of releases of Network Identity Manager.
    Whenever there is an addition to the API or a significant change
    in behavior, the API version is incremented.  A plug-in that is
    developed against a particular version of the API will be
    compatible with any release of Network Identity Manager that
    implements that version of the API.

    The Network Identity Manager version number is set as the file and
    product version of <tt>nidmgr32.dll</tt>.

    The API version refers to the version of the API exposed by
    <tt>nidmgr32.dll</tt>.  A plug-in that was built against a
    particular API version will be compatible with any version of
    Network Identity Manager whose API version is the same.

    - <b>1.3.0.0</b> Kerberos for Windows 3.2 <em>August 15, 2007</em>\n
      API version : <b>9</b>

    - <b>1.2.0.2</b> Kerberos for Windows 3.2 Beta 2 <em>Apr 11, 2007</em>\n
      API version : <b>8</b>

    - <b>1.2.0.1</b> <em>Apr 06, 2007</em>\n
      API version : <b>8</b>

    - <b>1.2.0.0</b> Kerberos for Windows 3.2 Beta 1 <em>Mar 29, 2007</em>\n
      API version : <b>8</b>

    - <b>1.1.11.0</b> <em>Mar 20, 2007</em>\n
      API version : <b>8</b>

    - <b>1.1.10.0</b> <em>Feb 28, 2007</em>\n
      API version : <b>8</b>

    - <b>1.1.9.0</b> <em>Jan 20, 2007</em>\n
      API version : <b>7</b>

    - <b>1.1.8.0</b> Kerberos for Windows 3.1 Final <em>Nov 22, 2006</em>\n
      API version : <b>6</b>

    - <b>1.1.6.0</b> Kerberos for Windows 3.1 Beta 4 <em>Nov 17, 2006</em>\n
      API version : <b>6</b>

    - <b>1.1.4.0</b> Kerberos for Windows 3.1 Beta 3 <em>Nov 08, 2006</em>\n
      API version : <b>6</b>

    - <b>1.1.2.0</b> <em>Oct 09, 2006</em>\n
      API version : <b>6</b>

    - <b>1.1.0.2</b> <em>Sep 21, 2006</em>\n
      API version : <b>6</b>

    - <b>1.1.0.1</b> <em>Jul 19, 2006</em>\n
      API version : <b>5</b>

    - <b>1.1.0.0</b> <em>Mar 08, 2006</em>\n
      API version : <b>5</b>

    - <b>1.0.0.0</b> Kerberos for Windows 3.0 <em>Dec 05, 2005</em>\n
      API version : <b>4</b>

    - <b>0.1.2.0</b> Second Alpha release <em>Nov 30, 2005</em>\n
      API version : <b>3</b>\n
      Released along with Kerberos for Windows 3.0 beta 2.

    - <b>0.1.1</b> First Alpha release <em>Nov 01, 2005</em>\n
      Released along with Kerberos for Windows 3.0 beta.

*/

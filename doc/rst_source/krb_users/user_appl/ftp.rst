ftp
=============

The Kerberos V5 FTP program works exactly like the standard UNIX FTP program, with the following Kerberos features added:

=========================== ===================================================================================================
-k *realm*                  requests tickets for the remote host in the specified realm, instead of determining the realm itself.
-f                          requests that your tickets be forwarded to the remote host. The -f argument must be the last argument on the command line.
protect *level*             (issued at the ftp> prompt) sets the protection level. **clear** is no protection; **safe** ensures data integrity by verifying the checksum, and **private** encrypts the data. Encryption also ensures data integrity.
=========================== ===================================================================================================

For example, suppose *jennifer* wants to get her RMAIL file from the directory *~jennifer/Mail*, on the host *daffodil.mit.edu*. She wants to encrypt the file transfer. The exchange would look like the following::

     shell% ftp daffodil.mit.edu
     Connected to daffodil.mit.edu.
     220 daffodil.mit.edu FTP server (Version 5.60) ready.
     334 Using authentication type GSSAPI; ADAT must follow
     GSSAPI accepted as authentication type
     GSSAPI authentication succeeded
     200 Data channel protection level set to private.
     Name (daffodil.mit.edu:jennifer):
     232 GSSAPI user jennifer@ATHENA.MIT.EDU is authorized as jennifer
     230 User jennifer logged in.
     Remote system type is UNIX.
     Using binary mode to transfer files.
     ftp> protect private
     200 Protection level set to Private.
     ftp> cd ~jennifer/MAIL
     250 CWD command successful.
     ftp> get RMAIL
     227 Entering Passive Mode (128,0,0,5,16,49)
     150 Opening BINARY mode data connection for RMAIL (361662 bytes).
     226 Transfer complete.
     361662 bytes received in 2.5 seconds (1.4e+02 Kbytes/s)
     ftp> quit
     shell%

------------------

Feedback:

Please, provide your feedback at krb5-bugs@mit.edu?subject=Documentation___users_appl


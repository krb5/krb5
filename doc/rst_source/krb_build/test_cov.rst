
Test coverage
=================

It is considered good practice to develop and maintain the test suite with high level 
of test coverage, i.e. the tests that execute every single statement, every line of the code and
then validate the result.

The GNU's *gcov* is a tool that analyses the frequency of execution of each line of the code.
For more details see GNU documentation http://gcc.gnu.org/onlinedocs/gcc/Gcov.html

To invoke *gcov* on *krb5* tree, do *configure* with the following options and run the tests::

    ./configure CFLAGS="-fprofile-arcs -ftest-coverage -O0" LIBS=-lgcov 
    make
    make check

It will result into creation of the new helper files with the extentions *gcno* and *gcda*.

To validate the test coverage of the specific file, change the directory to
its location and run ::

    gcov -o filename.so.gcno filename.c 

To see the test coverage of the *filename.c* open a newly created file *filename.c.gcov* in the editor.

Some recent test coverage result can be found at the http://k5wiki.kerberos.org/wiki/Test_coverage 







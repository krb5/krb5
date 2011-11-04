How to build this documentation from the source
==================================================

Pre-requisites:

  - Sphinx 1.0.4 or higher (See http://sphinx.pocoo.org) with “autodoc” extension installed.


How to build the Sphinx based documentation without references to API documentation
---------------------------------------------------------------------------------------

To generate documentation in the *html* format, from the *trunk/doc/rst_source*  run::

      sphinx-build .  output_dir

To produce manpages run::

      sphinx-build -b man  .  output_dir

.. note::   The manpages output is controled by *man_pages* tag in the Sphinx configuration file 
            *trunk/doc/rst_source/conf.py*.

How to deploy the Doxygen output in Sphinx project.
----------------------------------------------------

The text below is meant to give the instructions on how to incorporate MIT Kerberos API reference 
documentation into Sphinx document hierarchy.  
The Sphinx API documentation can be constructed without (:ref:`Part_A`) or with (:ref:`Part_B`) the bridge 
to the original Doxygen HTML output.

Pre-requisites:

   - python 2.5+ with *Cheetah, lxml* and  *xml* extension modules installed;
   - Doxygen documentation generator (http://www.doxygen.org) installed;
   - For "Part B" only:
       -    Sphinx “doxylink” extension;
       -    Doxygen HTML output

.. _Part_A:

Part A:    Transforming Doxygen XML output into reStructuredText (rst)  without the bridge to Doxygen HTML output.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


1.    Delete lines containing text "Doxygen reference" from the template files 
      *func_document.tmpl* and *type_document.tmpl* located in trunk/doc/rst_tools directory;

2.    In the Doxygen configuration file (trunk/src/Doxyfile) set *GENERATE_XML* flag  to YES. 
      Generate Doxygen XML output. 
      To do so from the command line from the source directory (trunk/src) run::

         doxygen

      The *XML_OUTPUT* tag specifies the location of the Doxygen XML output. 
      The default location for this setup is *trunk/out/xml*.

3.    Suppose the Doxygen XML output is located in *trunk/out/xml* directory and
      the desired name for the reStructuredText  output directory is *rst_dir*. 
      From *trunk/doc/rst_tools* run::

           python doxy.py –i  ../../out/xml –o rst_dir –t func

      This will result in the storing the API function documentation files in *rst* format in the *rst_dir*. 

      .. note:: The file names are constructed based on the function name. 
                For example, the file for krb5_build_principal() will be krb5_build_principal.rst

      Run::

           python doxy.py –i ../../out/xml –o rst_dir –t typedef

      It is similar to the API function conversion, but for data types. The result will be stored under *rst_dir/types* directory

      Alternatively, running::

         python doxy.py –i  ../../out/xml  –o rst_dir

         or
 
         python doxy.py –i  ../../out/xml  –o rst_dir -t all

      converts Doxygen XML output into reStructuredText format files both for API functions and data types;

4.    In *trunk/doc/krb_appldev/index.rst* add the following section to point to the API references::

         .. toctree::
             :maxdepth: 1

             refs/index.rst

5.    Copy the content of 

         - *rst_dir* into *krb_appldev/refs/api* directory, and 
        
         - *rst_dir/types* into *krb_appldev/refs/types* directory;

6.    Rebuild Sphinx source. From the *trunk/doc/rst_source*  run::

         sphinx-build .  output_dir


.. _Part_B:


Part B:    Bridge to Doxygen HTML output.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Transform Doxygen XML output into reStructuredText.
   In src/Doxygen configuration file request generation of the tag file and XML output::

       GENERATE_TAGFILE       = krb5doxy.tag
       GENERATE_XML           = YES

2. Modify Sphinx conf.py file to point to the “doxylink” extension and Doxygen tag file::

      extensions = ['sphinx.ext.autodoc', 'sphinxcontrib.doxylink']
      doxylink = { ' krb5doxy' : ('/tmp/krb5doxy.tag, ' doxy_html_dir ') }

   where *doxy_html_dir* is the location of the Doxygen HTML output

3.  Continue with steps 3 - 6 of Part A.




# make source-tree symlinks to generated source-files,
# so that synctree-generated shadows of the source-tree will have access
# to the generated files.
# this should be run in the shadow-dir, after synctree completes.

#attach krb5
#synctree -s /mit/krb5/src -d .
foreach f ( include/krb5/error_tables lib/error_tables kdc comerr ss)
   ln -s /mit/krb5/build/@sys/${f}/*_err.[ch] ${f}
   ls -ls ${f}/*_err.[ch]
   end

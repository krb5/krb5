d=`pwd`
if ! test -d $d/trunk/src ; then echo "Not in top-level.  Punting."
else
  title kerberos hacking
  add svn
  cp $KRB5CCNAME $KRB5CCNAME.backup
  : cd $d/src
  kpath=$d/trunk/src
  export LD_LIBRARY_PATH=$kpath/lib:$LD_LIBRARY_PATH
  PATH=${kpath}/clients/kvno:${kpath}/clients/klist:${kpath}/appl/telnet/telnet:$PATH
  alias kcopy="cp $KRB5CCNAME.backup $KRB5CCNAME"
  alias kback="cp $KRB5CCNAME $KRB5CCNAME.backup"
fi

#!/usr/local/bin/perl -w
$_=<STDIN>;
$_=<STDIN> while $_!~/^#\s*TEMPLATE BEGINS HERE\s*$/;
$_=<STDIN> while /^# *TEMPLATE BEGINS HERE\s*$/;
while (<STDIN>) { y#\245:\304\266#\*/:\\#; print; }

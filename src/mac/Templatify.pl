#!/usr/local/bin/perl -w
while (<STDIN>) { last if /^#  TEMPLATE BEGINS HERE$/ }
do { y#\245:\304\266#\*/:\\#; print } while (<STDIN>);

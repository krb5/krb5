#!/usr/bin/perl

# Copyright 2026 Massachusetts Institute of Technology.
# All Rights Reserved.
#
# Export of this software from the United States of America may
#   require a specific license from the United States Government.
#   It is the responsibility of any person or organization contemplating
#   export to obtain such a license before exporting.
#
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of M.I.T. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  Furthermore if you modify this software you must label
# your software as modified software and not distribute it in such a
# fashion that it might be confused with the original M.I.T. software.
# M.I.T. makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.

use strict;
use warnings;
use File::Spec;

sub read_file {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "Cannot read $path: $!\n";
    local $/;
    my $contents = <$fh>;
    close($fh) or die "Cannot close $path: $!\n";
    return $contents;
}

sub get_number_define {
    my ($contents, $name, $path) = @_;
    return $1 if $contents =~ /^#define\s+\Q$name\E\s+(\d+)\s*$/m;
    die "Cannot find $name in $path\n";
}

sub replacement {
    my ($name, $values, $path) = @_;
    die "Unknown substitution \@$name\@ in $path\n"
        unless exists($values->{$name});
    return $values->{$name};
}

@ARGV == 4 or die
    "Usage: $0 bits patchlevel.h template-directory output-directory\n";
my ($bits, $version_path, $template_dir, $output_dir) = @ARGV;
$bits eq '32' || $bits eq '64' or die "Invalid bitness: $bits\n";

my $version_header = read_file($version_path);
my $major = get_number_define($version_header, 'KRB5_MAJOR_RELEASE',
                              $version_path);
my $minor = get_number_define($version_header, 'KRB5_MINOR_RELEASE',
                              $version_path);
my $patch = get_number_define($version_header, 'KRB5_PATCHLEVEL',
                              $version_path);
my $version = "$major.$minor";
$version .= ".$patch" if $patch != 0;
$version .= "-$1"
    if $version_header =~ /^#define\s+KRB5_RELTAIL\s+"([^"]+)"\s*$/m;

my %values = (
    prefix => '${pcfiledir}/../..',
    exec_prefix => '${prefix}',
    libdir => '${prefix}/lib',
    includedir => '${prefix}/include',
    DEFCCNAME => 'API:',
    DEFKTNAME => 'FILE:%{WINDOWS}\\krb5kt',
    DEFCKTNAME => 'FILE:%{WINDOWS}\\krb5clientkt',
    KRB5_VERSION => $version,
    KRB5_PC_LIBS => "-lkrb5_$bits -lkrbcc$bits -lxpprof$bits " .
                    "-lkfwlogon -lcomerr$bits -lk5sprt$bits",
    KRB5_PC_LIBS_PRIVATE => "-lk5sprt$bits",
    GSSAPI_PC_LIBS => "-lgssapi$bits"
);

my @files = qw(krb5-gssapi krb5 mit-krb5-gssapi mit-krb5);
for my $name (@files) {
    my $template_path = File::Spec->catfile($template_dir, "$name.pc.in");
    my $output_path = File::Spec->catfile($output_dir, "$name.pc");
    my $contents = read_file($template_path);
    $contents =~ s/\@([A-Za-z0-9_]+)\@/
        replacement($1, \%values, $template_path)/gex;
    open(my $fh, '>', $output_path) or die "Cannot write $output_path: $!\n";
    print $fh $contents or die "Cannot write $output_path: $!\n";
    close($fh) or die "Cannot close $output_path: $!\n";
}

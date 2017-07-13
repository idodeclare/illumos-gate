#!/usr/perl5/bin/perl
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
#
# Copyright 2017 Chris Fraire <cfraire@me.com>.
#

# Compare the contents of two files byte by byte up to a specified limit
# of bytes. Exit 0 if the files are identical within the limit or non-zero
# if there are differences or upon I/O failure.

use strict;
use warnings;

our $BLOCKSIZE = 512;
our ($file1, $file2, $numbytes);

my $usage = "Usage: $0 <file1> <file2> <numbytes>\n";
die $usage if @ARGV != 3;
($file1, $file2, $numbytes) = @ARGV;

open(my $fh1, "<", $file1) or die "Can't open < $file1: $!";
open(my $fh2, "<", $file2) or die "Can't open < $file2: $!";

for (my $o = 0; $o < $numbytes; $o += $BLOCKSIZE) {
	my $n = $numbytes - $o;
	$n = $BLOCKSIZE if $n > $BLOCKSIZE;

	my ($d1, $d2);
	my $r1 = sysread($fh1, $d1, $n);
	die "file1 I/O error: $!" if ! defined $r1;

	my $r2 = sysread($fh2, $d2, $n);
	die "file2 I/O error: $!" if ! defined $r2;

	if ($r1 != $r2) {
		die "file1 and file2 are different lengths";
	} elsif (($d1 cmp $d2) != 0) {
		die "file1 and file2 differ at offset $o";
	} elsif ($r1 == 0) {
		warn "Both files ended early at offset $o";
	}
}

close($fh1) or die "file1 close failed: $!";
close($fh2) or die "file2 close failed: $!";

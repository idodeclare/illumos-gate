#!/usr/bin/perl
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.illumos.org/license/CDDL (originally
# http://www.opensolaris.org/os/licensing).
#
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 2017, Chris Fraire <cfraire@me.com>.
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
	}
	elsif (($d1 cmp $d2) != 0) {
		die "file1 and file2 differ at offset $o";
	}
	elsif ($r1 == 0) {
		warn "Both files ended early at offset $o";
	}
}

close($fh1) or die "file1 close failed: $!";
close($fh2) or die "file2 close failed: $!";

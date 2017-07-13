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

# Write n blocks to a specified output file. Write p% of them as fully-zero
# blocks and the rest of them as blocks where randomly 90% of the bits are
# 1. If p% is less than 100%, then make sure the final blocks are NULs to
# test a final lseek.
#
# Exit 0 on success or non-zero on failure.

use strict;
use warnings;
use Getopt::Std;

our $BLOCKSIZE = 512;
our $DEFAULTPCTZERO = 99;
our ($opt_f, $opt_b, $opt_K, $opt_p);

my $usage = "Usage: $0 -f <outfile> -b <numbytes>
		[-K <blocksize>] [-p <% zero blocks>]

	-K blocksize default is $BLOCKSIZE
	-p % zero blocks default is $DEFAULTPCTZERO\n\n";
die $usage if !getopts("f:b:K:p:")
    || ! defined $opt_f
    || ! defined $opt_b
    || $opt_b < 1
    || (defined $opt_K && $opt_K < 1)
    || (defined $opt_p && ($opt_p < 0 || $opt_p > 100));

$opt_K = $BLOCKSIZE if ! defined $opt_K;
$opt_p = $DEFAULTPCTZERO if ! defined $opt_p;

open(my $fh, ">", $opt_f) or die "Can't open > $opt_f: $!";

for (my $i = 0; $i < $opt_b; $i += $opt_K) {
	# output K bytes except possibly for the final block
	my $n = $opt_b - $i;
	$n = $opt_K if $n > $opt_K;

	my $is_last_block = $i + $n >= $opt_b;
	my $is_zero = $opt_p == 0 ? 0 : $opt_p == 100 ? 1
	    : $is_last_block ? 1 : rand() * 100 <= $opt_p;
	for (my $j = 0; $j < $n; ++$j) {
		print $fh pack('C', $is_zero ? 0 : rand() >= .1 ? 1 : 0);
	}
}

close($fh) or die "close failed: $!";

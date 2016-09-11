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
# Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
#

# Build contents of a .gitignore from relative path-files in @ARGV, and write
# the contents if the .gitignore does not exist in the cwd or if the contents
# differ. The relative paths are ensured to be anchored to ./ so that the
# .gitignore rules are not inherited in sub-directories.
#
# Some illumos Makefiles clobber macros that actually contain committed files
# (e.g., usr/src/cmd/cmd-inet/usr.lib/wanboot/bootlog-cgi/Makefile clobbering
# $(PROG) which contains committed bootlog-cgi). Support, therefore, an -x
# switch to specify files that should be excluded if they appear otherwise in
# @ARGV. E.g, for the previous example, the .DONE recipe might be:
# $(MAKE_GITIGNORE) -x bootlog-cgi $(PROG) .
#
# Some illumos Makefiles copy objects up and out of the current directory
# using ../, which .gitignore cannot handle as it is descendant-only. As a
# workaround, for @lines which go up a limited number of levels, write a
# translation of those lines to an intermediate file, ".gitignore-<subdir>",
# in the parent directory (e.g., ../.gitignore-i386 or ../../.gitignore-a-b),
# to be incorporated by this script when called in that parent directory.
#
# A rare few illumos Makefiles execute multiple times in the same working
# directory for iterating CURTYPE values (e.g., "library" and "standalone"
# for libumem). Since normally an execution of this script would clobber
# previous executions' .gitignore contents, support a -d <discriminator>
# switch to write ".gitignore,<discriminator>," files in the current directory
# which will be accumulated into a final .gitignore in the same "addendum"
# method used for ".gitignore-<subdir>" translations.

use strict;
use warnings;
use Cwd qw(realpath getcwd);
use File::Basename;
use File::Spec::Functions qw(abs2rel splitdir);
use Getopt::Long;

our $cwd = realpath(getcwd);
affirm_in_git_repo($cwd);

our $gitignore = "$cwd/.gitignore";

our ($opt_d, $opt_v, @opt_x, $disc);
GetOptions(
    'v' => \$opt_v,
    'd=s' => \$opt_d,
    'x=s' => \@opt_x)
    or die "Usage: $0 [-v] [-d <discriminator>] "
        . "[-x file-path]* [file-path ...]\n";

# (the commas will be marker characters for discriminated .gitignore files)
$disc = $opt_d ? ",$opt_d," : "";

# Process distinct entries from @ARGV, but "normalize" as .gitignore
# entries--e.g., commenting-out entries whose paths are ../ up and away from
# the current directory and ignoring certain, common entries that are known
# to be handled by the root illumos-gate/.gitignore.
my %uniq;
my @lines = sort { lc($a) cmp lc($b) }
    map { normalize_gitignore_entry($_) }
    grep { my $r = !exists $uniq{$_}; $uniq{$_} = 1; $r; }
    grep { !is_opt_excluded($_) }
    grep { !is_already_ignored($_) } @ARGV;
my $contents = join("", map { s/\z/\n/rx } @lines);

# Write or clean up in parent directories any "subdir" .gitignore*-* files
# originating from this directory. Go up a certain number of levels but not
# above usr/src.
my @dirs = reverse splitdir($cwd);
for (my $j = 0; $j <= 4 && $j < @dirs; ++$j) {
	my $subdir = join("-", reverse @dirs[0..$j]);
	last if $subdir =~ /^usr-src\b/x;
	my $dotdot = join("", map { "../" } @dirs[0..$j]);
	my $gitignore_sub = "$cwd/$dotdot.gitignore$disc-$subdir";

	# "addenda" are any files which are located ../ up and out of cwd
	my @addenda = map { s`^\#\Q$dotdot`/`rx }
	  grep { m`^\#\Q$dotdot\E[^\.]`x } @lines;
	if (@addenda > 0) {
		my $addendum = join("", map { s/\z/\n/rx } @addenda);
		write_if_different($gitignore_sub, $addendum);
	} elsif (-f $gitignore_sub) {
		print "Removing defunct $gitignore_sub.\n" if $opt_v;
		unlink $gitignore_sub;
	}

	# if -d is used, that makes regular, non-discriminated
	# .gitignore-<subdir> files ineligible, so clear any that exist
	if ($opt_d) {
		my $gitignore_subnodisc = "$cwd/$dotdot.gitignore-$subdir";
		if (-f $gitignore_subnodisc) {
			print "Removing defunct $gitignore_subnodisc.\n" if
			    $opt_v;
			unlink $gitignore_subnodisc;
		}
	} else {
		# otherwise, clean up any formerly-discriminated files
		map { unlink } glob "$cwd/$dotdot.gitignore,*,-$subdir";
	}
}

# if -d is used, write a cwd ".gitignore,<discriminator>," file, and then
# reset $contents
if ($opt_d) {
	my $gitignore_disc = "$gitignore$disc";
	write_if_different($gitignore_disc, $contents);
	$contents = "";
} else {
	# otherwise, clean up any formerly-discriminated files
	map { unlink } glob "$gitignore,*,*";
}

# incorporate addenda created from related runs of script including, if
# applicable, for -d <discriminator> above
foreach my $addendum (glob "$cwd/.gitignore-* $cwd/.gitignore,*") {
	$contents .= "# addendum\n";
	$contents .= `/bin/cat "$addendum"`;
}

# write or clear the accumulated contents of the cwd .gitignore
write_if_different($gitignore, $contents);

#------------------------------------------------------------------------------

# Filter out some commonly appearing items in clean/clobber targets which are
# already ignored in illumos-gate/.gitignore. This is not comprehensive, but
# it greatly reduces the redundancy.
sub is_already_ignored {
	my ($file) = @_;
	return $file eq "lint.out"
	    || $file =~ m`^debug(?:32|64)/`x
	    || ($file =~ m`^\.([^/]*)\z`x && length($1) < 5) # .po not .bashrc
	    || $file =~ /\.(?:class|exec|jar|ln|o|tmp)\z/x;
}

# return true if the arg matches an -x <file-path> switch
sub is_opt_excluded {
	my ($file) = @_;
	return 0 if @opt_x < 1;
	return 0 < grep { $_ eq $file } @opt_x;
}

# unlink existing $file if $contents is empty; otherwise, rewrite $file if
# contents differ
sub write_if_different {
	my ($file, $contents) = @_;

	my $has_file = -f $file;
	printf("$file exists: %s\n", $has_file ? "yes" : "no") if $opt_v;

	if ($contents eq "") {
		unlink $file if $has_file;
	}
	elsif (!$has_file or !is_equal_contents($file, $contents)) {
		open(my $fh, ">$file")
		    or die "Error opening $file for writing\n";
		print $fh $contents or die "Error writing $file\n";
	}
}

# return true if $filename has text contents equal to $contents
sub is_equal_contents {
	my ($filename, $contents) = @_;
	local $/;

	open(my $fh, "<$filename") or die "Error opening $filename\n";
	my $fcontents = <$fh>;
	die "Error reading $filename\n" if ! defined $fcontents;
	my $is_equal = $contents eq $fcontents;

	printf("$gitignore has matching content: %s\n", $is_equal ? "yes" :
	    "no") if $opt_v;
	return $is_equal;
}

# normalize a file path to a .gitignore entry:
# *) for symlinks, if the link is up and out of the cwd (e.g., ../a/foo),
#    then leave entry as a comment in .gitignore;
# *) for files, verify all paths using realpath. If invalid, leave entry as
#    comment (##) in .gitignore. Make absolute paths into relative paths in
#    case the absolute path was up and out of cwd (for .gitignore-<subdir>).
# *) lastly, normalize entries to .gitignore syntax, anchoring them to the
#    cwd (e.g., [relative] a/b/foo normalized to [anchored] /a/b/foo).
sub normalize_gitignore_entry {
	my ($entry) = @_;

	if ($entry =~ m`/.`x) {
		if (-l $entry) {
			my $clink = condense_link($entry);
			my $rel = abs2rel($clink, $cwd);
			# the double-# prevents pattern-matching for @addenda
			return "##$entry" if !defined $rel;
			$entry = $rel;
			return "#$entry" if !defined $clink ||
			    $clink !~ m`^\Q$cwd/`x;
			# otherwise, leave $entry as is
		} else {
			my $realentry = realpath($entry);
			# the double-# prevents pattern-matching for @addenda
			return "##$entry" if !defined $realentry;

			if ($entry =~ m`^/`x) {
				my $rel = abs2rel($entry, $cwd);
				# the double-# prevents pattern-matching for @addenda
				return "##$entry" if !defined $rel;
				$entry = $rel;
				# this value is only used if the realpath is up and out of cwd
			}
			return "#$entry" if $realentry !~ m`^\Q$cwd/`x;
			$entry = $realentry;
			$entry =~ s/^\Q$cwd//x;
		}
	}

	# ensure a trailing / for a directory (but not a dir-symlink or else Git
	# is confused)
	$entry .= "/" if $entry !~ m`/\z`x && -d $entry && !-l $entry;

	# translate to anchored .gitignore form
	$entry =~ s`^\./`/`x;
	$entry =~ s`^(?!/)`/`x;
	return $entry;
}

# Condense the path of a known symlink that is relative to cwd in order to
# produce an absolute path (illumos-gate has no directory symlinks, so naive
# condensation of ../ is ok). E.g., ../../foobar will be condensed w.r.t.
# /code/illumos-gate/usr/src/abc/def/ as /code/illumos-gate/usr/src/foobar.
sub condense_link {
	my ($link) = @_;
	return $link if $link =~ m`^/`x;

	my $lroot = $cwd;
	$link =~ s`^(\./)+``x;
	while ($link =~ s`^\Q../``x) {
		$link =~ s`^(\./)+``x;
		$lroot =~ s`/[^/]+\z``x;
	}
	return "$lroot/$link";
}

# Confirm that cwd or above is a Git repo (-d .git) or else short-circuit
# any generation of .gitignore* i.e., if a build is run from an archive of
# or a Mercurial repo of illumos-gate.
sub affirm_in_git_repo {
	my ($p) = @_;

	chop $p if length($p) > 1 && substr($p, -1, 1) eq "/";
	do {
		if (-d "$p/.git") {
			return;
		} else {
			(undef, $p) = fileparse($p);
			chop $p;
		}
	} while (length($p) > 0 && $p ne "./");

	warn "noop: Not a git repository"
	    . " (or any of the parent directories): .git\n"
	    if exists $ENV{MAKE_GITIGNORE_DEBUG};
	exit;
}

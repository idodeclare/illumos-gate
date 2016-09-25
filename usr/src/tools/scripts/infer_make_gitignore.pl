#!/usr/bin/perl -p -i
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

# Examine files specified in @ARGV and possibly add or append a command to run
# $(MAKE_GITIGNORE) in any Makefile's .DONE target.
#
# This script is limited to processing files named "Makefile" plus a small
# set of exceptions found empirically (e.g., Makefile.solaris for grub). The
# @ARGV values can be in any relative directory from cwd, but cwd must be
# the root of the illumos-gate checkout so that a value for the SRC macro can
# be assumed.
#
# The macros to pass to the execution of $(MAKE_GITIGNORE) are inferred from
# a search of the text resulting from a Perl-only preprocessing of the
# Makefile to retrieve its full content by recursively loading the text of
# any "include"-d files. "clean"- and "clobber"-style targets are then
# searched for simple references to macros (e.g., $(FOO) or $(FOO)* but not
# $(FOO:%.x=bar/%.y).
#
# Complex references in clean/clobber targets should be refactored to
# distinct, simple macros for use by this script and also to encourage
# reusability between the clean/clobber targets and the .DONE target used
# for MAKE_GITIGNORE.
#
# ("make -D" was considered, but while that command "displays the text of the
# makefiles read in", it actually displays the text after round-1 of macro
# expansion, but this script needs the raw text).
#
# A rare few illumos Makefiles execute multiple times in the same working
# directory for iterating CURTYPE values (e.g., "library" and "standalone"
# for libumem). This script detects CURTYPE in order to call MAKE_GITIGNORE
# with the -d <discriminator> switch.
#
# Also, another rare few illumos Makefiles include in their clean/clobber
# recipes (though not executed) some committed files (e.g.,
# usr/src/cmd/cmd-inet/usr.lib/wanboot/bootlog-cgi/Makefile "clobbering"
# $(PROG) which contains committed bootlog-cgi). This script recognizes a
# special macro, UNIGNOREFILES, in order to call MAKE_GITIGNORE also with
# -x <file-path> switch(es).
#
# Following are examples of macro matches that might be found in
# clean/clobber recipes: $(CLEANFILES), $(CLEAN_FILES), $(PROG)* #.

use strict;
use warnings;
use Cwd;
use File::Basename;
use Getopt::Std;
our ($archdir, $cwd, $didname, $mach, %macros, $fullpath, $fullname,
  $inclpathadj, @includes, @oktoskip, $usrsrc, $worktext, $opt_v, $opt_n);

BEGIN {
	die "Error: need to be in illumos-gate root\n" if ! -d ".git";
	$cwd = getcwd;

	# $(SRC) is common macro used in makefile include statements
	$usrsrc = "$cwd/usr/src";
	# $(MACH) is common macro used in makefile include statements
	$mach = `uname -p`;
	chomp $mach;

	die "Usage: $0 [-n] [-v] [makefile-path ...]\n" if !getopts('vn');

	# do this last and especially after chomp
	undef $/;
}

my ($mname, $mpath) = fileparse($ARGV);
undef $inclpathadj;

# generally only "Makefile" needs a .DONE-make_gitignore, but there are some
# exceptions found empirically
if ($mname eq "Makefile") {
	# ok, no path adjustment necessary
}
# usr/src/grub/... directive: $(MAKE) -f Makefile.solaris
elsif ($mname eq "Makefile.solaris") {
	# ok, no path adjustment necessary
}
# usr/src/cmd/ptools
elsif ($mpath =~ m`/ptools/$`) {
	# directive: include ../../Makefile.bld
	if ($mname eq "Makefile.bld") {
		$inclpathadj = qr`^\Q../../`;
	}
	# directive: $(MAKE) -f ../Makefile.ptool
	elsif ($mname eq "Makefile.ptool") {
		$inclpathadj = qr`^\Q../`;
	}
	else {
		next;
	}
}
else {
	# no other Makefile* are eligible
	next;
}

$fullpath = pathjoin($cwd, $mpath);
$fullname = "$fullpath$mname";
$didname = 0;   # set to true on first mywarn for $ARGV
@includes = (); # will be appended with arguments to "include"
%macros = ();   # macros gleaned to be part of clean/clobber-type recipes
$worktext = $_; # append-only buffer of content read during recursive loads

my $optdisc = "";  # discriminator fragment to be included in filenames
my $optexcl = "";  # -x handling for UNIGNOREFILES if matched
my $force_make = 0;

{
	# reproduce in Perl the effect of ARCHDIR:sh = cd ..; basename `pwd`
	my ($nn, $pp);
	$pp = $fullpath;
	$pp =~ s`/$``;
	($nn, $pp) = fileparse($pp);
	$pp =~ s`/$``;
	($nn, $pp) = fileparse($pp);
	$archdir = $nn;
}

# $_ is the content of the Makefile, but do a Perl-only preprocessing of the
# Makefile to expand ^include-d files and get the full content as $alltext,
# with "include" directives replaced inline with loaded (recursive) text.
#
# During the time when files are being recursively loaded, an append-only
# $worktext will be extended with the contents of each file. $worktext,
# out-of-order, suffices for gleaning the definitions of macros as needed.
my $alltext = inline_includes($_, $fullname);

# Remove any existing MAKE_GITIGNORE in a .DONE section (unless -n)
s/^\.DONE\s*:.*\n\K((?:\t\s*\S.*\n)+)   # match multi-line .DONE section,
 /my $v = $1;                           # using the \K keep escape for ease;
  $v =~ s`^\t\s*\$\(MAKE_GITIGNORE\)    # match entire MAKE_GITIGNORE,
    (?:.+\x20\\\n)* .* (?<!\x20\\)\n    # detecting line continuations;
    ``mx;                               # and remove the entire command
  $v
 /mxe if !$opt_n;

my @macros = ();

# CURTYPE indicates that -d <discriminator> is needed
if ($alltext =~ /^(CURTYPE)\s*=/m) {
	$optdisc = qq[-d \$($1) ];
}

# UNIGNOREFILES indicates that -x <filepath> is needed
if ($alltext =~ /^(UNIGNOREFILES)\s*=/m) {
	$optexcl = qq[\$($1:%=-x %) ];
}

# The following macros conventionally indicate some derived files that are
# created by the Makefile and are used just as one signal that a run of
# MAKE_GITIGNORE will be needed.
if ($alltext =~ /^BINPROG|CLASSES|DERIVED_FILES|ETCPROG
  |INITPROG|JAR_FILE|JNIH|LIBPROG|MANLINKS|MODULE|OBJECTS|PROG\s*=
  /mx) {
	$force_make = 1;
}

# all...: target for $(SUBDIRS) are used as one signal that a run of
# MAKE_GITIGNORE will be needed.
if ($alltext =~ /^all\b[^:]*:(?!=)(.*\n
  (?:\t+\S.*\n)*)/mx && $1 =~ /\$(?:\(SUBDIRS\)|\{SUBDIRS\})/) {
	$force_make = 1;
}

# clean/clobber targets' recipes indicate things to be ignored. Only simple
# macro substitutions (e.g., $(FOO) or $(FOO)*, but not $(FOO:%.c:%.o), etc.)
# are matched. $(RM) and $(MAKE) are filtered out.
foreach my $c ($alltext =~
  /^(?:(?:clean|clobber)(?:_local)?  #line 1
    |local_(?:clean|clobber)         #line 1 (cont)
    |native-clobber                  #line 1 (cont)
    |rpcclean                        #line 1 (cont)
    |pyclobber                       #line 1 (cont)
    )\b[^:]*:(?!=).*\n               #line 1 (cont)
   ((?:\t+\S.*\n)+)                  #lines 2+
  /mxg) {
	push @macros, grep { $_ !~ /\$\((MAKE|RM)\)/ }
	  map { s/\$\K\{([A-Z][A-Z0-9_]+)\}/($1)/r } # curlies to parens
	  $c =~ /(\$(?:\([A-Z][A-Z0-9_]+\)  # e.g., $(FOO_1)
	    |\{[A-Z][A-Z0-9_]+\})\**)       # e.g., ${FOO_1}
	    (?:;|(?!\S)) # followed by semi-colon or not followed by non-wspace
	    /gix;
}

# if any signal to run MAKE_GITIGNORE was inferred...
if ($force_make || @macros > 0) {
	# warn if macro is not found--except for certain file exceptions--
	# but explicitly let ptools/Makefile.bld go to "else"
	if ($alltext !~ /^MAKE_GITIGNORE\b/m && $ARGV !~ m`/ptools/Makefile.bld$`) {
		if (!is_makefile_ok_to_skip($ARGV)) {
			mywarn("\t\$(MAKE_GITIGNORE) is not defined in preprocessed $ARGV\n");
		}
	}
	elsif (!$opt_n) {
		# Filter to unique macros
		my %uniq;
		@macros = grep { my $r = !exists $uniq{$_}; $uniq{$_} = 1; $r; }
		  sort map { s/^(?!\$)(.+)/\$($1)/r } @macros;

		# ensure a .DONE target exists
		if ($alltext !~ /^\.DONE\s*:/m) {
			# ensure adequate spacing at end of file. A quirk of Perl regex is that
			# the following will include all trailing NL...
			s/(\n*)$/length($1) >= 3 ? $1 : "\n\n\n"/es;
			# but the following will replace just before the one, last NL
			s/$/.DONE :/s;
		}

		# Construct a MAKE_GITIGNORE command with line-wrapping
		my $make_gitignore_cmd =  "\t\$(MAKE_GITIGNORE) $optdisc$optexcl";
		my $llen = length($make_gitignore_cmd);
		for (my $i = 0; $i < @macros; ++$i) {
			my $m = $macros[$i];
			$make_gitignore_cmd .= $m;
			$llen += length($m);
			if ($i + 1 < @macros) {
				if ($llen + 1 + length($macros[$i + 1]) > 70) {
					$make_gitignore_cmd .= " \\\n\t  ";
					$llen = 3;
				}
				else {
					$make_gitignore_cmd .= " ";
					$llen += 1;
				}
			}
		}
		$make_gitignore_cmd =~ s/\s+$//;
		$make_gitignore_cmd .= "\n";

		# Append to the .DONE target
		s/^\.DONE\s*:.*\n((?:\t\s*\S.*\n)*)\K   # match multi-line .DONE section,
		 /$make_gitignore_cmd                   # and append a new command
		 /mxe;
	}
}

#----------------------------------------------------------------------------

# Detect recursively-loaded Makefiles, and load their content. Included files
# are all relative to the original Makefile's directory, regardless of the
# depth of inclusion
sub inline_includes {
	my ($content, $file) = @_;

	my $macro_match = qr/
	  (BASEDIR|BOOTSRCDIR|BRAND_SHARED|BUILD_TYPE
	  |CLASS(?:_(?:OBJ|DBG)(?:32|64))?
	  |CMDDIR|CONF_SRCDIR|LIB_BASE|LIBCDIR|LIBMDIR|LIBSTAND_SRC
	  |METASSIST_TOPLEVEL|NDMP_DIR|PLATFORM|PROMIF|PSMBASE|SENDMAIL
	  |SRCDIR|TOPDIR|UTSBASE)
	  /x;
	my $rmacro = qr/\$((?:\($macro_match\)|\{$macro_match\}))/;
	$content =~ s/^include\s+(\S+)/
		my $incl = $1;
		# iteratively substitute any of the known macros above by searching
		# for their definitionsn in $alltext
		while ($incl =~ s`$rmacro`
			mywarn("\tBefore transformation: $incl\n") if $opt_v;
			my $macro = substr($1, 1, length($1) - 2);
			try_get_def($macro)`e) {
		}

		# substitute the values of a few known, external definitions
		$incl =~ s`\$\(ARCHDIR\)`$archdir`g;
		$incl =~ s`\$\(MACH\)`$mach`g;
		$incl =~ s`\$\(REL_PATH\)`..\/`g;
		$incl =~ s`\$\(SRC\)`$usrsrc`g;
		$incl =~ s`$inclpathadj`` if defined $inclpathadj;

		my $fullincl = pathjoin($fullpath, $incl);
		read_include($fullincl, $file)
	/meg;
	return $content;
}

# search for the value of a macro definition--e.g., FOO=(.+)--or else return
# '${FOO}' with curly brace syntax to indicate that it was not found
sub try_get_def {
	my ($macro) = @_;

	return $macros{$macro} if exists $macros{$macro};

	my $isfound = $worktext =~
	  /^(?:\Q$macro\E\s*=(?!:)\s*|\t+\@\Q$macro\E=)(\S*)/m;
	my $yn = $isfound ? "yes" : "no";
	mywarn("\tWas the definition of macro $macro inferred: $yn\n") if $opt_v;
	if ($isfound) {
		$macros{$macro} = $1;
		return $1;
	}
	else {
		# use brace syntax as a clue that a macro def was not found
		return "\${$macro}";
	}
}

# Read the content of a specified file, append the content to $worktext, and
# then transform content with inline_includes before returning it.
sub read_include {
	my ($file, $from) = @_;

	mywarn( "\tAbout to get contents of $file\n") if $opt_v;
	push @includes, $file if -f $file;

	local $/;
	open(my $fh, "<$file") or do {
		mywarn("\tError opening $file from $from\n");
		return "#incl $file";
	};
	my $content = <$fh>;
	(close($fh) && defined $content) or do {
		mywarn("\tError reading $file from $from\n");
		return "#incl $file";
	};

	# worktext is just used for text extraction while included files are being
	# recursively loaded, so order is unimportant
	$worktext .= "\n";
	$worktext .= $content;

	$content = inline_includes($content, $file);
	return $content;
}

# combines $root and $path if $path is relative; else returns $path untouched
sub pathjoin {
	my ($root, $path) = @_;
	return $path if $path =~ m`^/`;
	$root .= "/" if $root !~ m`/$`;
	return "$root$path";
}

# warn, making sure to show $fullname the first time through for an $ARGV
sub mywarn {
	if (!$didname) {
		warn "Processing $fullname\n";
		$didname = 1;
	}
	warn @_;
}

# some Makefiles empirically do not need a MAKE_GITIGNORE cleanup. Ignore
# those explicitly to quiet some warnings.
sub is_makefile_ok_to_skip {
	my ($file) = @_;
	# remove any leading part so $file is relative starting with usr/src/...
	$file =~ s`^.+(?=\b usr/src \b)``x;
	return scalar(grep { $file eq $_ } @oktoskip) > 0;
}

BEGIN {
	my $oklist = <<'END_LIST';
usr/src/cmd/cvcd/sparc/sun4u/Makefile
usr/src/cmd/cvcd/sparc/Makefile
usr/src/cmd/dcs/Makefile
usr/src/cmd/dcs/sparc/Makefile
usr/src/cmd/sendmail/cf/cf/Makefile
usr/src/cmd/prtdscp/sparc/Makefile
usr/src/cmd/prtdscp/Makefile
usr/src/cmd/scsi/sestopo/Makefile
usr/src/cmd/scsi/Makefile
usr/src/cmd/scsi/smp/Makefile
usr/src/cmd/fm/fmtopo/Makefile
usr/src/cmd/fm/fmstat/Makefile
usr/src/cmd/fm/schemes/Makefile
usr/src/cmd/fm/notify/smtp-notify/Makefile
usr/src/cmd/fm/notify/snmp-notify/Makefile
usr/src/cmd/fm/fminject/Makefile
usr/src/cmd/fm/fmadm/Makefile
usr/src/cmd/fm/modules/Makefile
usr/src/cmd/fm/modules/common/sw-diag-response/Makefile
usr/src/cmd/fm/modules/common/Makefile
usr/src/cmd/fm/modules/SUNW,Sun-Blade-T6320/Makefile
usr/src/cmd/fm/modules/SUNW,Netra-T5220/Makefile
usr/src/cmd/fm/modules/SUNW,USBRDT-5240/Makefile
usr/src/cmd/fm/modules/SUNW,Netra-CP3060/Makefile
usr/src/cmd/fm/modules/SUNW,Netra-T5440/Makefile
usr/src/cmd/fm/modules/sun4v/Makefile
usr/src/cmd/fm/modules/SUNW,SPARC-Enterprise/Makefile
usr/src/cmd/fm/modules/SUNW,Netra-CP3260/Makefile
usr/src/cmd/fm/modules/SUNW,SPARC-Enterprise-T5120/Makefile
usr/src/cmd/fm/modules/SUNW,Sun-Fire-T200/Makefile
usr/src/cmd/fm/modules/SUNW,T5140/Makefile
usr/src/cmd/fm/modules/sun4u/Makefile
usr/src/cmd/fm/modules/SUNW,Sun-Blade-T6300/Makefile
usr/src/cmd/fm/Makefile
usr/src/cmd/fm/fmdump/Makefile
usr/src/cmd/fm/eversholt/esc/Makefile
usr/src/cmd/fm/eversholt/eftinfo/Makefile
usr/src/cmd/fm/eversholt/files/Makefile
usr/src/cmd/fm/eversholt/Makefile
usr/src/cmd/fm/ipmitopo/Makefile
usr/src/cmd/prtdiag/sparc/Makefile
usr/src/cmd/make/Makefile
usr/src/cmd/make/lib/Makefile
usr/src/cmd/scadm/sparc/Makefile
usr/src/cmd/mdb/sparc/Makefile
usr/src/cmd/mdb/i86xpv/Makefile
usr/src/cmd/mdb/i86xpv/modules/Makefile
usr/src/cmd/mdb/intel/modules/Makefile
usr/src/cmd/mdb/sun4u/Makefile
usr/src/cmd/mdb/sun4u/modules/unix/Makefile
usr/src/cmd/mdb/sun4u/modules/opl/oplhwd/Makefile
usr/src/cmd/mdb/sun4u/modules/opl/Makefile
usr/src/cmd/mdb/sun4u/modules/lw8/Makefile
usr/src/cmd/mdb/sun4u/modules/lw8/sgenv/Makefile
usr/src/cmd/mdb/sun4u/modules/serengeti/sgsbbc/Makefile
usr/src/cmd/mdb/sun4u/modules/serengeti/Makefile
usr/src/cmd/mdb/i86pc/Makefile
usr/src/cmd/mdb/i86pc/modules/Makefile
usr/src/cmd/mdb/sun4v/modules/mdesc/Makefile
usr/src/cmd/mdb/sun4v/modules/vdsk/Makefile
usr/src/cmd/mdb/sun4v/modules/Makefile
usr/src/cmd/mdb/sun4v/modules/errh/Makefile
usr/src/cmd/mdb/sun4v/modules/unix/Makefile
usr/src/cmd/mdb/sun4v/modules/ldc/Makefile
usr/src/cmd/mdb/sun4v/Makefile
usr/src/cmd/sgs/libelf/demo/Makefile
usr/src/cmd/picl/plugins/common/Makefile
usr/src/cmd/picl/plugins/sun4v/Makefile
usr/src/cmd/picl/plugins/sun4v/lib/Makefile
usr/src/cmd/picl/plugins/lib/Makefile
usr/src/cmd/picl/plugins/sun4u/lib/Makefile
usr/src/cmd/picl/plugins/sun4u/cherrystone/Makefile
usr/src/cmd/picl/plugins/sun4u/silverstone/Makefile
usr/src/cmd/picl/plugins/sun4u/daktari/Makefile
usr/src/cmd/picl/plugins/sun4u/blade/Makefile
usr/src/cmd/picl/plugins/sun4u/chicago/Makefile
usr/src/cmd/picl/plugins/sun4u/lw2plus/Makefile
usr/src/cmd/picl/plugins/sun4u/excalibur/Makefile
usr/src/cmd/picl/plugins/sun4u/lw8/Makefile
usr/src/cmd/picl/plugins/sun4u/schumacher/Makefile
usr/src/cmd/picl/plugins/sun4u/seattle/Makefile
usr/src/cmd/picl/plugins/sun4u/littleneck/Makefile
usr/src/cmd/picl/plugins/sun4u/enchilada/Makefile
usr/src/cmd/picl/plugins/sun4u/grover/Makefile
usr/src/cmd/picl/plugins/sun4u/psvc/Makefile
usr/src/cmd/picl/plugins/sun4u/mpxu/Makefile
usr/src/cmd/picl/plugins/sun4u/chalupa/Makefile
usr/src/cmd/picl/plugins/sun4u/taco/Makefile
usr/src/cmd/picl/plugins/sun4u/boston/Makefile
usr/src/cmd/picl/plugins/sun4u/snowbird/lib/Makefile
usr/src/cmd/picl/plugins/sun4u/sebring/Makefile
usr/src/cmd/picl/plugins/sun4u/ents/Makefile
usr/src/cmd/picl/plugins/Makefile
usr/src/cmd/picl/Makefile
usr/src/cmd/zonestat/Makefile
usr/src/cmd/sckmd/sparc/Makefile
usr/src/cmd/lp/lib/Makefile
usr/src/cmd/svr4pkg/Makefile
usr/src/cmd/hal/addons/Makefile
usr/src/cmd/hal/probing/Makefile
usr/src/cmd/fs.d/udfs/Makefile
usr/src/cmd/fs.d/pcfs/Makefile
usr/src/cmd/fs.d/lofs/Makefile
usr/src/cmd/fs.d/hsfs/Makefile
usr/src/cmd/fs.d/zfs/Makefile
usr/src/cmd/tnf/Makefile
usr/src/cmd/abi/spectrans/Makefile
usr/src/cmd/abi/Makefile
usr/src/cmd/idmap/Makefile
usr/src/cmd/syseventd/daemons/Makefile
usr/src/cmd/syseventd/modules/Makefile
usr/src/cmd/krb5/Makefile
usr/src/cmd/rcap/Makefile
usr/src/man/Makefile
usr/src/ucblib/Makefile
usr/src/uts/sparc/dump/Makefile
usr/src/tools/make/Makefile
usr/src/tools/make/lib/Makefile
usr/src/lib/libmtmalloc/tests/Makefile
usr/src/lib/libprtdiag/sparc/Makefile
usr/src/lib/fm/topo/Makefile
usr/src/lib/fm/topo/maps/Makefile
usr/src/lib/fm/topo/modules/Makefile
usr/src/lib/fm/topo/modules/i86pc/Makefile
usr/src/lib/fm/topo/modules/SUNW,SPARC-Enterprise/Makefile
usr/src/lib/fm/topo/modules/sun4u/Makefile
usr/src/lib/fm/topo/modules/common/Makefile
usr/src/lib/fm/topo/modules/SUNW,Sun-Fire/Makefile
usr/src/lib/fm/topo/modules/sun4v/Makefile
usr/src/lib/fm/topo/modules/SUNW,Sun-Fire-15000/Makefile
usr/src/lib/mpapi/Makefile
usr/src/lib/brand/ipkg/Makefile
usr/src/lib/brand/labeled/Makefile
usr/src/lib/brand/shared/Makefile
usr/src/lib/libsmedia/plugins/Makefile
usr/src/lib/libsmedia/Makefile
usr/src/lib/gss_mechs/mech_dh/Makefile
usr/src/lib/scsi/Makefile
usr/src/lib/scsi/plugins/Makefile
usr/src/lib/scsi/plugins/smp/Makefile
usr/src/lib/scsi/plugins/ses/Makefile
usr/src/lib/scsi/plugins/scsi/Makefile
usr/src/lib/scsi/plugins/scsi/engines/Makefile
usr/src/lib/libpcp/Makefile
usr/src/lib/crypt_modules/Makefile
usr/src/lib/lvm/libpreen/Makefile
usr/src/lib/librsc/Makefile
usr/src/lib/librsc/sparc/Makefile
usr/src/lib/libsecdb/help/Makefile
usr/src/psm/stand/cpr/sparcv9/Makefile
usr/src/psm/stand/lib/promif/sparcv9/ieee1275/Makefile
usr/src/psm/stand/bootlst/sparc/Makefile
usr/src/psm/stand/bootblks/ufs/Makefile
usr/src/psm/stand/bootblks/ufs/sparc/Makefile
usr/src/psm/stand/bootblks/hsfs/Makefile
usr/src/psm/stand/bootblks/zfs/Makefile
usr/src/test/util-tests/Makefile
usr/src/test/util-tests/tests/Makefile
usr/src/test/os-tests/tests/Makefile
usr/src/test/os-tests/Makefile
usr/src/test/libc-tests/Makefile
usr/src/test/test-runner/Makefile
usr/src/test/test-runner/stf/Makefile
usr/src/test/Makefile
usr/src/test/zfs-tests/Makefile
usr/src/test/zfs-tests/cmd/Makefile
usr/src/test/zfs-tests/tests/functional/Makefile
usr/src/test/zfs-tests/tests/stress/Makefile
usr/src/test/zfs-tests/tests/Makefile
END_LIST

	push @oktoskip, split /\n/, $oklist;
}

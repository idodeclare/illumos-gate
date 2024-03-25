#! /usr/perl5/bin/perl -p -i
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
# Copyright 2016, 2024 Chris Fraire <cfraire@me.com>
#

# Examine files specified in @ARGV, and possibly add or append a command to run
# $(MAKE_GITIGNORE) in any Makefile's .DONE target.
#
# This script is limited to processing files named "Makefile" plus a small set
# of exceptions found empirically (e.g., Makefile.solaris for grub) and minus a
# small set of exceptions found empirically. Running with -V as the sole
# argument will validate that the "minus" set of files still exist. The @ARGV
# values can be in any relative directory from cwd, but cwd must be the root of
# the illumos-gate checkout so that a value for the SRC macro can be assumed.
#
# The macros to pass to the execution of $(MAKE_GITIGNORE) are inferred from a
# search of the text resulting from a Perl-only preprocessing of the Makefile
# to retrieve its full content by recursively loading the text of any
# "include"-d files. "clean"- and "clobber"-style targets are then searched for
# simple references to macros (e.g., $(FOO) or $(FOO)* but not
# $(FOO:%.x=bar/%.y).
#
# "make -D" was considered, but while that command "displays the text of the
# makefiles read in", it actually displays the text after round-1 of macro
# expansion. This script, however, needs the raw text.
#
# Complex references in clean/clobber targets should be refactored to distinct,
# simple macros for use by this script and also to encourage reusability
# between the clean/clobber targets and the .DONE target used for
# MAKE_GITIGNORE.
#
# A rare few illumos Makefiles execute multiple times in the same working
# directory for iterating CURTYPE values (e.g., "library" and "standalone" for
# libumem). This script detects CURTYPE in order to call MAKE_GITIGNORE with
# the -d <discriminator> switch.
#
# Also, another rare few illumos Makefiles include in their clean/clobber
# recipes (though not executed) some committed files (e.g.,
# usr/src/cmd/cmd-inet/usr.lib/wanboot/bootlog-cgi/Makefile "clobbering"
# $(PROG) which contains committed bootlog-cgi). This script recognizes a
# special macro, UNIGNOREFILES, in order to call MAKE_GITIGNORE also with
# -x <file-path> switch(es).
#
# Following are examples of macro matches that might be found in
# clean/clobber recipes: $(CLEANFILES), $(CLEAN_FILES), $(PROG)*

use strict;
use warnings;
use Cwd;
use English;
use File::Basename;
use Getopt::Std;
our ($archdir, $cwd, $didname, %macros, $fullpath, $fullname, $inclpathadj,
    @includes, $macro_match_syn, $num_updated, @oktoskip, $usrsrc, $worktext,
    $opt_n, $opt_v, $opt_V);

BEGIN { undef $/ }

INIT {
	local $/ = "\n";
	$num_updated = 0;

	die "Error: need to be in illumos-gate root\n" if ! -d ".git";
	$cwd = getcwd;

	# $(SRC) is common macro used in makefile include statements
	$usrsrc = "$cwd/usr/src";

	die "Usage: $0 [-n] [-v] [makefile-path ...]

	or

	$0 -V

	-n : dryrun
	-v : verbose
	-V : validate the script's hardcoded exception list of files\n" if
	!getopts('nvV') || (@ARGV < 1 && !$opt_V);

	# Validate that @oktoskip refers to extant files.
	if ($opt_V) {
		if (! -d "usr/src") {
			die "Error: missing expected usr/src/\n";
		}

		for my $f (@oktoskip) {
			if (! -f $f) {
				warn "Warn: missing file $f\n";
			} else {
				print $f, "\n";
			}
		}
		exit;
	}
}

my ($mname, $mpath) = fileparse($ARGV);
undef $inclpathadj;

# generally only "Makefile" needs a .DONE-make_gitignore, but there are some
# exceptions found empirically
if ($mname eq "Makefile") {
	# ok, no path adjustment necessary
} elsif ($mname eq "Makefile.digest" || $mname eq "Makefile.hmac" ||
    $mname eq "Makefile.longhash" || $mname eq "Makefile.solaris") {
	# 1. usr/src/test/crypto-tests/tests/digest/Makefile directive:
	#     $(MAKE) -f Makefile.digest
	# 2. usr/src/test/crypto-tests/tests/hmac/Makefile directive:
	#     $(MAKE) -f Makefile.hmac
	# 3. usr/src/test/crypto-tests/tests/longhash/Makefile directive:
	#     $(MAKE) -f Makefile.longhash
	# 4. usr/src/grub/... directive:
	#     $(MAKE) -f Makefile.solaris
	# ... then ok to continue; no path adjustment necessary
} elsif ($mpath =~ m`/ptools/\z`x) {
	# usr/src/cmd/ptools
	if ($mname eq "Makefile.bld") {
		# directive: include ../../Makefile.bld
		$inclpathadj = qr`^\Q../../`x;
	} elsif ($mname eq "Makefile.ptool") {
		# directive: $(MAKE) -f ../Makefile.ptool
		$inclpathadj = qr`^\Q../`x;
	} else {
		next;
	}
} else {
	# no other Makefile* are eligible
	next;
}

$fullpath = pathjoin($cwd, $mpath);
$fullname = "$fullpath$mname";
$didname = 0;	# set to true on first mywarn for $ARGV
@includes = ();	# will be appended with arguments to "include"
%macros = ();	# macros gleaned to be part of clean/clobber-type recipes
$worktext = $_;	# append-only buffer of content read during recursive loads

my $optdisc = "";	# discriminator fragment to be included in filenames
my $optexcl = "";	# -x handling for UNIGNOREFILES if matched
my $force_make = 0;

{
	# reproduce in Perl the effect of ARCHDIR:sh = cd ..; basename `pwd`
	my ($nn, $pp);
	$pp = $fullpath;
	$pp =~ s`/\z``x;
	($nn, $pp) = fileparse($pp);
	$pp =~ s`/\z``x;
	($nn, $pp) = fileparse($pp);
	$archdir = $nn;
}

# $_ is the content of the Makefile, but do a Perl-only preprocessing of the
# Makefile to expand included files and get the full content as $alltext, with
# "include" directives replaced inline with loaded (recursive) text.
#
# During the time when files are being recursively loaded, an append-only
# $worktext will be extended with the contents of each file. $worktext,
# out-of-order, suffices for gleaning the definitions of macros as needed.
my $alltext = inline_includes($_, $fullname);

# Remove any existing MAKE_GITIGNORE in a .DONE section (unless -n)
s/^\.DONE\s*:.*\n\K((?:\t[\t\x20]*\S.*\n)+)/	# match multi-line .DONE section
	my $v = $1;				# using \K-keep for ease;
	$v =~ s`^\t[\t\x20]*\@?\$\(MAKE_GITIGNORE\)	# match entire command,
	    (?:.+\x20\\\n)* .* (?<!\x20\\)\n	# detecting line continuations;
	    ``mx;				# and remove the entire command
	$v/emx if !$opt_n;

my @macros = ();

# CURTYPE= indicates that -d <discriminator> is needed
if ($alltext =~ /^(CURTYPE)\s*=/mx) {
	$optdisc = "-d \$($1) ";
	mywarn("\t${optdisc}determined from $MATCH\n") if $opt_v;
}

# include ... /Makefile.crypto indicates that -d <discriminator> is needed. NB,
# the match from the global $_.
if (m`^include\s.*/Makefile.crypto \b`mx) {
	$optdisc = "-d \$(BASEPROG) ";
	mywarn("\t${optdisc}determined from $MATCH\n") if $opt_v;
}

# UNIGNOREFILES indicates that -x <filepath> is needed
if ($alltext =~ /^(UNIGNOREFILES)\s*=/mx) {
	$optexcl = "\$($1:%=-x %) ";
	mywarn("\t-x ${optexcl}determined from $MATCH\n") if $opt_v;
}

# The following macros conventionally indicate some derived files that are
# created by the Makefile and are used just as one signal that a run of
# MAKE_GITIGNORE will be needed.
if ($alltext =~ /^BINPROG|CLASSES|DERIVED_FILES|ETCPROG|INITPROG|
    i386_ARCHITECTURES|JAR_FILE|JNIH|LIBPROG|MANLINKS|MODULE|OBJECTS|
    PROG\s*=/mx) {
	$force_make = 1;
}

# all...: target for $(SUBDIRS) are used as one signal that a run of
# MAKE_GITIGNORE will be needed.
if ($alltext =~ /^all\b[^:]*:(?!=)(.*\n (?:\t+\S.*\n)*)/mx &&
    $1 =~ /\$(?: \(SUBDIRS\) | \{SUBDIRS\} )/x) {
	$force_make = 1;
}

# clean/clobber targets' recipes indicate things to be ignored. Only simple
# macro substitutions (e.g., $(FOO) or $(FOO)*, but not $(FOO:%.c:%.o), etc.)
# are matched. Some macros are explicitly ignored.
foreach my $c ($alltext =~ /
    ^(?:(?:clean|clobber)(?:_local)?	#line 1
    |local_(?:clean|clobber)		#line 1 (cont)
    |native-clobber			#line 1 (cont)
    |rpcclean				#line 1 (cont)
    |pyclobber				#line 1 (cont)
    )\b[^:]*:(?!=).*\n			#line 1 (cont)
    ((?:\t[\t\x20]*\S.*\n)+)			#lines 2+
    /gmx) {
	push @macros, grep { $_ !~ /\$\((?: MAKE|RM|RMFLAGS|TARGET )\)/x }
	    map { s/\$\K\{([A-Z][A-Z0-9_]+)\}/($1)/rx }	# curlies to parens
	    $c =~ /(\$(?:\([A-Z][A-Z0-9_]+\)	# e.g., $(FOO_1)
	        |\{[A-Z][A-Z0-9_]+\})\**)	# e.g., ${FOO_1}
	        (?:;|(?!\S)) # followed by ; or not followed by non-whitespace
	    /gix;
}

# if any signal to run MAKE_GITIGNORE was inferred...
if ($force_make || @macros > 0) {
	# warn if macro is not found--except for certain file exceptions--
	# but explicitly let ptools/Makefile.bld go to "else"
	if ($alltext !~ /^MAKE_GITIGNORE\b/mx &&
	    $ARGV !~ m`/ptools/Makefile.bld$`x) {
		if ($opt_v || !is_makefile_ok_to_skip($ARGV)) {
			mywarn("\t\$(MAKE_GITIGNORE) is not defined in" .
			    " preprocessed $ARGV\n");
		}
	} elsif (!$opt_n) {
		# Filter to unique macros
		my %uniq;
		@macros = grep { my $r = !exists $uniq{$_}; $uniq{$_} = 1; $r; }
		    sort map { s/^(?!\$)(.+)/\$($1)/rx } @macros;

		# ensure a .DONE target exists
		if ($alltext !~ /^\.DONE\s*:/mx) {
			# ensure adequate spacing at end of file. (\z here)
			s/(\n*)\z/
			    my $l = length($1);
			    $l >= 3 ? $1 : "\n" x 3/esx;
			# ($ here)
			s/$/.DONE:/sx;
		}

		# Construct a MAKE_GITIGNORE command with line-wrapping
		my $make_gitignore_cmd =
		    "\t\@\$(MAKE_GITIGNORE) $optdisc$optexcl";
		my $llen = tlength($make_gitignore_cmd);
		for (my $i = 0; $i < @macros; ++$i) {
			my $m = $macros[$i];
			$make_gitignore_cmd .= $m;
			$llen += tlength($m);
			if ($i + 1 < @macros) {
				# count 1 blank + possible continuation " \\"
				my $nspace = 1 + ($i + 2 < @macros ? 2 : 0);
				if ($llen + $nspace +
				    tlength($macros[$i + 1]) > 79) {
					my $mindent = "\t    ";
					$make_gitignore_cmd .= " \\\n$mindent";
					$llen = tlength($mindent);
				} else {
					$make_gitignore_cmd .= " ";
					$llen++;
				}
			}
		}
		$make_gitignore_cmd =~ s/\s+\z//x;
		$make_gitignore_cmd .= "\n";

		# Append to the .DONE target. Match multi-line .DONE section,
		# and append a new command.
		s/^\.DONE\s*: .*\n (?:\t[\t\x20]*\S.*\n)* \K
		    /$make_gitignore_cmd/emx;
		++$num_updated;
	}
}

END {
	warn sprintf("%d %s updated.\n", $num_updated, $num_updated == 1 ?
	    "file" : "files");
}

#------------------------------------------------------------------------------

# Detect recursively-loaded Makefiles, and load their content. Included files
# are all relative to the original Makefile's directory, regardless of the
# depth of inclusion
sub inline_includes {
	my ($content, $file) = @_;

	$content =~ s/^include \s+ (\S+)/
		mywarn("\t$MATCH\n") if $opt_v;
		expand_and_read($1, $file)/egmx;
	return $content;
}

# Attempt to transform a limited set of (empirically-determined) illumos macros
# within the specified $incl filename macro, and try to read the resulting
# expanded filename to append $worktext.
sub expand_and_read {
	my ($incl, $from) = @_;

	# global $macro_match_syn for caching regex
	if (! defined $macro_match_syn) {
		my $macro_match = qr/
		  (BASEDIR|BOOTSRC(?:DIR)?|BRAND_SHARED|BUILD_TYPE|
		  CLASS(?:_(?:OBJ|DBG)(?:32|64))?|CMDDIR|CONF_SRCDIR|CRYPTOSRC|
		  LIB_BASE|LIBCDIR|LIBMDIR|LIBSTAND_SRC|METASSIST_TOPLEVEL|
		  NDMP_DIR|PLATFORM|PROMIF|PSMBASE|SASRC|SENDMAIL|SGSHOME|
		  SRCDIR|TOPDIR|UTSBASE|ZFSSRC)
		  /x;
		$macro_match_syn = qr/\$(\($macro_match\) | \{$macro_match\})/x;
	}

	# iteratively substitute any of the known macros above by
	# searching for their definitionsn in $alltext
	while ($incl =~ s`$macro_match_syn`
		mywarn("\tBefore transformation: $incl\n") if $opt_v;
		my $macro = substr($1, 1, length($1) - 2);
		try_get_def($macro)`ex) {
	}

	# substitute the values of a few known, external definitions
	$incl =~ s`\$\(ARCHDIR\)`$archdir`gx;
	$incl =~ s`\$\(REL_PATH\)`..\/`gx;
	$incl =~ s`\$\(SRC\)`$usrsrc`gx;
	$incl =~ s`$inclpathadj`` if defined $inclpathadj;

	my $repl = "";
	if ($incl =~ m`\$\(MACH(?:INE)?\)`x ||
	    $incl =~ m`\$\{MACH(?:INE)?\}`x) {
		my $incl0 = $incl;
		my $found_arch = 0;
		mywarn("\tBefore transformation: $incl\n") if $opt_v;
		foreach my $mach ("amd64", "i386", "sparc", "sparcv9") {
			$incl = $incl0;
			$incl =~ s`\$\(MACH(?:INE)?\)`$mach`gx;
			$incl =~ s`\$\{MACH(?:INE)?\}`$mach`gx;
			my $fullincl = pathjoin($fullpath, $incl);
			if (-f $fullincl) {
				$repl .= read_include($fullincl, $from);
				$found_arch = 1;
			}
		}
		mywarn("\tNo MACH(INE) for $incl0\n") if !$found_arch;
	} else {
		my $fullincl = pathjoin($fullpath, $incl);
		$repl .= read_include($fullincl, $from);
	}
	return $repl;
}

# search for the value of a macro definition--e.g., FOO=(.+)--or else return
# '$/FOO/' with odd syntax to indicate that it was not found
sub try_get_def {
	my ($macro) = @_;

	return $macros{$macro} if exists $macros{$macro};

	my $isfound = $worktext =~ /^(?:\Q$macro\E\s*=(?!:)\s* |
	    \t+\@\Q$macro\E=)(\S*)/mx;
	my $yn = $isfound ? "yes" : "no";
	mywarn("\tWas the definition of macro $macro inferred: $yn\n") if
	    $opt_v;
	if ($isfound) {
		$macros{$macro} = $1;
		return $1;
	} else {
		# use odd syntax as a clue that a macro def was not found
		return "\$/$macro/";
	}
}

# Read the content of a specified file, append the content to $worktext, and
# then transform content with inline_includes before returning it.
sub read_include {
	my ($file, $from) = @_;

	mywarn("\tTry to read $file\n") if $opt_v;
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

	# worktext is just used for text extraction while included files are
	# being recursively loaded, so order is unimportant
	$worktext .= "\n";
	$worktext .= $content;

	$content = inline_includes($content, $file);
	return $content;
}

# combines $root and $path if $path is relative; else returns $path untouched
sub pathjoin {
	my ($root, $path) = @_;
	return $path if $path =~ m`^/`x;
	$root .= "/" if $root !~ m`/\z`x;
	return "$root$path";
}

# infer length with \t as 8 spaces
sub tlength {
	my ($v) = @_;
	return length($v) + 7 * ($v =~ tr/\t//);
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
usr/src/cmd/abi/Makefile
usr/src/cmd/abi/spectrans/Makefile
usr/src/cmd/bhyve/test/Makefile
usr/src/cmd/bhyve/test/tests/Makefile
usr/src/cmd/boot/installboot/Makefile
usr/src/cmd/dcs/Makefile
usr/src/cmd/dcs/sparc/Makefile
usr/src/cmd/fm/eversholt/eftinfo/Makefile
usr/src/cmd/fm/eversholt/esc/Makefile
usr/src/cmd/fm/eversholt/files/Makefile
usr/src/cmd/fm/eversholt/Makefile
usr/src/cmd/fm/eversholt/native/Makefile
usr/src/cmd/fm/fmadm/Makefile
usr/src/cmd/fm/fmdump/Makefile
usr/src/cmd/fm/fminject/Makefile
usr/src/cmd/fm/fmstat/Makefile
usr/src/cmd/fm/fmtopo/Makefile
usr/src/cmd/fm/ipmitopo/Makefile
usr/src/cmd/fm/Makefile
usr/src/cmd/fm/modules/common/Makefile
usr/src/cmd/fm/modules/common/sw-diag-response/Makefile
usr/src/cmd/fm/modules/Makefile
usr/src/cmd/fm/notify/smtp-notify/Makefile
usr/src/cmd/fm/notify/snmp-notify/Makefile
usr/src/cmd/fm/schemes/Makefile
usr/src/cmd/fs.d/hsfs/Makefile
usr/src/cmd/fs.d/lofs/Makefile
usr/src/cmd/fs.d/pcfs/Makefile
usr/src/cmd/fs.d/udfs/Makefile
usr/src/cmd/fs.d/zfs/Makefile
usr/src/cmd/hal/addons/Makefile
usr/src/cmd/hal/probing/Makefile
usr/src/cmd/idmap/Makefile
usr/src/cmd/krb5/Makefile
usr/src/cmd/lp/lib/Makefile
usr/src/cmd/make/lib/Makefile
usr/src/cmd/make/Makefile
usr/src/cmd/mdb/i86pc/Makefile
usr/src/cmd/mdb/i86pc/modules/Makefile
usr/src/cmd/mdb/i86xpv/Makefile
usr/src/cmd/mdb/i86xpv/modules/Makefile
usr/src/cmd/mdb/intel/modules/Makefile
usr/src/cmd/picl/Makefile
usr/src/cmd/picl/plugins/common/Makefile
usr/src/cmd/picl/plugins/lib/Makefile
usr/src/cmd/picl/plugins/Makefile
usr/src/cmd/picl/plugins/sun4u/boston/Makefile
usr/src/cmd/picl/plugins/sun4u/chalupa/Makefile
usr/src/cmd/picl/plugins/sun4u/cherrystone/Makefile
usr/src/cmd/picl/plugins/sun4u/chicago/Makefile
usr/src/cmd/picl/plugins/sun4u/daktari/Makefile
usr/src/cmd/picl/plugins/sun4u/enchilada/Makefile
usr/src/cmd/picl/plugins/sun4u/ents/Makefile
usr/src/cmd/picl/plugins/sun4u/excalibur/Makefile
usr/src/cmd/picl/plugins/sun4u/grover/Makefile
usr/src/cmd/picl/plugins/sun4u/lib/Makefile
usr/src/cmd/picl/plugins/sun4u/littleneck/Makefile
usr/src/cmd/picl/plugins/sun4u/lw2plus/Makefile
usr/src/cmd/picl/plugins/sun4u/lw8/Makefile
usr/src/cmd/picl/plugins/sun4u/mpxu/Makefile
usr/src/cmd/picl/plugins/sun4u/psvc/Makefile
usr/src/cmd/picl/plugins/sun4u/schumacher/Makefile
usr/src/cmd/picl/plugins/sun4u/seattle/Makefile
usr/src/cmd/picl/plugins/sun4u/sebring/Makefile
usr/src/cmd/picl/plugins/sun4u/silverstone/Makefile
usr/src/cmd/picl/plugins/sun4u/taco/Makefile
usr/src/cmd/picl/plugins/sun4v/lib/Makefile
usr/src/cmd/picl/plugins/sun4v/Makefile
usr/src/cmd/prtdiag/sparc/Makefile
usr/src/cmd/prtdscp/Makefile
usr/src/cmd/prtdscp/sparc/Makefile
usr/src/cmd/rcap/Makefile
usr/src/cmd/scadm/sparc/Makefile
usr/src/cmd/sckmd/sparc/Makefile
usr/src/cmd/scsi/Makefile
usr/src/cmd/scsi/sestopo/Makefile
usr/src/cmd/scsi/smp/Makefile
usr/src/cmd/sendmail/cf/cf/Makefile
usr/src/cmd/sgs/libelf/demo/Makefile
usr/src/cmd/svr4pkg/Makefile
usr/src/cmd/syseventd/daemons/Makefile
usr/src/cmd/syseventd/modules/Makefile
usr/src/cmd/zonestat/Makefile
usr/src/data/bhyve/Makefile
usr/src/data/Makefile
usr/src/data/ucode/Makefile
usr/src/lib/brand/ipkg/Makefile
usr/src/lib/brand/labeled/Makefile
usr/src/lib/brand/shared/Makefile
usr/src/lib/crypt_modules/Makefile
usr/src/lib/fm/topo/Makefile
usr/src/lib/fm/topo/maps/Makefile
usr/src/lib/fm/topo/modules/common/Makefile
usr/src/lib/fm/topo/modules/i86pc/Makefile
usr/src/lib/fm/topo/modules/Makefile
usr/src/lib/gss_mechs/mech_dh/Makefile
usr/src/lib/iconv_modules/utf-8/common/binarytables/test/Makefile
usr/src/lib/libmtmalloc/tests/Makefile
usr/src/lib/libpcp/Makefile
usr/src/lib/libprtdiag/sparc/Makefile
usr/src/lib/librsc/Makefile
usr/src/lib/librsc/sparc/Makefile
usr/src/lib/libsecdb/help/Makefile
usr/src/lib/libsmedia/Makefile
usr/src/lib/libsmedia/plugins/Makefile
usr/src/lib/mpapi/Makefile
usr/src/lib/scsi/Makefile
usr/src/lib/scsi/plugins/Makefile
usr/src/lib/scsi/plugins/scsi/engines/Makefile
usr/src/lib/scsi/plugins/scsi/Makefile
usr/src/lib/scsi/plugins/ses/Makefile
usr/src/lib/scsi/plugins/smp/Makefile
usr/src/lib/varpd/Makefile
usr/src/man/Makefile
usr/src/psm/stand/bootlst/sparc/Makefile
usr/src/psm/stand/cpr/sparcv9/Makefile
usr/src/psm/stand/lib/promif/sparcv9/ieee1275/Makefile
usr/src/test/bhyve-tests/Makefile
usr/src/test/bhyve-tests/tests/Makefile
usr/src/test/crypto-tests/cmd/Makefile
usr/src/test/crypto-tests/Makefile
usr/src/test/crypto-tests/tests/digest/Makefile
usr/src/test/crypto-tests/tests/hmac/Makefile
usr/src/test/crypto-tests/tests/Makefile
usr/src/test/crypto-tests/tests/modes/aes/Makefile
usr/src/test/crypto-tests/tests/modes/Makefile
usr/src/test/elf-tests/Makefile
usr/src/test/elf-tests/tests/Makefile
usr/src/test/elf-tests/tests/mapfiles/Makefile
usr/src/test/elf-tests/tests/relocs/amd64/Makefile
usr/src/test/elf-tests/tests/relocs/i386/Makefile
usr/src/test/elf-tests/tests/relocs/Makefile
usr/src/test/elf-tests/tests/resolution/Makefile
usr/src/test/elf-tests/tests/sections/Makefile
usr/src/test/elf-tests/tests/tls/amd64/Makefile
usr/src/test/elf-tests/tests/tls/i386/Makefile
usr/src/test/elf-tests/tests/tls/Makefile
usr/src/test/libc-tests/Makefile
usr/src/test/libmlrpc-tests/Makefile
usr/src/test/libmlrpc-tests/tests/Makefile
usr/src/test/libmlrpc-tests/tests/netrlogon/Makefile
usr/src/test/Makefile
usr/src/test/net-tests/Makefile
usr/src/test/os-tests/Makefile
usr/src/test/os-tests/tests/cores/Makefile
usr/src/test/os-tests/tests/Makefile
usr/src/test/smbclient-tests/cmd/Makefile
usr/src/test/smbclient-tests/Makefile
usr/src/test/smbclient-tests/tests/Makefile
usr/src/test/smbclient-tests/tests/performance/Makefile
usr/src/test/smbclient-tests/tests/smbfs/Makefile
usr/src/test/smbsrv-tests/Makefile
usr/src/test/test-runner/Makefile
usr/src/test/test-runner/stf/Makefile
usr/src/test/util-tests/Makefile
usr/src/test/util-tests/tests/make/files/make_a/Makefile
usr/src/test/util-tests/tests/Makefile
usr/src/test/zfs-tests/cmd/Makefile
usr/src/test/zfs-tests/Makefile
usr/src/test/zfs-tests/tests/functional/Makefile
usr/src/test/zfs-tests/tests/Makefile
usr/src/test/zfs-tests/tests/stress/Makefile
usr/src/tools/make/lib/Makefile
usr/src/tools/make/Makefile
usr/src/tools/sgs/Makefile
usr/src/tools/smatch/src/Makefile
usr/src/ucblib/Makefile
usr/src/uts/common/io/qede/579xx/drivers/ecore/Makefile
usr/src/uts/sparc/dump/Makefile
END_LIST

	push @oktoskip, split /\n/, $oklist;
}

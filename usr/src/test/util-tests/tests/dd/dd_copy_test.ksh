#!/usr/bin/ksh
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
# Copyright 2017, 2023 Chris Fraire <cfraire@me.com>.
#

set -o pipefail

if [[ -z $TESTPOOL ]]; then
	>&2 echo "fatal: TESTPOOL is not defined"
	exit 1
fi

DD="${DD:-/usr/bin/dd}"
BINCOMP="${BINCOMP:-/opt/util-tests/bin/bincomp}"
MKRANDZERO="${MKRANDZERO:-/opt/util-tests/bin/mkrandzero}"

ddc_arg0="$(basename $0)"
ddc_zvol="$TESTPOOL/ddc_vblk$$"
ddc_vblk="/dev/zvol/rdsk/$TESTPOOL/ddc_vblk$$"
ddc_vreg="/tmp/ddc_vreg$$"
# Following is set by setup() to name of temporary file with some NUL holes
ddc_if01=
# Following is set by setup() to name of temporary file with no NUL holes
ddc_if11=
# Following is set by setup() to name of temporary file with only NUL bytes
ddc_if00=
# Following is reset by tests to no. of bytes of last input file
ddifsz=
# Following is reset by tests to name of last written file
ddof=

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	>&2 echo "TEST_FAIL: $msg"
	cleanup nowarn
	exit 1
}

function setup
{
	typeset func="setup"
	readonly func

	echo "Initialize random input files."

	ddc_if01=$(mktemp /tmp/ddc_if01_XXXXXX) || \
	    fatal "$func failed to create temp file"
	ddc_if11=$(mktemp /tmp/ddc_if11_XXXXXX) || \
	    fatal "$func failed to create temp file"
	ddc_if00=$(mktemp /tmp/ddc_if00_XXXXXX) || \
	    fatal "$func failed to create temp file"

	# Create files that fit in the 2M size used for test ZVOLs.
	# if01 has one partial block, while if11 and if00 have only full
	# blocks.
	"$MKRANDZERO" -f "$ddc_if01" -b 1974073 -K 4096 -p 90 && \
	    "$MKRANDZERO" -f "$ddc_if11" -b 1996800 -K 4096 -p 0 && \
	    "$MKRANDZERO" -f "$ddc_if00" -b 1996800 -K 4096 -p 100 || \
	    fatal "$func failed to initialize random contents"
}

function setuptest
{
	typeset func="setuptest"
	readonly func
	typeset vtype=$1
	typeset zout

	[[ -n $vtype ]] || fatal "$func vtype is required"
	shift

	cleantest
	echo "Set up $vtype test"

	case "$vtype" in
	"vreg")
		cat /dev/null > "$ddc_vreg" || \
		    fatal "$func failed to write $ddc_vreg"
		ddof="$ddc_vreg" ;;
	"vblk")
		# create ZVOL with specified volblocksize to match the size
		# specified for mkrandzero. The expected size of ZVOL
		# metadata is under 5% of vol size.
		zfs create -V 2M -o volblocksize=4096 "$ddc_zvol" || \
		    fatal "$func failed to create zvol $ddc_zvol"
		ddof="$ddc_vblk";;
	*)
		fatal "$func unknown vtype $vtype";;
	esac
}

function cleantest
{
	typeset rc=0

	rm -f "$ddc_vreg" || rc=1

	zfs get name "$ddc_zvol" > /dev/null 2>&1
	[[ $? -ne 0 ]] || zfs destroy -fr "$ddc_zvol" || rc=1

	return $rc
}

function cleanup
{
	typeset nowarn=$1

	[[ -n $ddc_if01 ]] && rm -f "$ddc_if01"
	[[ -n $ddc_if11 ]] && rm -f "$ddc_if11"
	[[ -n $ddc_if00 ]] && rm -f "$ddc_if00"
	cleantest
	if [[ $? -ne 0 && -z $nowarn ]]; then
		>&2 echo "TEST_FAIL: failed to clean up"
		exit 1
	fi
}

function runtest
{
	typeset func="runtest"
	readonly func
	typeset ddif=$1
	typeset zout

	[[ -n $ddif ]] || fatal "$func ddif is required"
	shift

	echo "Run dd if=$ddif of=$ddof $*"

	ddifsz=$(statsize "$ddif") && \
	    "$DD" "$@" if="$ddif" of="$ddof"
}

function statsize
{
	wc -c "$1" | awk '{print $1}'
}

function cmpsize
{
	typeset func="cmpsize"
	readonly func
	typeset vtype=$1
	typeset ddif=$2
	typeset cmp=$3
	typeset ddofsz=0
	typeset a1=0.00
	typeset res zout

	[[ -n $vtype ]] || fatal "$func vtype is required"
	[[ -n $ddif ]] || fatal "$func ddif is required"
	[[ -n $cmp ]] || fatal "$func cmp is required"
	shift 3

	case "$vtype" in
	"vreg")
		ddofsz=$(statsize "$ddof") || \
		    fatal "$func failed to stat $ddof";;
	"vblk")
		zout=$(zfs get -H -p logicalused "$ddc_zvol") || \
		    fatal "$func failed to zfs-get $ddc_zvol"
		ddofsz=$(echo $zout | awk '{print $3}');;
	*)
		fatal "$func unknown vtype $vtype";;
	esac

	echo "osize $ddofsz <=> isize $ddifsz"

	case "$cmp" in
	"==")
		# test that osize is precisely equal to isize
		res=$((ddifsz == ddofsz)) || fatal "$func failed to cmp $cmp";;
	"~=")
		# test that osize is approximately equal to isize within
		# specified precision
		a1=$1
		res=$((ddifsz * (1. - a1) <= ddofsz && \
		    ddofsz <= ddifsz * (1. + a1) )) || \
		    fatal "$func failed to cmp $cmp";;
	"<=")
		# test that osize is less than a specified fraction of isize
		a1=$1
		res=$((ddofsz <= ddifsz * a1)) || \
		    fatal "$func failed to cmp $cmp";;
	*)
		fatal "$func unknown cmp $cmp";;
	esac

	if (( res == 0 )); then
		fatal "$func does not pass cmp $cmp $*"
	else
		echo "$func passes cmp $cmp $*"
	fi
}

function epass
{
	runtest "$@" || fatal "dd-copy=$* failed, expected success"
}

function cmpbytes
{
	typeset func="cmpbytes"
	readonly func
	typeset ddif=$1

	[[ -n $ddif ]] || fatal "$func ddif is required"
	shift

	"$BINCOMP" "$ddif" "$ddof" "$ddifsz"
	if [[ $? -ne 0 ]]; then
		fatal "dd-copy $func failed, expected success"
	else
		echo "$func file bytes are equal."
	fi
}

setup

# vreg tests: cmpsize should always be ==

setuptest vreg
epass "$ddc_if11"
cmpbytes "$ddc_if11"
cmpsize vreg "$ddc_if11" '=='

setuptest vreg
epass "$ddc_if11" conv=sparse
cmpbytes "$ddc_if11"
cmpsize vreg "$ddc_if11" '=='

setuptest vreg
epass "$ddc_if01"
cmpbytes "$ddc_if01"
cmpsize vreg "$ddc_if01" '=='

setuptest vreg
epass "$ddc_if01" conv=sparse
cmpbytes "$ddc_if01"
cmpsize vreg "$ddc_if01" '=='

setuptest vreg
epass "$ddc_if00"
cmpbytes "$ddc_if00"
cmpsize vreg "$ddc_if00" '=='

setuptest vreg
epass "$ddc_if00" conv=sparse
cmpbytes "$ddc_if00"
cmpsize vreg "$ddc_if00" '=='

# vblk tests: cmpsize should be within 5% of if11 input size (no-NUL), less
# than 50% of if10 (some NUL), and less than 5% for if00 (all NUL)

setuptest vblk
epass "$ddc_if11"
cmpbytes "$ddc_if11"
cmpsize vblk "$ddc_if11" '~=' .05

setuptest vblk
epass "$ddc_if11" conv=sparse
cmpbytes "$ddc_if11"
cmpsize vblk "$ddc_if11" '~=' .05

setuptest vblk
epass "$ddc_if01"
cmpbytes "$ddc_if01"
cmpsize vblk "$ddc_if01" '~=' .05

setuptest vblk
epass "$ddc_if01" conv=sparse
cmpbytes "$ddc_if01"
cmpsize vblk "$ddc_if01" '<=' .5

setuptest vblk
epass "$ddc_if00"
cmpbytes "$ddc_if00"
cmpsize vblk "$ddc_if00" '~=' .05

setuptest vblk
epass "$ddc_if00" conv=sparse
cmpbytes "$ddc_if00"
cmpsize vblk "$ddc_if00" '<=' .05

# stride vblk tests: the size comparisons described above for vblk tests
# apply here, but the writes are done in four passes

setuptest vblk
epass "$ddc_if11" stride=4
epass "$ddc_if11" iseek=1 oseek=1 stride=4
epass "$ddc_if11" iseek=2 oseek=2 stride=4
epass "$ddc_if11" iseek=3 oseek=3 stride=4
cmpbytes "$ddc_if11"
cmpsize vblk "$ddc_if11" '~=' .05

setuptest vblk
epass "$ddc_if11" stride=4 conv=sparse
epass "$ddc_if11" iseek=1 oseek=1 stride=4 conv=sparse
epass "$ddc_if11" iseek=2 oseek=2 stride=4 conv=sparse
epass "$ddc_if11" iseek=3 oseek=3 stride=4 conv=sparse
cmpbytes "$ddc_if11"
cmpsize vblk "$ddc_if11" '~=' .05

setuptest vblk
epass "$ddc_if01" stride=4
epass "$ddc_if01" iseek=1 oseek=1 stride=4
epass "$ddc_if01" iseek=2 oseek=2 stride=4
epass "$ddc_if01" iseek=3 oseek=3 stride=4
cmpbytes "$ddc_if01"
cmpsize vblk "$ddc_if01" '~=' .5

setuptest vblk
epass "$ddc_if01" stride=4 conv=sparse
epass "$ddc_if01" iseek=1 oseek=1 stride=4 conv=sparse
epass "$ddc_if01" iseek=2 oseek=2 stride=4 conv=sparse
epass "$ddc_if01" iseek=3 oseek=3 stride=4 conv=sparse
cmpbytes "$ddc_if01"
cmpsize vblk "$ddc_if01" '<=' .5

setuptest vblk
epass "$ddc_if00" stride=4
epass "$ddc_if00" iseek=1 oseek=1 stride=4
epass "$ddc_if00" iseek=2 oseek=2 stride=4
epass "$ddc_if00" iseek=3 oseek=3 stride=4
cmpbytes "$ddc_if00"
cmpsize vblk "$ddc_if00" '~=' .05

setuptest vblk
epass "$ddc_if00" stride=4 conv=sparse
epass "$ddc_if00" iseek=1 oseek=1 stride=4 conv=sparse
epass "$ddc_if00" iseek=2 oseek=2 stride=4 conv=sparse
epass "$ddc_if00" iseek=3 oseek=3 stride=4 conv=sparse
cmpbytes "$ddc_if00"
cmpsize vblk "$ddc_if00" '<=' .05

# The strict block size matching above for mkrandzero and volblocksize were
# concerned with aligning NUL holes. Heretofore, the dd commands have run
# with the default bs=512. Run with an explicit, larger bs.

setuptest vblk
epass "$ddc_if11" stride=4 bs=4096 conv=sparse
epass "$ddc_if11" iseek=1 oseek=1 stride=4 bs=4096 conv=sparse
epass "$ddc_if11" iseek=2 oseek=2 stride=4 bs=4096 conv=sparse
epass "$ddc_if11" iseek=3 oseek=3 stride=4 bs=4096 conv=sparse
cmpbytes "$ddc_if11"
cmpsize vblk "$ddc_if11" '~=' .05

setuptest vblk
epass "$ddc_if01" stride=4 bs=4096 conv=sparse
epass "$ddc_if01" iseek=1 oseek=1 stride=4 bs=4096 conv=sparse
epass "$ddc_if01" iseek=2 oseek=2 stride=4 bs=4096 conv=sparse
epass "$ddc_if01" iseek=3 oseek=3 stride=4 bs=4096 conv=sparse
cmpbytes "$ddc_if01"
cmpsize vblk "$ddc_if01" '<=' .5

setuptest vblk
epass "$ddc_if00" stride=4 bs=4096 conv=sparse
epass "$ddc_if00" iseek=1 oseek=1 stride=4 bs=4096 conv=sparse
epass "$ddc_if00" iseek=2 oseek=2 stride=4 bs=4096 conv=sparse
epass "$ddc_if00" iseek=3 oseek=3 stride=4 bs=4096 conv=sparse
cmpbytes "$ddc_if00"
cmpsize vblk "$ddc_if00" '<=' .05

cleanup
echo "TEST PASS: $ddc_arg0"

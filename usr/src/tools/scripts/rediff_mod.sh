#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
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

# This script needs to use a diff that has -d, -p, -u. Default to the
# location of OpenIndiana hipster's GNU diff, but allow overriding by env.
export GNU_DIFF="${GNU_DIFF:-/usr/gnu/bin/diff}"

function usage {
	prog="$(basename "$0")"
	>&2 echo \
"Usage: $0 [-p] <contrib file> <illumos src file>

	-p	Show which C function each change is in.

	Run to confirm that the input files are different and to create
	or update an <illumos src file>.patch file.

	e.g., $prog path/to/dns-sd.1 path/to/dns-sd.1m
	e.g., $prog -p path/to/dns-sd.c path/to/dns-sd.c

	GNU_DIFF	set env var to override the default, $GNU_DIFF
"
	exit 1
}

function cleanup {
	if [ "$tempf" != "" ]; then
		rm -f "$tempf"
	fi
}

# Default to diff using -d/--minimal (try hard to find a smaller set of
# changes.) and -u/--unified (output NUM [default 3] lines of unified
# context.)
diffargs="-d -u"

while getopts :p opt; do
	case "$opt" in
		p) diffargs="-p $diffargs";
		shift;;
	esac
done
if [ $# -gt 0 ] && [ "$1" = "--" ]; then
	shift
fi
if [ $# -ne 2 ]; then
	usage
fi

# affirm that the input files exist
ls "$1" > /dev/null && ls "$2" > /dev/null || exit 2

# affirm that GNU_DIFF runs successfully with $diffargs by a test
# on /dev/null
"$GNU_DIFF" $diffargs /dev/null /dev/null
if [ $? -ne 0 ]; then
	>&2 echo "ERROR: set GNU_DIFF in the environment to override to a" \
	    "working version."
	exit 2
fi

# create a new, temporary patch file
tempf=$(mktemp /tmp/rediff_modXXXXXX) || exit 2
trap cleanup EXIT

# affirm that a diff is produced as expected
echo "# illumos revision" >> "$tempf" || exit 2
"$GNU_DIFF" $diffargs "$1" "$2" >> "$tempf"
if [ $? -eq 0 ]; then
	>&2 echo "ERROR: no diff exists as expected between $1 and $2"
	exit 2
fi

# move the temporary patch file into its src location
mv "$tempf" "$2".patch || exit 2

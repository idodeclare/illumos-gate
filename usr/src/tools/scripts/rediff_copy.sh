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

function usage {
	prog="$(basename "$0")"
	>&2 echo \
"Usage: $0 <contrib file> <illumos-src-file>

	Run to confirm that the input files are identical.

	e.g., $prog path/to/dns-sd.1 path/to/dns-sd.1m
"
	exit 1
}

if [ $# -ne 2 ]; then
	usage
fi

# affirm that the input files exist
ls "$1" > /dev/null && ls "$2" > /dev/null || exit 2

# affirm that the input files are identical, or else show diffs
diff "$1" "$2"
if [ $? -ne 0 ]; then
	>&2 echo "ERROR: an unexpected diff exists between $1 and $2"
	exit 2
fi

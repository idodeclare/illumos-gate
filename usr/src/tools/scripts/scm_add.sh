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

# Default to use `git add'
export SCM_ADD="${SCM_ADD:-git add}"

function usage {
	prog="$(basename "$0")"
	>&2 echo \
"Usage: $0 <contrib file> ...

	Run to add a source file to source code management software,
	after first removing extraneous whitespace line endings.

	e.g., $prog path/to/dns-sd.1

	SCM_ADD	set env var to override the default, $SCM_ADD
"
	exit 1
}

if [ $# -eq 0 ]; then
	usage
fi

# affirm that SCM_ADD is defined
if [ -z "$SCM_ADD" ]; then
	>&2 echo "ERROR: SCM_ADD is not defined"
	exit 2
fi

# remove extraneous, line-ending whitespace; and run the SCM_ADD command
perl -p -i -e 'use strict;
    use warnings;
    BEGIN { undef $/ }
    # strip line-ending tabs and spaces
    s/[\x20\t]+$//mg;
    # strip file-ending tabs and spaces
    s/[\x20\t]+$//s;
    ' "$@" && $SCM_ADD "$@" || exit 2

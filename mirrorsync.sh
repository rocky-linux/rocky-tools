#!/bin/env bash
#
# mirrorsync - Synchronize a Rocky mirror
# By: Dennis Koerner <koerner@netzwerge.de>
# 
# The latest version of this script can be found at:
# https://github.com/rocky-linux/rocky-tools
# 
# Please read https://docs.rockylinux.org/en/rocky/8/guides/add_mirror_manager
# for further information on setting up a Rocky mirror.
#
# Copyright (c) 2021 Rocky Enterprise Software Foundation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice (including the next
# paragraph) shall be included in all copies or substantial portions of the
# Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#


RSYNC="/usr/bin/rsync"
# You can change v to q if you do not want detailed logging
OPTS="-vrlptDSH --exclude=*.~tmp~ --delete-delay --delay-updates"

# Please use a mirror next to you for initial sync
# or if you are hosting a private rather than a pulic mirror.
# Local mirrors might be faster.
# Also we might restrict access to the master in the future.
# A complete list of mirrors can be found at
# https://mirrors.rockylinux.org/mirrormanager/mirrors/Rocky
SRC="msync.rockylinux.org::rocky/mirror/pub/rocky/"

# Your local path. Change to whatever fits your system.
# MIRRORMODULE is also used in syslog output.
MIRRORMODULE="rocky-linux"
DST="/mnt/mirrorserver/${MIRRORMODULE}"

FILELISTFILE="fullfiletimelist-rocky"
LOCKFILE=$0.lockfile

CHECKRESULT=$(${RSYNC} --no-motd --dry-run --out-format='%n' ${SRC}${FILELISTFILE} ${DST}/${FILELISTFILE})
if [ -z $CHECKRESULT ]; then
	echo "${FILELISTFILE} unchanged. Not updating at" $(date) >> $0.log 2>&1
	logger -t rsync "Not updating ${MIRRORMODULE}: ${FILELISTFILE} unchanged."
	exit 1
fi


if [ -e $LOCKFILE ]; then
	echo "Update already in progress at" $(date) >> $0.log 2>&1
	logger -t rsync "Not updating ${MIRRORMODULE}: already in progress."
else
	touch $LOCKFILE
	echo "Started update at" $(date) >> $0.log 2>&1
	logger -t rsync "Updating ${MIRRORMODULE}"
		
	${RSYNC} ${OPTS} ${SRC} ${DST}/ >> $0.log 2>&1
	logger -t rsync "Finished updating ${MIRRORMODULE}"  
	echo "End:" $(date) >> $0.log 2>&1
	rm $LOCKFILE
fi

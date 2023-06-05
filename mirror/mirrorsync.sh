#!/bin/env bash
#
# mirrorsync - Synchronize a Rocky mirror
# By: Dennis Koerner <koerner@netzwerge.de>
# 
# The latest version of this script can be found at:
# https://github.com/rocky-linux/rocky-tools
# 
# Please read https://docs.rockylinux.org/guides/mirror_management/add_mirror_manager/
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

# Find rsync in default path
rsync_run(){
	if command -v rsync >/dev/null; then
		command rsync "$@";
	else
		command -p rsync "$@";
	fi;
}

# You can change v to q if you do not want detailed logging
# You may also add additional excludes if you don't want to provide certain
# repositories or architectures.
opts=(-vrlptDSH --exclude="*.~tmp~" --delete-delay --delay-updates)

# Please use a mirror geographically close to you for initial sync,
# or if you are hosting a private mirror(not publicly available).
#
# Note that local mirrors may be faster, and we might restrict
# access to the master in the future.
#
# A complete list of mirrors can be found at
# https://mirrors.rockylinux.org/mirrormanager/mirrors/Rocky
src="msync.rockylinux.org::rocky/mirror/pub/rocky"

# Your local path. Change to whatever fits your system.
# $mirrormodule is also used in syslog output.
mirrormodule="rocky-linux"
dst="/mnt/mirrorserver/${mirrormodule}"

filelistfile="fullfiletimelist-rocky"
lockfile="$0.lockfile"
logfile="$0.log"

# Check if the filelistfile has changed on upstream mirror
# and exit cleanly if it is still the same
checkresult=$(rsync_run --no-motd --dry-run --out-format="%n" "${src}/${filelistfile}" "${dst}/${filelistfile}")
if [[ -z "$checkresult" ]]; then
	printf "%s unchanged. Not updating at %(%c)T\n" "$filelistfile" -1 >> "$logfile" 2>&1
	logger -t rsync "Not updating ${mirrormodule}: ${filelistfile} unchanged."
	exit 0
fi

# Check for existing lockfile to avoid multiple simultaneously running syncs
# If lockfile exists but process is dead continue anyway
if [[ -e "$lockfile" ]] && ! kill -0 "$(< "$lockfile")" 2>/dev/null; then
	printf "Warning: lockfile exists but process dead, continuing.\n" >> "$logfile" 2>&1
	logger -t rsync "Warning: lockfile exists but process dead, continuing with updating ${mirrormodule}."
	rm -f "$lockfile"
elif [[ -e "$lockfile" ]]; then
	printf "Update already in progress at %(%c)T\n" -1 >> "$logfile" 2>&1
	logger -t rsync "Not updating ${mirrormodule}: already in progress."
	exit 1
fi

# The actual syncing part
printf '%s\n' "$$" > "$lockfile"
printf "Started update at %(%c)T\n" -1 >> "$logfile" 2>&1
logger -t rsync "Updating ${mirrormodule}"
rsync_run "${opts[@]}" "${src}/" "${dst}/" >> "$logfile" 2>&1
logger -t rsync "Finished updating ${mirrormodule}"  
printf "End: %(%c)T\n" -1 >> "$logfile" 2>&1
rm -f "$lockfile"

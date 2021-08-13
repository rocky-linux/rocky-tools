#!/bin/bash
# 
# migrate2rocky - Migrate another EL8 distribution to RockyLinux 8.
# By: Peter Ajamian <peter@pajamian.dhs.org>
# Adapted from centos2rocky.sh by label <label@rockylinux.org>
#
# The latest version of this script can be found at:
# https://github.com/rocky-linux/rocky-tools
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

## Using this script means you accept all risks of system instability.

# These checks need to be right at the top because we start with bash-isms right
# away in this script.
if [ -n "$POSIXLY_CORRECT" ] || [ -z "$BASH_VERSION" ]; then
    printf '%s\n' "bash >= 4.2 is required for this script." >&2
    exit 1
fi

# We need bash version >= 4.2 for associative arrays and other features.
if (( BASH_VERSINFO[0]*100 + BASH_VERSINFO[1] < 402 )); then
    printf '%s\n' "bash >= 4.2 is required for this script." >&2
    exit 1
fi

# Make sure we're root.
if (( EUID != 0 )); then
    printf '%s\n' \
	"You must run this script as root.  Either use sudo or 'su -c ${0}'" >&2
    exit 1
fi


# Path to logfile
logfile=/var/log/migrate2rocky.log

# Send all output to the logfile as well as stdout.
# After the following we get:
# Output to 1 goes to stdout and the logfile.
# Output to 2 goes to stderr and the logfile.
# Output to 3 just goes to stdout.
# Output to 4 just goes to stderr.
# Output to 5 just goes to the logfile.
truncate -s0 "$logfile"
# shellcheck disable=SC2094
exec \
    3>&1 \
    4>&2 \
    5>> "$logfile" \
    > >(tee -a "$logfile") \
    2> >(tee -a "$logfile" >&2)

# List nocolor last here so that -x doesn't bork the display.
errcolor=$(tput setaf 1)
infocolor=$(tput setaf 6)
nocolor=$(tput op)

# Single arg just gets returned verbatim, multi arg gets formatted via printf.
# First arg is the name of a variable to store the results.
msg_format () {
    local _var
    _var="$1"
    shift
    if (( $# > 1 )); then
	# shellcheck disable=SC2059
	printf -v "$_var" "$@"
    else
	printf -v "$_var" "%s" "$1"
    fi
}

# Send an info message to the log file and stdout (with color)
infomsg () {
    local msg
    msg_format msg "$@"
    printf '%s' "$msg" >&5
    printf '%s%s%s' "$infocolor" "$msg" "$nocolor" >&3
}

# Send an error message to the log file and stderr (with color)
errmsg () {
    local msg
    msg_format msg "$@"
    printf '%s' "$msg" >&5
    printf '%s%s%s' "$errcolor" "$msg" "$nocolor" >&4
}

export LC_ALL=en_US.UTF-8 LANGUAGE=en_US
shopt -s nullglob

SUPPORTED_MAJOR="8"
SUPPORTED_PLATFORM="platform:el$SUPPORTED_MAJOR"
ARCH=$(arch)

gpg_key_url="https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-rockyofficial"
gpg_key_sha512="88fe66cf0a68648c2371120d56eb509835266d9efdf7c8b9ac8fc101bdf1f0e0197030d3ea65f4b5be89dc9d1ef08581adb068815c88d7b1dc40aa1c32990f6a"

sm_ca_dir=/etc/rhsm/ca
unset tmp_sm_ca_dir

# all repos must be signed with the same key given in $gpg_key_url
declare -A repo_urls
repo_urls=(
    [rockybaseos]="https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/BaseOS/$ARCH/os/"
    [rockyappstream]="https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/AppStream/$ARCH/os/"
)

unset CDPATH

exit_message() {
  errmsg $'\n'"$1"$'\n\n'
  final_message
  exit 1
}

final_message() {
    errmsg '%s ' \
	"An error occurred while we were attempting to convert your system to" \
	"Rocky Linux. Your system may be unstable. Script will now exit to" \
	"prevent possible damage."$'\n\n'
    logmessage
}

logmessage(){
    printf '%s%s%s\n' "$infocolor" \
	"A log of this installation can be found at $logfile" \
	"$nocolor" >&3
}

# This just grabs a field from os-release and returns it.
os-release () (
    . /etc/os-release
    if ! [[ ${!1} ]]; then
	return 1
    fi
    printf '%s\n' "${!1}"
)

# Check the version of a package against a supplied version number.  Note that
# this uses sort -V to compare the versions which isn't perfect for rpm package
# versions, but to do a proper comparison we would need to use rpmdev-vercmp in
# the rpmdevtools package which we don't want to force-install.  sort -V should
# be adequate for our needs here.
pkg_ver() (
    ver=$(rpm -q --qf '%{VERSION}\n' "$1") || return 2
    if [[ $(sort -V <<<"$ver"$'\n'"$2" | head -1) != "$2" ]]; then
	return 1
    fi
    return 0
)

# Set up a temporary directory.
pre_setup () {
    if ! tmp_dir=$(mktemp -d) || [[ ! -d "$tmp_dir" ]]; then
	exit_message "Error creating temp dir"
    fi
    # failglob makes pathname expansion fail if empty, dotglob adds files
    # starting with . to pathname expansion
    if ( shopt -s failglob dotglob; : "$tmp_dir"/* ) 2>/dev/null ; then
	exit_message "Temp dir not empty"
    fi
}

# Cleanup function gets rid of the temporary directory.
exit_clean () {
    if [[ -d "$tmp_dir" ]]; then
	rm -rf "$tmp_dir"
    fi
    if [[ -f "$container_macros" ]]; then
	rm -f "$container_macros"
    fi
}

pre_check () {
    if [[ -e /etc/rhsm/ca/katello-server-ca.pem ]]; then
	exit_message \
'Migration from Katello-modified systems is not supported by migrate2rocky. '\
'See the README file for details.'
    fi
    if [[ -e /etc/salt/minion.d/susemanager.conf ]]; then
        exit_message \
'Migration from Uyuni/SUSE Manager-modified systems is not supported by '\
'migrate2rocky. See the README file for details.'
    fi
}

# All of the binaries used by this script are available in a EL8 minimal install
# and are in /bin, so we should not encounter a system where the script doesn't
# work unless it's severely broken.  This is just a simple check that will cause
# the script to bail if any expected system utilities are missing.
bin_check() {
    # Check the platform.
    if [[ $(os-release PLATFORM_ID) != "$SUPPORTED_PLATFORM" ]]; then
	exit_message \
'This script must be run on an EL8 distribution.  Migration from other '\
'distributions is not supported.'
    fi

    local -a missing bins
    bins=(
	rpm dnf awk column tee tput mkdir cat arch sort uniq
	rmdir rm head curl sha512sum mktemp systemd-detect-virt
    )
    if [[ $update_efi ]]; then
	bins+=(findmnt grub2-mkconfig efibootmgr grep mokutil lsblk)
    fi
    for bin in "${bins[@]}"; do
	if ! type "$bin" >/dev/null 2>&1; then
	    missing+=("$bin")
	fi
    done

    local -A pkgs
    pkgs=(
	[dnf]=4.2
	[dnf-plugins-core]=0
    )

    for pkg in "${!pkgs[@]}"; do
	ver=${pkgs[$pkg]}
	if ! pkg_ver "$pkg" "$ver"; then
	    # shellcheck disable=SC2140
	    exit_message \
"$pkg >= $ver is required for this script.  Please run "\
"\"dnf install $pkg; dnf update\" first."
	fi
    done;

    if (( ${#missing[@]} )); then
	exit_message \
"Commands not found: ${missing[*]}.  Possible bad PATH setting or corrupt "\
"installation."
    fi
}

# This function will overwrite the repoquery_results associative array with the
# info for the resulting package.  Note that we explicitly disable the epel repo
# as a special-case below to avoid having the extras repository map to epel.
repoquery () {
    local name val prev result
    result=$(
	dnf -q --setopt=epel.excludepkgs=epel-release repoquery -i "$1" ||
	    exit_message "Failed to fetch info for package $1."
    )
    if ! [[ $result ]]; then
	# We didn't match this package, the repo could be disabled.
	return 1
    fi
    declare -gA repoquery_results=()
    while IFS=" :" read -r name val; do
	if [[ -z $name ]]; then
	    repoquery_results[$prev]+=" $val"
	else
	    prev=$name
	    repoquery_results[$name]=$val
	fi
    done <<<"$result"
}

# This function will overwrite the repoinfo_results associative array with the
# info for the resulting repository.
repoinfo () {
    local name val result
    result=$(dnf -q repoinfo "$1") ||
    	exit_message "Failed to fetch info for repository $1."
    if [[ $result == 'Total packages: 0' ]]; then
	# We didn't match this repo.
	return 1
    fi
    declare -gA repoinfo_results=()
    while IFS=" :" read -r name val; do
	if [[ ! ( $name || $val) ]]; then
	    continue
	fi
	if [[ -z $name ]]; then
	    repoinfo_results[$prev]+=" $val"
	else
	    prev=$name
	    repoinfo_results[$name]=$val
	fi
    done <<<"$result"

    # dnf repoinfo doesn't return the gpgkey, but we need that so we have to get
    # it from the repo file itself.
    # "end_of_file" is a hack here.  Since it is not a valid dnf setting we know
    # it won't appear in a .repo file on a line by itself, so it's safe to
    # search for the string to make the awk parser look all the way to the end
    # of the file.
    # shellcheck disable=SC2154
    repoinfo_results[Repo-gpgkey]=$(
	awk '
	    $0=="['"${repoinfo_results[Repo-id]}"']",$0=="end_of_file" {
		if (l++ < 1) {next}
		else if (/^\[.*\]$/) {nextfile}
		else if (sub(/^gpgkey\s*=\s*file:\/\//,"")) {print; nextfile}
		else {next}
	    }
	' < "${repoinfo_results[Repo-filename]}"
    )

    # Add an indicator of whether this is a subscription-manager managed
    # repository.
    # shellcheck disable=SC2154
    repoinfo_results[Repo-managed]=$(
	awk '
            BEGIN {FS="[)(]"}
            /^# Managed by \(.*\) subscription-manager$/ {print $2}
        ' < "${repoinfo_results[Repo-filename]}"
    )
}

provides_pkg () (
    if [[ ! $1 ]]; then
	return 0
    fi

    set -o pipefail
    provides=$(dnf -q provides "$1" | awk '{print $1; nextfile}') ||
	return 1
    set +o pipefail
    pkg=$(rpm -q --queryformat '%{NAME}\n' "$provides") ||
    	pkg=$(dnf -q repoquery --queryformat '%{NAME}\n' "$provides") ||
    	exit_message "Can't get package name for $provides."
    printf '%s\n' "$pkg"
)

# If you pass an empty arg as one of the package specs to rpm it will match
# every package on the system.  This funtion simply strips out any empty args
# and passes the rest to rpm to avoid this side-effect.
saferpm () (
    args=()
    for a in "$@"; do
	if [[ $a ]]; then
	    args+=("$a")
	fi
    done
    rpm "${args[@]}"
)

# And a similar function for dnf
safednf () (
    args=()
    for a in "$@"; do
	if [[ $a ]]; then
	    args+=("$a")
	fi
    done
    dnf "${args[@]}"
)

collect_system_info () {
    # Dump the DNF cache first so we start with a clean slate.
    infomsg $'\nRemoving dnf cache\n'
    rm -rf /var/cache/{yum,dnf}
    # Check the efi mount first, so we can bail before wasting time on all these
    # other checks if it's not there.
    if [[ $update_efi ]]; then
	local efi_mount kname
	declare -g -a efi_disk efi_partition
	efi_mount=$(findmnt --mountpoint /boot/efi --output SOURCE \
	    --noheadings) ||
	    exit_message "Can't find EFI mount.  No EFI  boot detected."
	kname=$(lsblk -dno kname "$efi_mount")
	efi_disk=$(lsblk -dno pkname "/dev/$kname")

	if [[ $efi_disk ]]; then
	    efi_partition=$(<"/sys/block/$efi_disk/$kname/partition")
	else
	    # This is likely an md-raid or other type of virtual disk, we need
	    # to dig a little deeper to find the actual physical disks and
	    # partitions.
	    kname=$(lsblk -dno kname "$efi_mount")
	    cd "/sys/block/$kname/slaves" || exit_message \
"Unable to gather EFI data: Can't cd to /sys/block/$kname/slaves."
	    if ! (shopt -s failglob; : ./*) 2>/dev/null; then
		exit_message \
"Unable to gather EFI data: No slaves found in /sys/block/$kname/slaves."
	    fi
	    efi_disk=()
	    for d in *; do
		efi_disk+=("$(lsblk -dno pkname "/dev/$d")")
		efi_partition+=("$(<"$d/partition")")
		if [[ ! ${efi_disk[-1]} || ! ${efi_partition[-1]} ]]; then
		    exit_message \
"Unable to gather EFI data: Can't find disk name or partition number for $d."
		fi
	    done
	    cd -
	fi
    fi

    # check if EFI secure boot is enabled
    if [[ $update_efi ]]; then
	if mokutil --sb-state 2>&1 | grep -q "SecureBoot enabled"; then
	    exit_message \
"EFI Secure Boot is enabled but Rocky Linux doesn't provide a signed shim yet."\
" Disable EFI Secure Boot and reboot."
	fi
    fi

    # Don't enable these module streams, even if they are enabled in the source
    # distro.
    declare -g -a module_excludes
    module_excludes=(
	libselinux-python:2.8
    )

    # Some OracleLinux modules have stream names of ol8 instead of rhel8 and ol
    # instead of rhel.  This is a map that does a glob match and replacement.
    local -A module_glob_map
    module_glob_map=(
	['%:ol8']=:rhel8
	['%:ol']=:rhel
    );

    # We need to map rockylinux repository names to the equivalent repositories
    # in the source distro.  To do that we look for known packages in each
    # repository and see what repo they came from.  We need to use repoquery for
    # this which requires downloading the package, so we pick relatively small
    # packages for this.
    declare -g -A repo_map pkg_repo_map
    declare -g -a managed_repos
    pkg_repo_map=(
	[baseos]=rootfiles.noarch
	[appstream]=apr-util-ldap.$ARCH
	[ha]=pacemaker-doc.noarch
	[powertools]=libaec-devel.$ARCH
	[extras]=epel-release.noarch
    )
#	[devel]=quota-devel.$ARCH

    PRETTY_NAME=$(os-release PRETTY_NAME)
    infomsg '%s' \
	"Preparing to migrate $PRETTY_NAME to Rocky Linux 8."$'\n\n' \
	"Determining repository names for $PRETTY_NAME"

    for r in "${!pkg_repo_map[@]}"; do
	printf '.'
	p=${pkg_repo_map[$r]}
	repoquery "$p" || continue
	repo_map[$r]=${repoquery_results[Repository]}
    done

    printf '%s\n' '' '' \
"Found the following repositories which map from $PRETTY_NAME to Rocky Linux 8:"
    column -t -s $'\t' -N "$PRETTY_NAME,Rocky Linux 8" < <(
	for r in "${!repo_map[@]}"; do
	    printf '%s\t%s\n' "${repo_map[$r]}" "$r"
	done
    )

    infomsg $'\n'"Getting system package names for $PRETTY_NAME"

    # We don't know what the names of these packages are, we have to discover
    # them via various means. The most common means is to look for either a
    # distro-agnostic provides or a filename.  In a couple of cases we need to
    # jump through hoops to get a filename that is provided specifically by the
    # source distro.
    # Get info for each repository to determine which ones are subscription
    # managed.
    # system-release here is a bit of a hack, but it ensures that the
    # rocky-repos package will get installed.
    for r in "${!repo_map[@]}"; do
	repoinfo "${repo_map[$r]}"
	if [[ $r == "baseos" ]]; then
	    local baseos_filename=system-release
	    if [[ ! ${repoinfo_results[Repo-managed]} ]]; then
		baseos_filename="${repoinfo_results[Repo-filename]}"
	    fi
	    local baseos_gpgkey="${repoinfo_results[Repo-gpgkey]}"
	fi
	if [[ ${repoinfo_results[Repo-managed]} ]]; then
	    managed_repos+=("${repo_map[$r]}")
	fi
    done

    # First get info for the baseos repo
    repoinfo "${repo_map[baseos]}"
    declare -g -A pkg_map provides_pkg_map
    declare -g -a addl_provide_removes addl_pkg_removes
    provides_pkg_map=(
	[rocky-backgrounds]=system-backgrounds
	[rocky-indexhtml]=redhat-indexhtml
	[rocky-repos]="$baseos_filename"
	[rocky-logos]=system-logos
	[rocky-logos-httpd]=system-logos-httpd
	[rocky-logos-ipa]=system-logos-ipa
	[rocky-gpg-keys]="$baseos_gpgkey"
	[rocky-release]=system-release
    )
    addl_provide_removes=(
	redhat-release
	redhat-release-eula
    )

    # Check to make sure that we don't already have a full or partial
    # RockyLinux install.
    if [[ $(rpm -qa "${!provides_pkg_map[@]}") ]]; then
	exit_message \
$'Found a full or partial RockyLinux install already in place.  Aborting\n'
$'because continuing with the migration could cause further damage to system.'
    fi

    for pkg in "${!provides_pkg_map[@]}"; do
	printf '.'
	prov=${provides_pkg_map[$pkg]}
	pkg_map[$pkg]=$(provides_pkg "$prov") ||
	    exit_message "Can't get package that provides $prov."
    done
    for prov in "${addl_provide_removes[@]}"; do
	printf '.'
	local pkg;
	pkg=$(provides_pkg "$prov") || continue
	addl_pkg_removes+=("$pkg")
    done

    printf '%s\n' '' '' \
"Found the following system packages which map from $PRETTY_NAME to Rocky "\
"Linux 8:"
    column -t -s $'\t' -N "$PRETTY_NAME,Rocky Linux 8" < <(
	for p in "${!pkg_map[@]}"; do
	    printf '%s\t%s\n' "${pkg_map[$p]}" "$p"
	done
    )

    infomsg $'\n'"Getting list of installed system packages."$'\n'

    readarray -t installed_packages < <(
	saferpm -qa --queryformat="%{NAME}\n" "${pkg_map[@]}"
    )
    declare -g -A installed_pkg_check installed_pkg_map
    for p in "${installed_packages[@]}"; do
	installed_pkg_check[$p]=1
    done
    for p in "${!pkg_map[@]}"; do
	if [[ ${pkg_map[$p]} && ${installed_pkg_check[${pkg_map[$p]}]} ]]; then
	    installed_pkg_map[$p]=${pkg_map[$p]}
 	fi
    done;

    printf '%s\n' '' \
"We will replace the following $PRETTY_NAME packages with their Rocky Linux 8 "\
"equivalents"
    column -t -s $'\t' -N "Packages to be Removed,Packages to be Installed" < <(
	for p in "${!installed_pkg_map[@]}"; do
	    printf '%s\t%s\n' "${installed_pkg_map[$p]}" "$p"
	done
    )

    if (( ${#addl_pkg_removes[@]} )); then
	printf '%s\n' '' \
"In addition to the above the following system packages will be removed:" \
	    "${addl_pkg_removes[@]}"
    fi

    # Release packages that are part of SIG's should be listed below when they
    # are available.
    # UPDATE: We may or may not do something with SIG's here, it could just be
    # left as a separate excercise to swap out the sig repos.
    #sigs_to_swap=()

    infomsg '%s' $'\n' \
	$'Getting a list of enabled modules for the system repositories.\n'

    # Get a list of system enabled modules.
    readarray -t enabled_modules < <(
	set -e -o pipefail
	safednf -q "${repo_map[@]/#/--repo=}" module list --enabled |
	awk '
	    $1 == "@modulefailsafe", /^$/ {next}
	    $1 == "Name", /^$/ {if ($1!="Name" && !/^$/) print $1":"$2}
    	' | sort -u
	set +e +o pipefail
    )

    # Map the known module name differences.
    disable_modules=()
    local i gl repl mod
    for i in "${!enabled_modules[@]}"; do
	mod=${enabled_modules[$i]}
	for gl in "${!module_glob_map[@]}"; do
	    repl=${module_glob_map[$gl]}
	    mod=${mod/$gl/$repl}
	done
	if [[ $mod != "${enabled_modules[$i]}" ]]; then
	    disable_modules+=(${enabled_modules[$i]})
	    enabled_modules[$i]=$mod
	fi
    done

    # Remove entries matching any excluded modules.
    if (( ${#module_excludes[@]} )); then
	printf '%s\n' '' "Excluding modules:" "${module_excludes[@]}"
	local -A module_check='()'
	local -a tmparr='()'
	for m in "${module_excludes[@]}"; do
	    module_check[$m]=1
	done
	for m in "${enabled_modules[@]}"; do
	    if [[ ! ${module_check[$m]} ]]; then
		tmparr+=("$m")
	    fi
	done
	enabled_modules=("${tmparr[@]}")
    fi

    printf '%s\n' '' "Found the following modules to re-enable at completion:" \
	"${enabled_modules[@]}" ''

    if (( ${#managed_repos[@]} )); then
	printf '%s\n' '' \
'In addition, since this system uses subscription-manager the following '\
'managed repos will be disabled:' \
	    "${managed_repos[@]}"
    fi
}

convert_info_dir=/root/convert
unset convert_to_rocky reinstall_all_rpms verify_all_rpms update_efi \
    container_macros

usage() {
  printf '%s\n' \
      "Usage: ${0##*/} [OPTIONS]" \
      '' \
      'Options:' \
      '-h Display this help' \
      '-r Convert to rocky' \
      '-V Verify switch' \
      '   !! USE WITH CAUTION !!'
  exit 1
} >&2

generate_rpm_info() {
    mkdir /root/convert
    infomsg  "Creating a list of RPMs installed: $1"$'\n'
    rpm -qa --qf \
"%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|"\
"%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}\n" |
	sort > "${convert_info_dir}/$HOSTNAME-rpm-list-$1.log"
    infomsg "Verifying RPMs installed against RPM database: $1"$'\n\n'
    rpm -Va | sort -k3 > \
	"${convert_info_dir}/$HOSTNAME-rpm-list-verified-$1.log"
}

# Run a dnf update before the actual migration.
pre_update() {
    infomsg '%s\n' "Running dnf update before we attempt the migration."
    dnf -y update || exit_message \
$'Error running pre-update.  Stopping now to avoid putting the system in an\n'\
$'unstable state.  Please correct the issues shown here and try again.'
}

package_swaps() {
    # Save off any subscription-manager keys, just in case.
    if ( shopt -s failglob dotglob; : "$sm_ca_dir"/* ) 2>/dev/null ; then
	tmp_sm_ca_dir=$tmp_dir/sm-certs
	mkdir "$tmp_sm_ca_dir" ||
	    exit_message "Could not create directory: $tmp_sm_ca_dir"
	cp -f -dR --preserve=all "$sm_ca_dir"/* "$tmp_sm_ca_dir/" ||
	    exit_message "Could not copy certs to $tmp_sm_ca_dir"
    fi

    # prepare repo parameters
    local -a dnfparameters
    for repo in "${!repo_urls[@]}"; do
	dnfparameters+=( "--repofrompath=${repo},${repo_urls[${repo}]}" )
	dnfparameters+=( "--setopt=${repo}.gpgcheck=1" )
	dnfparameters+=( "--setopt=${repo}.gpgkey=file://${gpg_key_file}" )
    done

    # Use dnf shell to swap the system packages out.
    safednf -y shell --disablerepo=\* --noautoremove \
	--setopt=protected_packages= --setopt=keepcache=True \
	"${dnfparameters[@]}" \
	<<EOF
	remove ${installed_pkg_map[@]} ${addl_pkg_removes[@]}
	install ${!installed_pkg_map[@]}
	run
	exit
EOF

    # rocky-repos and rocky-gpg-keys are now installed, so we don't need the
    # key file anymore
    rm -rf "$gpg_tmp_dir"

    # We need to check to make sure that all of the original system packages
    # have been removed and all of the new ones have been added. If a package
    # was supposed to be removed and one with the same name added back then
    # we're kind of screwed for this check, as we can't be certain, but all the
    # packages we're adding start with "rocky-*" so this really shouldn't happen
    # and we can safely not check for it.  The worst that will happen is a rocky
    # linux package will be removed and then installed again.
    local -a check_removed check_installed
    readarray -t check_removed < <(
	saferpm -qa --qf '%{NAME}\n' "${installed_pkg_map[@]}" \
	    "${addl_pkg_removes[@]}" | sort -u
    )

    if (( ${#check_removed[@]} )); then
	infomsg '%s' $'\n' \
	    "Packages found on system that should still be removed.  Forcibly" \
	    " removing them with rpm:"$'\n'
	# Removed packages still found on the system.  Forcibly remove them.
	for pkg in "${check_removed[@]}"; do
	    # Extra safety measure, skip if empty string
	    if [[ -z $pkg ]]; then
		continue
	    fi
	    printf '%s\n' "$pkg"
	    saferpm -e --allmatches --nodeps "$pkg" ||
	    saferpm -e --allmatches --nodeps --noscripts --notriggers "$pkg"
	done
    fi

    # Check to make sure we installed everything we were supposed to.
    readarray -t check_installed < <(
	{
	    printf '%s\n' "${!installed_pkg_map[@]}" | sort -u
	    saferpm -qa --qf '%{NAME}\n' "${!installed_pkg_map[@]}" | sort -u
	} | sort | uniq -u
    )
    if (( ${#check_installed[@]} )); then
	infomsg '%s' $'\n' \
	    "Some required packages were not installed by dnf.  Attempting to" \
	    " force with rpm:"$'\n'

	# Get a list of rpm packages to package names
	local -A rpm_map
	local -a file_list
	for rpm in /var/cache/dnf/{rockybaseos,rockyappstream}-*/packages/*.rpm
	do
	    rpm_map[$(
		    rpm -q --qf '%{NAME}\n' --nodigest "$rpm" 2>/dev/null
		    )]=$rpm
	done

	# Attempt to install.
	for pkg in "${check_installed[@]}"; do
	    printf '%s\n' "$pkg"
	    if ! rpm -i --force --nodeps --nodigest "${rpm_map[$pkg]}" \
		2>/dev/null; then
		# Try to install the package in just the db, then clean it up.
		rpm -i --force --justdb --nodeps --nodigest "${rpm_map[$pkg]}" \
		    2>/dev/null

		# Get list of files that are still causing problems and donk
		# them.
		readarray -t file_list < <(
		    rpm -V "$pkg" 2>/dev/null | awk '$1!="missing" {print $2}'
		)
		for file in "${file_list[@]}"; do
		    rmdir "$file" ||
		    rm -f "$file" ||
		    rm -rf "$file"
		done

		# Now try re-installing the package to replace the missing
		# files.  Regardless of the outcome here we just accept it and
		# move on and hope for the best.
		rpm -i --reinstall --force --nodeps --nodigest \
		    "${rpm_map[$pkg]}" 2>/dev/null
	    fi
	done
    fi

    # Distrosync
    infomsg $'Ensuring repos are enabled before the package swap\n'
    safednf -y --enableplugin=config-manager config-manager \
	--set-enabled "${!repo_map[@]}" || {
	printf '%s\n' 'Repo name missing?'
	exit 25
    }

    if (( ${#managed_repos[@]} )); then
	# Filter the managed repos for ones still in the system.
	readarray -t managed_repos < <(
	    safednf -q repolist "${managed_repos[@]}" |
	    	awk '$1!="repo" {print $1}'
	)

	if (( ${#managed_repos[@]} )); then
	    infomsg $'\nDisabling subscription managed repos\n'
	    safednf -y --enableplugin=config-manager config-manager \
		--disable "${managed_repos[@]}"
	fi
    fi

    if (( ${#disable_modules[@]} )); then
	infomsg $'Disabling modules\n\n'
	safednf -y module disable "${disable_modules[@]}" ||
	    exit_message "Can't disable modules ${disable_modules[*]}"
    fi

    if (( ${#enabled_modules[@]} )); then
	infomsg $'Enabling modules\n\n'
	safednf -y module enable "${enabled_modules[@]}" ||
    	    exit_message "Can't enable modules ${enabled_modules[*]}"
    fi

    # Make sure that excluded repos are disabled.
    infomsg $'Disabling excluded modules\n\n'
    safednf -y module disable "${module_excludes[@]}" ||
    	exit_message "Can't disable modules ${module_excludes[*]}"

    infomsg $'\nSyncing packages\n\n'
    dnf -y distro-sync || exit_message "Error during distro-sync."

    if rpm --quiet -q subscription-manager; then
	infomsg $'Subscription Manager found on system.\n'
	cat <<EOF
If you're converting from a subscription-managed distribution such as RHEL then
you may no longer need subscription-manager or dnf-plugin-subscription-manager.
While it won't hurt anything to have it on your system you may be able to safely
remove it with:

"dnf remove subscription-manager dnf-plugin-subscription-manager".

Take care that it doesn't remove something that you want to keep.

The subscription-manager dnf plugin may be enabled for the benefit of
Subscription Management. If no longer desired, you can use
"subscription-manager config --rhsm.auto_enable_yum_plugins=0" to block this
behavior.

EOF
    fi
    if [[ $tmp_sm_ca_dir ]]; then
	# Check to see if there's Subscription Manager certs which have been
	# removed
	local -a removed_certs
	readarray -t removed_certs < <((
	    shopt -s nullglob dotglob
	    local -a certs
	    cd "$sm_ca_dir" && certs=(*)
	    cd "$tmp_sm_ca_dir" && certs+=(*)
	    IFS=$'\n'
	    printf '%s' "${certs[*]}"
	) | sort | uniq -u)

	if (( ${#removed_certs[@]} )); then
	    cp -n -dR --preserve=all "$tmp_sm_ca_dir"/* "$sm_ca_dir/" ||
		exit_message "Could not copy certs back to $sm_ca_dir"
	    
	    infomsg '%s' \
		$'Some Subscription Manager certificates ' \
		"were restored to $sm_ca_dir after"$'\n' \
		$'migration so that the subscription-manager ' \
		$'command will continue to work:\n\n'
	    printf '%s\n' "${removed_certs[@]}" ''
	    cat <<EOF
If you no longer need to use the subscription-manager command then you may
safely remove these files.
EOF
	fi
    fi
}

# Check if this system is running on EFI
# If yes, we'll need to run fix_efi() at the end of the conversion
efi_check () {
    # Check if we have /sys mounted and it is looking sane
    if ! [[ -d /sys/class/block ]]; then
	exit_message "/sys is not accessible."
    fi
    
    # Now that we know /sys is reliable, use it to check if we are running on
    # EFI or not
    if systemd-detect-virt --quiet --container; then
	declare -g container_macros
	container_macros=$(mktemp /etc/rpm/macros.zXXXXXX)
	printf '%s\n' '%_netsharedpath /sys:/proc' > "$container_macros"
    elif [[ -d /sys/firmware/efi/ ]]; then
	declare -g update_efi
	update_efi=true
    fi
}

# Called to update the EFI boot.
fix_efi () (
    grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg ||
    	exit_message "Error updating the grub config."
    for i in "${!efi_disk[@]}"; do
	efibootmgr -c -d "/dev/${efi_disk[$i]}" -p "${efi_partition[$i]}" \
	    -L "Rocky Linux" -l /EFI/rocky/grubx64.efi ||
	    exit_message "Error updating uEFI firmware."
    done
)

# Download and verify the Rocky Linux package signing key
establish_gpg_trust () {
    # create temp dir and verify it is really created and empty, so we are sure
    # deleting it afterwards won't cause any harm
    declare -g gpg_tmp_dir
    gpg_tmp_dir=$tmp_dir/gpg
    if ! mkdir "$gpg_tmp_dir" || [[ ! -d "$gpg_tmp_dir" ]]; then
	exit_message "Error creating temp dir"
    fi
    # failglob makes pathname expansion fail if empty, dotglob adds files
    # starting with . to pathname expansion
    if ( shopt -s failglob dotglob; : "$gpg_tmp_dir"/* ) 2>/dev/null ; then
	exit_message "Temp dir not empty"
    fi

    # extract the filename from the url, use the temp dir just created
    declare -g gpg_key_file="$gpg_tmp_dir/${gpg_key_url##*/}"

    if ! curl -L -o "$gpg_key_file" --silent --show-error "$gpg_key_url"; then
	rm -rf "$gpg_tmp_dir"
	exit_message "Error downloading the Rocky Linux signing key."
    fi

    if ! sha512sum --quiet -c <<<"$gpg_key_sha512 $gpg_key_file"; then
	rm -rf "$gpg_tmp_dir"
	exit_message "Error validating the signing key."
    fi
}

## End actual work

noopts=0
while getopts "hrVR" option; do
  (( noopts++ ))
  case "$option" in
    h)
      usage
      ;;
    r)
      convert_to_rocky=true
      ;;
    V)
      verify_all_rpms=true
      ;;
    *)
      errmsg $'Invalid switch\n'
      usage
      ;;
  esac
done
if (( ! noopts )); then
    usage
fi

pre_setup
trap exit_clean EXIT
pre_check
efi_check
bin_check

if [[ $verify_all_rpms ]]; then
  generate_rpm_info begin
fi

if [[ $convert_to_rocky ]]; then
    collect_system_info
    establish_gpg_trust
    pre_update
    package_swaps
fi

if [[ $verify_all_rpms && $convert_to_rocky ]]; then
  generate_rpm_info finish
  infomsg $'You may review the following files:\n'
  find /root/convert -type f -name "$HOSTNAME-rpms-*.log"
fi

if [[ $update_efi && $convert_to_rocky ]]; then
    fix_efi
fi

printf '\n\n\n'
if [[ $convert_to_rocky ]]; then
    infomsg $'\nDone, please reboot your system.\n'
fi
logmessage

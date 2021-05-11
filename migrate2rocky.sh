#!/bin/bash
# 
# migrate2rocky - Migrate another EL8 distribution to RockyLinux 8.
# By: Peter Ajamian <peter@pajamian.dhs.org>
# Adapted from centos2rocky.sh by label <label@rockylinux.org>
#

## Rocky is RC status. Using this script means you accept all risks of system
## instability.

# Path to logfile
logfile=/var/log/centos2rocky.log

# Send all output to the logfile as well as stdout.
truncate -s0 "$logfile"
exec > >(tee -a "$logfile") 2> >(tee -a "$logfile" >&2)

# List nocolor last here so that +x doesn't bork the display.
errcolor=$(tput setaf 1)
blue=$(tput setaf 4)
nocolor=$(tput op)

export LANG=en_US.UTF-8

SUPPORTED_MAJOR="8"
SUPPORTED_PLATFORM="platform:el$SUPPORTED_MAJOR"
ARCH=$(arch)
repo_urls=(
    "rockybaseos,https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/BaseOS/$ARCH/os/"
    "rockyappstream,https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/AppStream/$ARCH/os/"
)

unset CDPATH

exit_message() {
  printf '%s\n' "$1"
  final_message
  exit 1
} >&2

final_message() {
  printf '%s\n' "${errcolor}An error occurred while we were attempting to convert your system to Rocky Linux. Your system may be unstable. Script will now exit to prevent possible damage.$nocolor"
  logmessage
}

logmessage(){
  printf '%s\n' "${blue}A log of this installation can be found at $logfile$nocolor"
}

# This just grabs a field from os-release and returns it.
os-release () {
    . /etc/os-release
    if ! [[ ${!1} ]]; then
	return 1
    fi
    printf '%s\n' "${!1}"
}

# All of the binaries used by this script are available in a EL8 minimal install
# and are in /bin, so we should not encounter a system where the script doesn't
# work unless it's severly broken.  This is just a simple check that will cause
# the script to bail if any expected system utilities are missing.
bin_check() {
    # Make sure we're root.
    if (( EUID != 0 )); then
	exit_message "You must run this script as root.  Either use sudo or 'su -c ${0}'"
    fi

    # Check the platform.
    if [[ $(os-release PLATFORM_ID) != $SUPPORTED_PLATFORM ]]; then
	exit_message "This script must be run on an EL8 distribution.  Migration from other distributions is not supported."
    fi

    # We need bash version >= 4 for associative arrays.  This will also verify
    # that we're actually running bash.
    if (( BASH_VERSINFO < 4 )); then
	exit_message "bash >= 4.0 is required for this script."
    fi

    local -a missing
    for bin in rpm dnf awk column tee tput mkdir cat arch; do
	if ! type "$bin" >/dev/null 2>&1; then
	    missing+=("$bin")
	fi
    done

    if (( ${#missing[@]} )); then
	exit_message "Commands not found: ${missing[@]}.  Possible bad PATH setting or corrupt installation."
    fi
}

# This function will overwrite the repoquery_results associative array with the
# info for the resulting package.  Note that we explicitly disable the epel repo
# as a special-case below to avoid having the extras repository map to epel.
repoquery () {
    local name val prev result=$(
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
	if [[ -z $name ]]; then
	    repoinfo_results[$prev]+=" $val"
	else
	    prev=$name
	    repoinfo_results[$name]=$val
	fi
    done <<<"$result"

    # dnf repoinfo doesn't return the gpgkey, but we need that so we have to get
    # it from the repo file itself.
    repoinfo_results[Repo-gpgkey]=$(
	awk '
	    $1=="['"${repoinfo_results[Repo-id]}"']" {next}
	    {if (/^\[.*\]$/) {nextfile}
	     else if (sub(/^gpgkey=file:\/\//,"")) print
	    }' < "${repoinfo_results[Repo-filename]}"
    )
}

collect_system_info () {
    # We need to map rockylinux repository names to the equivalent repositories
    # in the source distro.  To do that we look for known packages in each
    # repository and see what repo they came from.  We need to use repoquery for
    # this which requires downloading the package, so we pick relatively small
    # packages for this.
    declare -g -A repo_map pkg_repo_map
    pkg_repo_map=(
	[baseos]=rootfiles.noarch
	[appstream]=apr-util-ldap.$ARCH
	[devel]=quota-devel.$ARCH
	[ha]=pacemaker-doc.noarch
	[powertools]=libaec-devel.$ARCH
	[extras]=epel-release.noarch
    )

    PRETTY_NAME=$(os-release PRETTY_NAME)
    printf '%s\n' "${blue}Preparing to migrate $PRETTY_NAME to Rocky Linux 8.$nocolor"
    printf '\n%s' "${blue}Determining repository names for $PRETTY_NAME$nocolor"

    for r in "${!pkg_repo_map[@]}"; do
	printf '.'
	p=${pkg_repo_map[$r]}
	repoquery "$p" || continue
	repo_map[$r]=${repoquery_results[Repository]}
    done

    printf '%s\n' '' '' "Found the following repositories which map from $PRETTY_NAME to Rocky Linux 8:"
    column -t -N "$PRETTY_NAME,Rocky Linux 8" < <(for r in "${!repo_map[@]}"; do
	printf '%s %s\n' "${repo_map[$r]}" "$r"
	done)

    printf '\n%s' "${blue}Getting system package names for $PRETTY_NAME$nocolor."

    # We don't know what the names of these packages are, we have to discover
    # them via various means. The most common means is to look for either a
    # distro-agnostic provides or a filename.  In a couple of cases we need to
    # jump through hoops to get a filename that is provided specifically by the
    # source distro.
    # First get info for the baseos repo
    repoinfo "${repo_map[baseos]}"
    declare -g -A pkg_map provides_pkg_map
    provides_pkg_map=(
	[rocky-backgrounds]=system-backgrounds
	[rocky-indexhtml]=redhat-indexhtml
	[rocky-repos]="${repoinfo_results[Repo-filename]}"
	[rocky-logos]=system-logos
	[rocky-gpg-keys]="${repoinfo_results[Repo-gpgkey]}"
	[rocky-release]=system-release
    )

    for pkg in "${!provides_pkg_map[@]}"; do
	printf '.'
	prov=${provides_pkg_map[$pkg]}
	local provides
	set -o pipefail
	provides=$(dnf -q provides "$prov" | awk '{print $1; nextfile}') ||
	    exit_message "Can't get package that provides $prov."
	set +o pipefail
	pkg_map[$pkg]=$(dnf -q repoquery --queryformat '%{NAME}' "$provides") ||
	    exit_message "Can't get package name for $provides."
    done

    printf '%s\n' '' '' "Found the following system packages which map from $PRETTY_NAME to Rocky Linux 8:"
    column -t -N "$PRETTY_NAME,Rocky Linux 8" < <(for p in "${!pkg_map[@]}"; do
	printf '%s %s\n' "${pkg_map[$p]}" "$p"
	done)

    printf '%s\n' '' "${blue}Getting list of installed system packages$nocolor."
    readarray -t installed_packages < <(rpm -qa --queryformat="%{NAME}\n" "${pkg_map[@]}")
    declare -g -A installed_pkg_check installed_pkg_map
    for p in "${installed_packages[@]}"; do
	installed_pkg_check[$p]=1
    done
    for p in "${!pkg_map[@]}"; do
	if [[ ${installed_pkg_check[${pkg_map[$p]}]} ]]; then
	    installed_pkg_map[$p]=${pkg_map[$p]}
	fi
    done;

    printf '%s\n' '' "We will replace the following $PRETTY_NAME packages with their Rocky Linux 8 equivalents"
    column -t -N "Packages to be Removed,Packages to be Installed" < <(
	for p in "${!installed_pkg_map[@]}"; do
	    printf '%s %s\n' "${installed_pkg_map[$p]}" "$p"
	done
    )

    # Release packages that are part of SIG's should be listed below when they
    # are available.
    # UPDATE: We may or may not do something with SIG's here, it could just be
    # left as a separate excersize to swap out the sig repos.
    #sigs_to_swap=()

    printf '%s\n' '' "${blue}Getting a list of enabled modules for the system repositories$nocolor."

    # Get a list of system enabled modules.
    readarray -t enabled_modules < <(
	set -e -o pipefail
	dnf -q "${repo_map[@]/#/--repo=}" module list --enabled |
	awk '
	    $1 == "@modulefailsafe", /^$/ {next}
	    $1 == "Name", /^$/ {if (line++>0 && !/^$/) print $1":"$2}
    	'
	set +e +o pipefail
    )

    printf '%s\n' '' "Found the following modules to re-enable at completion:"
    printf '%s\n' "${enabled_modules[@]}" ''
}

convert_info_dir=/root/convert
unset convert_to_rocky reinstall_all_rpms verify_all_rpms

usage() {
  printf '%s\n' \
      "Usage: ${0##*/} [OPTIONS]" \
      '' \
      'Options:' \
      '-h displays this help' \
      '-r Converts to rocky' \
      '-V Verifies switch' \
      '-R Reinstall all packages' \
      '   !! USE WITH CAUTION !!'
  exit 1
} >&2

generate_rpm_info() {
  mkdir /root/convert
  printf '%s\n' "${blue}Creating a list of RPMs installed: $1$nocolor"
  rpm -qa --qf "%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}\n" | sort > "${convert_info_dir}/$HOSTNAME-rpm-list-$1.log"
  printf '%s\n' "${blue}Verifying RPMs installed against RPM database: $1$nocolor" ''
  rpm -Va | sort -k3 > "${convert_info_dir}/$HOSTNAME-rpm-list-verified-$1.log"
}

package_swaps() {
    # Use dnf shell to swap the system packages out.
    if dnf -y shell --nogpg --disablerepo=\* \
	"${repo_urls[@]/#/--repofrompath=}" <<EOF
	remove ${installed_pkg_map[@]}
	install ${!installed_pkg_map[@]}
	run
	exit
EOF
    then :
    else return
    fi

    # Distrosync
    printf '%s\n' '' "${blue}Removing dnf cache$nocolor"
    rm -rf /var/cache/{yum,dnf}
    printf '%s\n' "${blue}Ensuring repos are enabled before the package swap$nocolor"
    dnf -y config-manager --set-enabled "${!repo_map[@]}" || {
      printf '%s\n' 'Repo name missing?'
      exit 25
    }
    printf '%s\n' "${blue}Enabling modules$nocolor" ''

    # We may very well need to do a reset/install here, but it takes a decent
    # amount of time, so we're better off just doing an enable unless we end up
    # with an explicit test case where reset/install is needed.
#    dnf -y module reset "${enabled_modules[@]}"
#    dnf -y module install "${enabled_modules[@]}"
    dnf -y module enable "${enabled_modules[@]}" ||
    	exit_message "Can't enable modules ${enabled_modules[@]}"
    printf '%s\n' '' "${blue}Syncing packages$nocolor" ''
    dnf -y distro-sync || exit_message "Error during distro-sync."
}

#sig_swaps() {
#  exit_message "Not Available"
#}

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
    R)
       exit_message 'Reinstalling all rpms is not supported at this time.'
#      reinstall_all_rpms=true
      ;;
    *)
      printf '%s\n' "${errcolor}Invalid switch.$nocolor"
      usage
      ;;
  esac
done
if (( ! noopts )); then
    usage
fi

bin_check

if [[ $verify_all_rpms ]]; then
  generate_rpm_info begin
fi

if [[ $convert_to_rocky ]]; then
    collect_system_info
    package_swaps
fi

# Warning, this is potentially dangerous.
if [[ $reinstall_all_rpms ]]; then
  printf '%s\n' "${errcolor}!! THIS MAY CAUSE ISSUES WITH YOUR SYSTEM !!$nocolor"
  rpm_list=("$(rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE} %{VENDOR}\n" | grep CentOS | awk '{print $1}')")
  if [[ -n "${rpm_list[*]}" ]]; then
    printf '%s ' 'Reinstalling rpms:' "${rpm_list[@]}"
    dnf reinstall "${rpm_list[@]}" -y
  fi
  non_rocky_rpm=("$(rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}|%{VENDOR}|%{PACKAGER}\n" |grep -iv Rocky)")
  if [[ -n ${non_rocky_rpm[*]} ]]; then
    printf '%s\n' "${blue}Non-Rocky packages are installed. This is generally not an issue. If you see centos packages, you may need to address them and file a bug report at https://bugs.rockylinux.org$nocolor"
    printf '\t%s\n' "${non_rocky_rpm[@]}"
  fi
fi

if [[ $verify_all_rpms && $convert_to_rocky ]]; then
  generate_rpm_info finish
  printf '%s\n' "${blue}You may review the following files:$nocolor"
  find /root/convert -type f -name "$HOSTNAME-rpms-*.log"
fi

printf '\n\n\n'
if [[ $convert_to_rocky ]]; then
    cat /etc/issue | awk 'NR<=15'
    printf '%s\n' "$blue" "Done, please reboot your system.$nocolor"
fi
logmessage
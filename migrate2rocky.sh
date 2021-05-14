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
shopt -s nullglob

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
os-release () (
    . /etc/os-release
    if ! [[ ${!1} ]]; then
	return 1
    fi
    printf '%s\n' "${!1}"
)

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
    for bin in rpm dnf awk column tee tput mkdir cat arch sort uniq rmdir rm; do
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
    # "end_of_file" is a hack here.  Since it is not a valid dnf setting we know
    # it won't appear in a .repo file on a line by itself, so it's safe to
    # search for the string to make the awk parser look all the way to the end
    # of the file.
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
    pkg=$(dnf -q repoquery --queryformat '%{NAME}' "$provides") ||
    	exit_message "Can't get package name for $provides."
    printf '%s\n' "$pkg"
)

collect_system_info () {
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
	[rocky-gpg-keys]="$baseos_gpgkey"
	[rocky-release]=system-release
    )
    addl_provide_removes=(
	redhat-release-eula
    )

    for pkg in "${!provides_pkg_map[@]}"; do
	printf '.'
	prov=${provides_pkg_map[$pkg]}
	pkg_map[$pkg]=$(provides_pkg $prov) ||
	    exit_message "Can't get package that provides $prov."
    done
    for prov in "${addl_provide_removes[@]}"; do
	printf '.'
	local pkg;
	pkg=$(provides_pkg $prov) || continue
	addl_pkg_removes+=("$pkg")
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

    if (( ${#addl_pkg_removes[@]} )); then
	printf '%s\n' '' "In addition to the above the following system packages will be removed:" \
	    "${addl_pkg_removes[@]}"
    fi

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

    printf '%s\n' '' "Found the following modules to re-enable at completion:" \
	"${enabled_modules[@]}" ''

    if (( ${#managed_repos[@]} )); then
	printf '%s\n' '' "In addition, since this system uses subscription-manger the following managed repos will be disabled:" \
	    "${managed_repos[@]}"
    fi
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
    dnf -y shell --nogpg --disablerepo=\* --noautoremove \
	--setopt=protected_packages= --setopt=keepcache=True \
	"${repo_urls[@]/#/--repofrompath=}" <<EOF
	remove ${installed_pkg_map[@]} ${addl_pkg_removes[@]}
	install ${!installed_pkg_map[@]}
	run
	exit
EOF

    # We need to check to make sure that all of the original system packages
    # have been removed and all of the new ones have been added. If a package
    # was supposed to be removed and one with the same name added back then
    # we're kind of screwed for this check, as we can't be certain, but all the
    # packages we're adding start with "rocky-*" so this really shouldn't happen
    # and we can safely not check for it.  The worst that will happen is a rocky
    # linux package will be removed and then installed again.
    local -a check_removed check_installed
    readarray -t check_removed < <(
	rpm -qa --qf '%{NAME}\n' "${installed_pkg_map[@]}" \
	    "${addl_pkg_removes[@]}" | sort -u
    )

    if (( ${#check_removed[@]} )); then
	printf '%s\n' '' "${blue}Packages found on system that should still be removed.  Forcibly removing them with rpm:$nocolor"
	# Removed packages still found on the system.  Forcibly remove them.
	for pkg in "${check_removed[@]}"; do
	    printf '%s\n' "$pkg"
	    rpm -e --allmatches --nodeps "${check_removed[@]}" ||
	    rpm -e --allmatches --nodeps --noscripts --notriggers "$pkg"
	done
    fi

    # Check to make sure we installed everything we were supposed to.
    readarray -t check_installed < <(
	{
	    printf '%s\n' "${!installed_pkg_map[@]}" | sort -u
	    rpm -qa --qf '%{NAME}\n' "${!installed_pkg_map[@]}" | sort -u
	} | sort | uniq -u
    )
    if (( ${#check_installed[@]} )); then
	printf '%s\n' '' "${blue}Some required packages were not installed by dnf.  Attempting to force with rpm:$nocolor"

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
    printf '%s\n' '' "${blue}Removing dnf cache$nocolor"
    rm -rf /var/cache/{yum,dnf}
    printf '%s\n' "${blue}Ensuring repos are enabled before the package swap$nocolor"
    dnf -y config-manager --set-enabled "${!repo_map[@]}" || {
      printf '%s\n' 'Repo name missing?'
      exit 25
    }

    if (( ${#managed_repos[@]} )); then
	# Filter the managed repos for ones still in the system.
	readarray -t managed_repos < <(
	    dnf -q repolist "${managed_repos[@]}" | awk '$1!="repo" {print $1}'
	)

	if (( ${#managed_repos[@]} )); then
	    printf '%s\n' '' "${blue}Disabling subscription managed repos$nocolor."
	    dnf -y config-manager --disable "${managed_repos[@]}"
	fi
    fi

    if (( ${#enabled_modules[@]} )); then
	printf '%s\n' "${blue}Enabling modules$nocolor" ''
	# We may very well need to do a reset/install here, but it takes a
	# decent amount of time, so we're better off just doing an enable unless
	# we end up with an explicit test case where reset/install is needed.
#    dnf -y module reset "${enabled_modules[@]}"
#    dnf -y module install "${enabled_modules[@]}"
	dnf -y module enable "${enabled_modules[@]}" ||
    	    exit_message "Can't enable modules ${enabled_modules[@]}"
    fi
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

#!/usr/bin/env bash
# label <label@rockylinux.org>
# Supports only CentOS 8.3

## Rocky is RC status. Using this script means you accept all risks of system instability.

# Path to logfile
logfile=/var/log/centos2rocky.log

# Send all output to the logfile as well as stdout.
truncate -s0 "$logfile"
exec > >(tee -a "$logfile") 2> >(tee -a "$logfile" >&2)

errcolor=$(tput setaf 1)
nocolor=$(tput op)
blue=$(tput setaf 4)

set -e
unset CDPATH

if [[ "$(id -u)" -ne 0 ]]; then
  printf '%s\n' "$errcolor" "You must run this script as root.$nocolor" \
      "${errcolor}Either use sudo or 'su -c ${0}'$nocolor"
fi

if ! type curl >/dev/null 2>&1; then
  printf "${blue}Curl is not installed! Installing it...$nocolor"
  dnf -y install curl libcurl
fi

export LANG=en_US.UTF-8

SUPPORTED_RELEASE="8.3"
SUPPORTED_MAJOR="8"
current_url="https://dl.rockylinux.org/pub/rocky/${SUPPORTED_RELEASE}/BaseOS/x86_64/os/Packages"
# These are packages that can be swapped safely over and will have more added over time.
packages_to_swap=(
  centos-backgrounds \
  centos-indexhtml \
  centos-linux-repos \
  centos-logos \
  centos-gpg-keys \
  centos-linux-release)

packages_that_exist=($(rpm -q --queryformat="%{NAME}\n" "${packages_to_swap[@]}" | grep -v "not installed"))
release_to_install=($(curl -L -s ${current_url} | awk -F '"' '/rocky-repos|rocky-gpg-keys|rocky-release/ {print $2}'))

# Release packages that are part of SIG's should be listed below when they are available.
#sigs_to_swap=()

# Defaults
list_enabled=("$(dnf repolist enabled | awk '!/repo/ {print $1}')")
enabled_modules=("$(dnf module list --enabled | grep rhel | awk '{print $1}')")
convert_info_dir=/root/convert
reinstall_all_rpms=false
verify_all_rpms=false

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

## The actual work
bin_hash() {
  hash "$1" >/dev/null 2>&1
}

bin_check() {
  if ! bin_hash "$1"; then
    exit_message "'${1}' command not found. Please ensure you are running bash or that your PATH is set correctly."
    logmessage
  fi
}

generate_rpm_info() {
  mkdir /root/convert
  printf '%s\n' "${blue}Creating a list of RPMs installed: $1$nocolor"
  rpm -qa --qf "%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}\n" | sort > "${convert_info_dir}/$(hostname)-rpm-list-$1.log"
  printf '%s\n' "${blue}Verifying RPMs installed against RPM database: $1$nocolor" ''
  rpm -Va | sort -k3 > "${convert_info_dir}/$(hostname)-rpm-list-verified-$1.log"
}

package_swaps() {
  mkdir /root/release
  pushd /root/release

  for x in "${release_to_install[@]}"; do
    curl -s "${current_url}/${x}" > "$x" || {
      printf '%s\n' "${errcolor}failed to download ${x}$nocolor" '' &&
      logmessage
      exit 20
    }
  done

  # Remove packages we need to swap
  rpm -e --nodeps "${packages_that_exist[@]}"

  # Install our release
  rpm -ihv "${release_to_install[@]}"

  # Distrosync if the above succeeded
  if [[ $? -eq 0 ]]; then
    printf '%s\n' "${blue}Removing dnf cache$nocolor"
    rm -rf /var/cache/{yum,dnf}
    printf '%s\n' "${blue}Ensuring repos are enabled before the package swap$nocolor"
    dnf config-manager --set-enabled ${list_enabled[@]} || {
      printf '%s\n' 'Repo name missing?'
      exit 25
    }
    dnf distro-sync -y
  else
    exit_message "We failed to install the release package."
    logmessage
  fi

  popd
}

sig_swaps() {
  exit_message "Not Available"
}

module_check() {
  printf '%s\n' "${blue}Finding our modules that are enabled$nocolor"
  for module in "${enabled_modules[@]}"; do
    case ${module} in
      container-tools|go-toolset|jmc|llvm-toolset|rust-toolset|virt)
        ;;
      *)
        unknown_modules+=("${module}")
        ;;
    esac
  done
  if [[ ${#unknown_modules[@]} -gt 0 ]]; then
    printf '%s\n' "${unknown_modules[@]}" \
	"${blue}There are some modules that are unsure of how to handle. This normally shouldn't happen. Do you want to resolve this yourself (Yes) or continue (No)?$nocolor"
    select yn in "Yes" "No"; do
      case $yn in
        Yes)
          printf '%s\n' "${errcolor}Unsure how to switch modules, so we are leaving.$nocolor"
          logmessage
          exit 1
          ;;
        No)
          break
          ;;
      esac
    done
  fi
}

# This is just in case. There is a likelihood this will have to be done.
module_fix() {
  for module in "${enabled_modules[@]}"; do
    dnf module reset -y "${module}"
    case ${module} in
      container-tools|go-toolset|jmc|llvm-toolset|rust-toolset|virt)
        dnf module install "${module}" -y
        ;;
      *)
        printf '%s\n' "${errcolor}Unsure how to deal with the module presented.$nocolor"
        logmessage
        ;;
      esac
    # Final update
    dnf update -y
  done
}


## End actual work

while getopts "hrVR" option; do
  case "$option" in
    h)
      usage
      ;;
    r)
      reinstall_all_rpms=true
      ;;
    V)
      verify_all_rpms=true
      ;;
    R)
      reinstall_all_rpms=true
      ;;
    *)
      printf '%s\n' "${errcolor}Invalid switch.$nocolor"
      usage
      ;;
  esac
done

printf '%s\n' "${blue}Ensuring rpm and yum are here.$nocolor"
for pkg in rpm yum curl; do
  bin_check "${pkg}"
done

printf '%s\n' "${blue}Ensuring your version of CentOS is supported$nocolor"
if ! old_release=$(rpm -q --whatprovides /etc/redhat-release); then
  exit_message "You are not running a supported distribution."
  logmessage
fi

if [ "$(echo "${old_release}" | wc -l)" -ne 1 ]; then
  exit_message "You seem to have package issues. More than one package provides redhat-release."
  logmessage
fi

if ! grep ${SUPPORTED_RELEASE} -q /etc/redhat-release; then
  exit_message "${SUPPORTED_RELEASE} is only supported for conversion at this time. Stream is not supported."
  logmessage
fi

if "${verify_all_rpms}"; then
  generate_rpm_info begin
fi

case "${old_release}" in
  centos-linux-release*);;
  rocky-release*)
    exit_message "You are already running Rocky."
    logmessage
    ;;
  *)
    exit_message "You are running an unsupported distribution. Good bye."
    logmessage
esac

# Check our modules before a swap
module_check

# Actually do the swap and distro-sync
package_swaps

# Fix up modules
module_fix

# Warning, this is potentially dangerous.
if "${reinstall_all_rpms}"; then
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

if "${verify_all_rpms}"; then
  generate_rpm_info finish
  printf '%s\n' "${blue}You may review the following files:$nocolor"
  find /root/convert -type f -name "$(hostname)-rpms-*.log"
fi


printf '\n\n\n'
cat /etc/issue | awk 'NR<=15'
printf '%s\n' "$blue" "Done, please reboot your system.$nocolor"
logmessage

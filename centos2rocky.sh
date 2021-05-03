#!/bin/bash
# label <label@rockylinux.org>
# Supports only CentOS 8.3

## Rocky is RC status. Using this script means you accept all risks of system instability.

set -e
unset CDPATH

if [ "$(id -u)" -ne 0 ]; then
  echo "You must run this script as root."
  echo "Either use sudo or 'su -c ${0}'"
fi

export LANG=en_US.UTF-8

# Add logfile for debugging later down the line
logfile=/var/log/centos2rocky.log

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
  echo "Usage: ${0##*/} [OPTIONS]"
  echo
  echo "Options:"
  echo "-h displays this help"
  echo "-r Converts to rocky"
  echo "-V Verifies switch"
  echo "-R Reinstall all packages"
  echo "   !! USE WITH CAUTION !!"
  exit 1
} >&2

exit_message() {
  echo "$1"
  log final_message
  exit 1
} >&2

final_message() {
  echo "An error occurred while we were attempting to convert your system to Rocky Linux. Your system may be unstable. Script will now exit to prevent possible damage."
}

## The actual work
bin_hash() {
  hash "$1" >/dev/null 2>&1
}

bin_check() {
  if ! bin_hash "$1"; then
    log exit_message "'${1}' command not found. Please ensure you are running bash or that your PATH is set correctly."
  fi
}

generate_rpm_info() {
  mkdir /root/convert
  echo "Creating a list of RPMs installed: $1"
  rpm -qa --qf "%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}\n" | sort > "${convert_info_dir}/$(hostname)-rpm-list-$1.log"
  echo "Verifying RPMs installed against RPM database: $1"
  rpm -Va | sort -k3 > "${convert_info_dir}/$(hostname)-rpm-list-verified-$1.log"
}

package_swaps() {
  mkdir /root/release
  pushd /root/release

  for x in "${release_to_install[@]}"; do
    wget -q "${current_url}/${x}" || { echo "failed to download ${x}" ; exit 20; }
  done

  # Remove packages we need to swap
  rpm -e --nodeps "${packages_that_exist[@]}"

  # Install our release
  rpm -ihv "${release_to_install[@]}"

  # Distrosync if the above succeeded
  if [ $? -eq 0 ]; then
    echo "Removing dnf cache"
    rm -rf /var/cache/{yum,dnf}
    echo "Ensuring repos are enabled before the package swap"
    dnf config-manager --set-enabled ${list_enabled[@]} || { echo "Repo name missing?" ; exit 25; }
    dnf distro-sync -y
  else
    log exit_message "We failed to install the release package."
  fi
  popd
}

sig_swaps() {
 log exit_message "Not Available"
}

module_check() {
  echo "Finding our modules that are enabled" &2>1 | tee -a $logfile
  for module in "${enabled_modules[@]}"; do
    case ${module} in
      container-tools|go-toolset|jmc|llvm-toolset|rust-toolset|virt)
        ;;
      *)
        unknown_modules+=("${module}")
        ;;
    esac
  done
  if [ ${#unknown_modules[@]} -gt 0 ]; then
    for x in "${unknown_modules[@]}"; do
      echo "${x}" &2>1 | tee -a $logfile
    done
    echo "There are some modules that are unsure of how to handle. This normally shouldn't happen. Do you want to resolve this yourself (Yes) or continue (No)?" &2>1 | tee -a $logfile
    select yn in "Yes" "No"; do
      case $yn in
        Yes)
          echo "Ensure how to switch modules, so we are leaving." &2>1 | tee -a $logfile
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
    dnf module reset -y "${module}" &2>1 | tee -a $logfile
    case ${module} in
      container-tools|go-toolset|jmc|llvm-toolset|rust-toolset|virt)
        dnf module install "${module}" -y &2>1 | tee -a $logfile
        ;;
      *)
        echo "Unsure how to deal with the module presented." &2>1 | tee -a $logfile
        ;;
      esac
    # Final update
    dnf update -y &2>1 | tee -a $logfile
  done
}

## End actual work

# Pipe output of script to $logfile
log(){
printf "\e[1;34m$(date): \e[0m$@\n" >> "$logfile"
    "$@" 2>> "$logfile"
}




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
      echo "Invalid switch." &2>1 | tee -a $logfile
      usage
      ;;
  esac
done

echo "Ensuring rpm, yum, and wget are here." &2>1 | tee -a $logfile
for pkg in rpm yum wget curl; do
  log bin_check "${pkg}"
done

echo "Ensuring your version of CentOS is supported" &2>1 | tee -a $logfile
if ! old_release=$(rpm -q --whatprovides /etc/redhat-release); then
  log exit_message "You are not running a supported distribution."
fi

if [ "$(echo "${old_release}" | wc -l)" -ne 1 ]; then
  log exit_message "You seem to have package issues. More than one package provides redhat-release."
fi

if ! grep ${SUPPORTED_RELEASE} -q /etc/redhat-release; then
  log exit_message "${SUPPORTED_RELEASE} is only supported for conversion at this time. Stream is not supported."
fi

if "${verify_all_rpms}"; then
  log generate_rpm_info begin
fi

case "${old_release}" in
  centos-linux-release*);;
  rocky-release*)
    log exit_message "You are already running Rocky."
    ;;
  *)
    log exit_message "You are running an unsupported distribution. Good bye."
esac

# Check our modules before a swap
module_check

# Actually do the swap and distro-sync
log package_swaps

# Fix up modules
module_fix

# Warning, this is potentially dangerous.
if "${reinstall_all_rpms}"; then
  echo "!! THIS MAY CAUSE ISSUES WITH YOUR SYSTEM !!" &2>1 | tee -a $logfile
  rpm_list=("$(rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE} %{VENDOR}\n" | grep CentOS | awk '{print $1}')")
  if [[ -n "${rpm_list[*]}" ]]; then
    echo "Reinstalling rpms: ${rpm_list[*]}" &2>1 | tee -a $logfile
    dnf reinstall "${rpm_list[@]}" -y &2>1 | tee -a $logfile
  fi
  non_rocky_rpm=("$(rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}|%{VENDOR}|%{PACKAGER}\n" |grep -iv Rocky)")
  if [[ -n ${non_rocky_rpm[*]} ]]; then
    echo "Non-Rocky packages are installed. This is generally not an issue. If you see centos packages, you may need to address them and file a bug report at https://bugs.rockylinux.org" &2>1 | tee -a $logfile
    printf '\t%s\n' "${non_rocky_rpm[@]}" &2>1 | tee -a $logfile
  fi
fi

if "${verify_all_rpms}"; then
  log generate_rpm_info finish
  echo "You may review the following files:" &2>1 | tee -a $logfile
  find /root/convert -type f -name "$(hostname)-rpms-*.log" &2>1| tee -a $logfile
fi

echo "Done, please reboot your system." &2>1 | tee -a $logfile

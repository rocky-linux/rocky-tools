#!/bin/bash
#set -x

# Give it a git server as the first argument
# Give it a file path for the list as the second argument

GITSERVER=${1}
LIST=${2}
TMPDIR=/var/tmp
for x in $(cat ${LIST}); do
  pkgname="${x}"
  echo "!!! ${pkgname}"
  git clone --mirror "https://git.centos.org/modules/${pkgname}.git" "${TMPDIR}/${pkgname}.git"
  git_ret_val=$?
  if [ $git_ret_val -ne 0 ]; then echo "${pkgname}" >> /tmp/failures ; fi
  pushd "${TMPDIR}/${pkgname}.git" || { echo "error"; exit 1; }
  if git branch | grep -Eq '^  (c8|c9)'; then
    git remote set-url origin "ssh://git@${GITSERVER}/modules/${pkgname}.git"
    git push --mirror
    ret_val=$?
    if [ $ret_val -ne 0 ]; then echo "${pkgname}" >> /tmp/failures ; fi
  fi
  popd || { echo "error"; exit 1; }
  if [[ -d "${TMPDIR}/${pkgname}.git" ]]; then
    rm -rf "${TMPDIR}/${pkgname}.git"
  fi
  echo "sleeping..."
  sleep 10
  unset pkgname
done

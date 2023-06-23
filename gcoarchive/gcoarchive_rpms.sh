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
  git clone --mirror "https://git.centos.org/rpms/${pkgname}.git" "${TMPDIR}/${pkgname}.git"
  git_ret_val=$?
  if [ $git_ret_val -ne 0 ]; then echo "${pkgname}" >> /tmp/failures ; fi
  pushd "${TMPDIR}/${pkgname}.git" || { echo "error"; exit 1; }
  if git branch | grep -Eq '^  (c8|c9)'; then
    for tag in $(git tag | grep -E 'imports/c(4|5|6|7)'); do git tag -d "${tag}" ; done
    for tag in $(git tag | grep -E 'imports/c(8|9|8s|9s)-sig'); do git tag -d "${tag}" ; done
    for branch in $(git branch | grep -E 'c(4|5|6|7)'); do git branch -D "${branch}" ; done
    for branch in $(git branch | grep -E 'c(8|9|8s|9s)-sig'); do git branch -D "${branch}" ; done
    git remote set-url origin "ssh://git@${GITSERVER}/rpms/${pkgname}.git"
    git push --mirror
    ret_val=$?
    if [ $ret_val -ne 0 ]; then echo "${pkgname}" >> /tmp/failures ; fi
    pushd /var/www/html/sources || { echo "error"; exit 1; }
    echo "${pkgname}: Pulling sources"
    wget -q --accept-regex="/sources/${pkgname}/(c8|c9)" -r "https://git.centos.org/sources/${pkgname}/" -np --cut-dirs 2 -R "*.html*"
    mv git.centos.org "${pkgname}"
    popd || { echo "error"; exit 1; }
  fi
  unset branch
  popd || { echo "error"; exit 1; }
  if [[ -d "${TMPDIR}/${pkgname}.git" ]]; then
    rm -rf "${TMPDIR}/${pkgname}.git"
  fi
  echo "sleeping..."
  sleep 10
  unset pkgname
done

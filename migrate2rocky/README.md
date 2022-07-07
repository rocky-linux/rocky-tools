migrate2rocky -- Conversion Script
===========

Running this script will convert an existing CentOS 8 system to Rocky Linux 8.

### Usage

```bash
./migrate2rocky.sh -h
├── -d   # --> Do not update before conversion
├── -h   # --> Display this help
├── -o   # --> Work in offline mode
├── -r   # --> Convert to Rocky
└── -V   # --> Verify switch

[!! USE WITH CAUTION !!]
```

### Disk Space Requirements

Please note the following disk space requirements.  These requirements may vary
from one system to another.  Offline mode may require further space for rpm
packages and repository metadata.  Failure to have adequate disk space available
may result in migrate2rocky leaving the system in an unstable state:

```
/usr   250M
/var   1.5G
/boot  50M
```

### Recommended Practice

When running this script, especially via a remote session, it is highly
recommended to enter a screen or tmux session before running.  If a standard
ssh or terminal session, such as the Cockpit Terminal window, is disrupted, the
script will die and leave the system in a potential unrecoverable state.  For
more on tmux sessions, please see:  https://github.com/tmux/tmux/wiki

### Known Issues

#### Running the script in Cockpit's Terminal Screen will be interrupted

Do not run this script through the Terminal screen built into Cockpit.  As the
script runs the upgrades, Cockpit will be restarted and Terminal connection will
disconnect, thus stopping the script and leaving the system in an unrecoverable
state.  It may be possible to launch a screen or tmux session from the Cockpit
Terminal, but USE AT YOUR OWN RISK.

#### EL8.0 Migrations

If you are attempting to migrate a system that has not been updated since 8.0
then you must run `dnf update` before attempting the migration.

If you are migrating from CentOS 8.0 then you must manually fix the baseurls of
the CentOS repositories before running `dnf update`:
```
sed -i -r \
    -e 's!^mirrorlist=!#mirrorlist=!' \
    -e 's!^#?baseurl=http://(mirror|vault).centos.org/\$contentdir/\$releasever/!baseurl=https://dl.rockylinux.org/vault/centos/8.5.2111/!i' \
    /etc/yum.repos.d/CentOS-*.repo
```

#### Migration in offline mode

Offline mode has received minimal testing and only for the CentOS 8.5 -> Rocky 8.5/8.6
migration from a minimal (straight from installation or fully updated) system using
CentOS 8.5 DVD and Rocky 8.5/8.6 DVD ISOs as offline repositories, mounted respectively
under /mnt/centos (hardcoded into and forced by the script only for the CentOS case - for other
EL8 distros you will need to manually define local repo paths under /etc/yum.repos.d/ before
launching the script) and /mnt/rocky (hardcoded into and always forced by the script - please
note that you will also need the Rocky GPG key in /mnt/RPM-GPG-KEY-rockyofficial) .

Please make sure that you do not inadvertently swap the current-EL8/Rocky local repositories
when mounting ISOs.

Package downgrades may happen, depending on the update status of the running EL8 distro and
on the content of the local repositories (e.g. using a Rocky 8.5 DVD ISO for offline
migrating a CentOS 8.5 with all latest-before-EOL updates applied).
Note that if you are disabling pre-migration updates then you will need only the base repositories'
metadata (repodata subdir) for the currently running EL8 (can be copied from original
installation ISO).

If you installed packages from further repos of the running EL8 distro (devel, extras, ha, powertools)
then you will need those same repos enabled and their Rocky equivalents locally available 
(under /mnt/rocky/{Extras,HA,PowerTools,Devel}) before starting the migration,
otherwise make sure that those additional repos are disabled.

#### Migration with pre-updating disabled

Disabling system updates before migration has been introduced and tested only as a convenience
option for the offline migration mode but it should be carefully tested on a non-production
system before attempting it.

#### Custom replacements of default repositories

This script expects the **original repository configuration being present, as
well as enabled** (i.e. for CentOS the `baseos` repo configuration in the
`/etc/yum.repos.d/CentOS-Linux-BaseOS.repo` file has to be present and enabled).
Offline mode will require at least the repository metadata (repodata subdir) for
the `baseos` and `appstream` repos to be available (for CentOS their path is
hardcoded as /mnt/centos/{BaseOS,AppStream} and can be copied or mounted from a
CentOS ISO).
Also make sure that there are **no other repositories** which could interfere
with the original configuration.

Any distribution that has had its core repositories altered, removed, duplicated
or overridden may cause migrate2rocky to break or corrupt the system when run.
Any attempt to migrate such systems, even after reversing the changes made by
such software, is not supported in any way. In all cases you should backup your
system before using migrate2rocky and USE AT YOUR OWN RISK.

This especially happens on systems configured with a centralized package
management like Katello (RedHat Satellite 6) or Uyuni (RedHat Satellite 5, SUSE
Manager).

#### RHEL migrations show error messages during conversion

```
  Installing       : rocky-release-8.3-13.el8.noarch                        2/5Error unpacking rpm package rocky-release-8.3-13.el8.noarch
...
error: unpacking of archive failed on file /usr/share/redhat-release: cpio: File from package already exists as a directory in system
error: rocky-release-8.3-13.el8.noarch: install failed
...
Error: Transaction failed
```

This results from conflicts in the directory structure of RHEL with that of
RockyLinux.  migrate2rocky will detect the issue and go on to remove the
conflicting directory and install rocky-release with the rpm command.

#### No matches found for the following enable plugin patterns: config-manager

The above error message is a display bug in dnf.  It does not affect the actual
dnf command or the migration.  You may safely ignore this message.
(RHBZ#1980712)

#### Grub still shows kernel entries from previous installation

This is normal.  The running kernel cannot be safely removed when migrate2rocky
is run.  The RockyLinux kernel should come up as the default highlighted kernel
on reboot but the other ones will remain until they are removed or replaced by
newer kernels.  If you want you can manually remove the old kernels after reboot
with dnf or rpm.

#### Symbolic links to Java programs in `/etc/alternatives` are gone

After migrating a system with an OpenJDK package installed you might encounter
that java does not work any more. There is a bug in the OpenJDK packages that
leads to losing the symbolic links in `/etc/alternatives` during the migration.
A bug report against the upstream packages has been filed
[here](https://bugzilla.redhat.com/show_bug.cgi?id=1976053).  As a workaround
you can use the following script to recreate the package default alternatives:
```
rpm -qa --scripts java-{1.8.0,11}-openjdk-{headless,devel} | sed -n '/postinstall/, /exit/{ /postinstall/! { /exit/ ! p} }' | sh
```

#### IPA fails to start after migration

This issue is caused by a version mismatch due to the way that modules work that
trick ipa into thinking that the package was downgraded even if it was not.  To
fix this issue run the following command after migration:
```
ipa-server-upgrade --skip-version-check
```
> Note: Since ipa-server-upgrade is a java program you will likely have to run
> the command to mitigate the "Symbolic links to Java programs..." issue above
> before running this command.

#### CentOS SIG repositories disappear after migrating to RockyLinux.

This is because the centos-release-* packages that contain the .repo files for
the individual repositories depend on centos-release.  Storage sig and related
release packages should be available soon from RockyLinux.  In the meantime you
can use a command like the following to install the .repo files and continue to
use the repository from CentOS (note please substitute the URL to the release
package for the repo that you need):
```
rpm2cpio <(curl http://mirror.centos.org/centos/8/extras/x86_64/os/Packages/centos-release-gluster9-1.0-1.el8.noarch.rpm) | cpio -iD/ \*.repo
```

### Latest Version

The latest version of this script can be found [here](https://github.com/rocky-linux/rocky-tools/).

### Debugging

The `migrate2rocky` script pipes everything shown on `stdout` and `stderr` to
`/var/log/migrate2rocky.log`.

If you run in to issues executing this script, please submit an issue
[here](https://github.com/rocky-linux/rocky-tools/issues).

Make sure to include the output log, and remove any sensitive information. (if
any)

Feel free to create a pull request if you think you've got the fix.

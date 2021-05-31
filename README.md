Rocky Tools
===========

Various scripts and tools that we find useful, whether we use them or they are
made for public consumption. For example, conversion scripts or otherwise.

## [migrate2rocky] -- Conversion Script

Running this script will convert an existing CentOS 8 system to Rocky Linux 8.

### Usage

```bash
./migrate2rocky.sh -h
├── -h   # --> Display this help
├── -r   # --> Convert to Rocky
└── -V   # --> Verify switch

[!! USE WITH CAUTION !!]
```

### Known Issues

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

#### Grub still shows kernel entries from previous installation

This is normal.  The running kernel cannot be safely removed when migrate2rocky
is run.  The RockyLinux kernel should come up as the default highlighed kernel
on reboot but the other ones will remain until they are removed or replaced by
newer kernels.  If you want you can manually remove the old kernels after reboot
with dnf or rpm.

### Debugging

The `migrate2rocky` script pipes everything shown on `stdout` and `stderr` to
`/var/log/migrate2rocky.log`.

If you run in to issues executing this script, please submit an issue
[here](https://github.com/rocky-linux/rocky-tools/issues).

Make sure to include the output log, and remove any sensitive information. (if
any)

Feel free to create a pull request if you think you've got the fix.

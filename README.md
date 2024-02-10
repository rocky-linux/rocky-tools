Rocky Tools
===========

Various scripts and tools that we find useful, whether we use them or they are
made for public consumption.

## [getsrc](./getsrc/) -- Git resource grabber

An automatic lookaside grabber supporting all flavors of: Fedora, Rocky Linux,
CentOS, CentOS Stream.

## [migrate2rocky](./migrate2rocky/) -- Conversion Script

Script(s) that that will convert existing Enterprise Linux systems to Rocky Linux
on a single major version. `migrate2rocky` will convert EL 8 systems to Rocky Linux 8.
`migrate2rocky9` will convert EL 9 systems to Rocky Linux 9.

## [mirrorsync](./mirror/) -- Mirror Script and Configurations

Example script and configuration notes for keeping a public or private mirror in sync.

## [gcoarchive](./gcoarchive/) -- Mirrors git.centos.org and sources

Scripts that help clone git.centos.org repos based on a list provided and its
accompanying dist-git sources. This assumes a /var/www/html/sources format for
sources.

Only clones 8 and 9. Does not clone sig content.

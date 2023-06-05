Rocky Mirror Scripts
====================

Scripts and snippets for mirror admins.

Please read https://docs.rockylinux.org/guides/mirror_management/add_mirror_manager/ for further information on setting up a Rocky mirror.

## example.crontab

A few suggestions for setting up a crontab for syncing.

## mirrorsync.sh

Example script for keeping a public or private mirror in sync.

You may modify this to exclude specific repositories or directories from your mirror (for example, you can exclude "source" by changing the `--exclude` to `--exclude={'*.~tmp~', 'source'}`).

# getsrc

An automatic lookaside grabber supporting all flavors of: Fedora, Rocky Linux, CentOS, CentOS Stream.  Easy to extend to other lookaside-based distros as well.

## Usage

- Download getsrc.sh , save to somewhere in your $PATH
- Run getsrc.sh inside a checked-out repo.  It will analyze the lookaside list file (".firefox.metadata", for example, or just "sources") and download the source tarballs for you
- Now you can do a local build or edit of the package

<br />

## Audience

I hope this will help anyone who needs to work with packages from different sources/repos in the RPM world.

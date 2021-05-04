Rocky Tools
===========

Various scripts and tools that we find useful, whether we use them or they are
made for public consumption. For example, conversion scripts or otherwise.

## [Centos2Rocky] -- Conversion Script

Running this script will convert an existing CentOS 8 system to Rocky Linux 8.

### Usage

```bash
./centos2rocky.sh -h
├── -h   # --> Displays this help
├── -r   # --> Converts to Rocky
├── -V   # --> Verifies switch
└── -R   # --> Reinstalls all packages 

[!! USE WITH CAUTION !!]
```

### Debugging

The `centos2rocky` script pipes everything shown on `stdout` to `/var/log/centos2rocky.log`. 

If you run in to issues executing this script, please submit an issue [here](https://github.com/rocky-linux/rocky-tools/issues).  

Make sure to [include the output log](https://pastebin.com/), and remove any sensitive information. (if any)

Feel free to create a pull request if you think you've got the fix.

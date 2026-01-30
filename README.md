# Diffie

![Logo](diffie.png)

Diffie is a simple (mostly vibecoded) forensics tool. The purpose of it is to highlight differences between files on a filesystem.

It consists of two binaries:
* [dscan](./src/bin/dscan.rs)
* [dshow](./src/bin/dshow.rs)

and operates on the notion of "snapshots". A snapshot contains metadata together with a unique checksum for every file - it currently uses "XXH3" which is a non-cryptographically secure hash but is very fast to compute (see [https://xxhash.com]).

Using `dscan` you can crate a snapshot of the filesystem below some root directory (or / by default).

Then `dshow` is a TUI file explorer using which you navigate the filesystem and search for differences (or press l to see a log of what is going on currently and all changed files).
The tool `dshow` can be invoked between old and new snapshot but it supports also a `live mode`. When you call it with:
```
dshow oldsnapshot --live /etc
```
it means `oldsnapshot` is some known good state and `/etc` should be monitored. This way all changes between that state and current `/etc` are shown.
You can use the tool also without an old snapshot like:
```
dshow --live /home/me
```

in that case you get what was changed inside your home directory since the tool was started. You always have the option to press s and export the current state as a new snapshot.
That you can the compare later.

To detect changes as fast as possible in `live mode` `inotify` is used on Linux (however that is a bit cumbersome as it doesn't work recursively and we need to preserve fds). 
On Mac/BSD `FSevents` are used for the same purpose (but since that works recursively we just add a watch on the root - your monitored directory and get changes almost immediately).
In any case we still do periodic polling (and recalculating all the data).

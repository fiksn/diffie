# Diffie

![Hellmann's](diffie.png)

## Intro

Diffie is a simple (mostly vibecoded) forensics tool. The purpose is to highlight which files are different and ensure filesystem integrity.
Think of [Tripwire](https://github.com/Tripwire/tripwire-open-source) or [AIDE](https://aide.github.io) just more modern and used mostly interactively.

It consists of multiple binaries:
* [dscan](./src/bin/dscan.rs)
* [dshow](./src/bin/dshow.rs)
* [dwatch](./src/bin/dwatch.rs)

and operates on the notion of `snapshots`. A snapshot contains metadata together with a unique checksum for every file - it currently uses "XXH3" which is a non-cryptographic hash function which on the other hand is very fast to compute ([read more](https://xxhash.com)). Note that no file content is stored but the snapshot can still get very big. Imagine the filesystem being a big Merkle tree.

## Usage

Using `dscan` you can crate a snapshot of the filesystem below some directory (or / by default).

Then `dshow` is a TUI file explorer using which you navigate the filesystem and search for differences (or press `L` to see a log of what is going on currently and all changed files).
The tool `dshow` can be invoked between old and new snapshot but it supports also a `live mode`. When you call it with:
```
dshow golden.snap --live /etc
```
it means `golden.snap` is some known good state and `/etc` should be monitored. This way all changes between that state and current `/etc` are shown.
You can use the tool also without an old snapshot like:
```
dshow --live /home/me
```

in that case you get what was changed inside your home directory since the tool was started. You always have the option to press `S` and export the current state as a new snapshot that you can the compare later.

Tool `dwatch` is basically `dshow` with `live mode` but without the TUI. Additionally you can pass what to ignore. The idea is that you can use it to script some alerting and create some sort of simple IDS from it.

## Events

To detect changes as fast as possible `inotify` is used on Linux (however that is a bit cumbersome as it doesn't work recursively and we need to preserve fds).
On Mac/BSD `FSevents` are used for the same purpose (but since that works recursively we just add a watch on the root of your monitored directory hierarchy and get changes almost immediately).
In any case we still do periodic polling (and recalculate all the data).

## Misc

Pull requests to make this less shitty are welcome.

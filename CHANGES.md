## Version 0.70

 * UDP support
 * source address binding support
 * use a real grammar for the configuration file and get rid of the hand-made
   parser

## Version 0.63

 * added a `-f` flag to run in the foreground
 * quit cleanly when `SIGINT` is received
 * increased data buffer size for better performance
 * fixed random uninitialised data accesses
 * fixed a memory leak in connection reallocation
 * fixed a file descriptor leak in configuration reload
 * fixed configuration file parsing (many bugs including a buffer overflow)
 * fixed configuration error reporting (line numbers were wrong)
 * log accepted connections in addition to denied ones
 * log DNS errors
 * code quality refactoring: got rid of a lot of old code, used C
   library functions instead of custom ones, enforced `const` correctness

## Version 0.62

fixed a potential buffer overrun; prior versions failed to reallocate one of
the arrays correctly when reallocating memory to accommodate more connections.
Thanks to Sam Hocevar.

## Version 0.61

fixed a bug in 0.6 which completely broke rinetd under Linux. Oops.

## Version 0.6

ported to Win32. Various compatibility fixes were made and some minor
oversights without functional consequences were corrected.

## Version 0.52

documentation added regarding the ability to bind to all IP addresses, if
desired, using the special address 0.0.0.0.

## Version 0.51

fixed failure to check for an open log file before writing log entries.

## Version 0.5

added logging in both tab-delimited and web-server-style formats. No longer
exits if an individual configuration file line generates an error. Added allow
and deny rules. Added -c command line option to specify a configuration file.

## Version 0.4

added support for kill -1 (SIGHUP) and specification of service names instead
of port numbers. Removed calls to realloc(), replacing them with code that
should fail gracefully without crashing the program or breaking existing
connections when another application is hogging memory.

## Version 0.3

fixed additional bugs relating to the code previously used only by non-Linux
OSes. This should fix problems such as connections not going away when they
should or connections being mysteriously closed. Most of that code is now
used by Linux also, so it is likely that rinetd is much closer to bug-free on
non-Linux platforms. Of course, I don't actually have any to play with it on.

## Version 0.2

fixed bug when several reads are necessary on one end or the other before a
write flushes them. Fixed bug which threw away data not yet sent to the other
side on close, when running under Linux. Fixed associated bugs that probably
affected other operating systems as well. Fixed bug causing long, perhaps
indefinite pauses when a possible connection to a server socket went away
before the accept() call, resulting in a blocking call.

## Version 0.1

original version.


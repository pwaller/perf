# Linux Perf Bindings for Go

If you'd like to measure the exact number of CPU cycles and misses of a specific piece of Go code, you've come to the right place!

Unfortunately, it is not possible for a program being profiled by perf to exclude all but a specific bit of code. The linux documentation seems to imply that this can be achieved with `prctl`, but there are mailing list posts indicating that this does not work.

The solution is to profiling a specific section of code is to "self profile", which is that a program should configure and read the linux counters itself. In this case, `prctl(PR_TASK_PERF_EVENTS_DISABLE)` and `prctl(PR_TASK_PERF_EVENTS_ENABLE)` work as expected.

I'm afraid the code is very rough and ready at the moment. If you want to use it, you should figure it out by reading the source and the Linux documentation for the perf counters. Generally, you should only use this if you know what you're doing, otherwise you are likely to get bogus results.

Help is welcomed.

#!/usr/sbin/dtrace -s
/*
 * watchexec.d
 *
 * Example script from Chapter 11 of the book: DTrace: Dynamic Tracing in
 * Oracle Solaris, Mac OS X, and FreeBSD", by Brendan Gregg and Jim Mauro,
 * Prentice Hall, 2011. ISBN-10: 0132091518. http://dtracebook.com.
 * 
 * See the book for the script description and warnings. Many of these are
 * provided as example solutions, and will need changes to work on your OS.
 */

#pragma D option destructive
#pragma D option quiet

inline string REPORT_CMD = "sudo sh /usr/local/bin/reporter.sh";

dtrace:::BEGIN
{
	/*
	 * Ensure this contains all the reporting commands,
	 * otherwise this script will be a feedback loop:
	 */
	ALLOWED[REPORT_CMD] = 1;
	ALLOWED["/bin/sh"] = 1;

	/*
	 * Commands to allow.
	 * Example list (from Solaris) in alphabetical order:
	 */
	ALLOWED["/bin/bash"] = 1;
	ALLOWED["/usr/bin/sudo"] = 1;
	ALLOWED["/bin/cp"] = 1;
	ALLOWED["/usr/bin/tail"] = 1;
	ALLOWED["/usr/bin/basename"] = 1;
	ALLOWED["/bin/cat"] = 1;
	ALLOWED["/bin/chmod"] = 1;
	ALLOWED["/usr/sbin/chown"] = 1;
	ALLOWED["/usr/bin/grep"] = 1;
	ALLOWED["/usr/bin/head"] = 1;
	ALLOWED["/bin/ls"] = 1;
	ALLOWED["/usr/bin/pgrep"] = 1;
	ALLOWED["/usr/bin/pkill"] = 1;
	ALLOWED["/bin/kill"] = 1;
	ALLOWED["/usr/bin/ssh"] = 1;
	ALLOWED["/usr/bin/tput"] = 1;
	ALLOWED["/usr/bin/tr"] = 1;
	ALLOWED["/usr/bin/uname"] = 1;
	ALLOWED["/sbin/nfsd"] = 1;
	ALLOWED["/usr/bin/openssl"] = 1;

	printf("Reporting unknown exec()s to %s...\n", REPORT_CMD);
}

syscall::exec*:entry
/ALLOWED[copyinstr(arg0)] != 1/
{
	/*
	 * Customize arguments for reporting command:
	 */
	self->untrusted_pid = pid;
	system("%s %s %s %s %d %d %d %Y\n", REPORT_CMD, "New Process",execname, copyinstr(arg0),
	    uid, pid, ppid, walltimestamp);
}

syscall::open*:entry
/self->untrusted_pid == pid/
{
        system("%s %s %s %s %d %d %d %Y\n", REPORT_CMD, "File Access",execname, copyinstr(arg0),
            uid, pid, ppid, walltimestamp);
}

syscall::exec*:return
{
	self->untrusted_path = 0;
}

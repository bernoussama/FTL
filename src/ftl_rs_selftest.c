/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Fork stress test for the Rust library (pihole-FTL rust-fork-test <N>)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// The parent keeps the Rust process-local lock busy from a second thread and
// forks N children. Each child runs ftl_rs_after_fork() and then uses the
// library. A lock held at fork time shows up as a child that blocks, which
// the timeout reports, or as a child that fails the checks.

#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "ftl_rs.h"

#define FORK_TEST_TIMEOUT_S 30

// Set by the parent to stop the lock thread
static atomic_bool lock_thread_stop = false;

static void *lock_thread(void *arg)
{
	while(!atomic_load(&lock_thread_stop))
		ftl_rs_selftest_tick();
	return NULL;
}

// Runs in a forked child. Returns true if the library behaves as expected.
static bool child_checks(void)
{
	ftl_rs_after_fork();

	// The child starts from fresh state, so its ticks start again at 1
	uint64_t tick = ftl_rs_selftest_tick();
	if(tick != 1)
		return false;
	for(unsigned int i = 0; i < 100; i++)
		if(ftl_rs_selftest_tick() != ++tick)
			return false;

	// Byte i of a selftest buffer is i % 251 (rust/src/selftest.rs)
	const size_t sizes[] = { 0, 1, 4096, 100000 };
	for(size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
	{
		ftl_rs_buf buf = ftl_rs_selftest_buf(sizes[s]);
		bool ok = buf.len == sizes[s] && (buf.len == 0 || buf.ptr != NULL);
		for(size_t i = 0; ok && i < buf.len; i++)
			ok = buf.ptr[i] == (uint8_t)(i % 251);
		ftl_rs_buf_free(&buf);
		// A freed buffer is reset, and a second free does nothing
		ok = ok && buf.ptr == NULL && buf.len == 0 && buf.cap == 0;
		ftl_rs_buf_free(&buf);
		if(!ok)
			return false;
	}
	return true;
}

int ftl_rs_fork_test(const unsigned int children)
{
	if(children == 0 || children > FTL_RS_FORK_TEST_MAX_CHILDREN)
		return EXIT_FAILURE;

	pthread_t thread;
	if(pthread_create(&thread, NULL, lock_thread, NULL) != 0)
	{
		printf("rust fork test: cannot start the lock thread\n");
		return EXIT_FAILURE;
	}

	pid_t pids[FTL_RS_FORK_TEST_MAX_CHILDREN] = { 0 };
	unsigned int forked = 0;
	for(unsigned int i = 0; i < children; i++)
	{
		const pid_t pid = fork();
		if(pid == 0)
			_exit(child_checks() ? EXIT_SUCCESS : EXIT_FAILURE);
		if(pid < 0)
		{
			printf("rust fork test: fork failed after %u children\n", forked);
			break;
		}
		pids[forked++] = pid;
	}

	// Poll for the children until they are all done or the deadline passes
	struct timespec start = { 0 };
	clock_gettime(CLOCK_MONOTONIC, &start);
	unsigned int pending = forked, passed = 0;
	bool timed_out = false;
	while(pending > 0)
	{
		for(unsigned int i = 0; i < forked; i++)
		{
			int status = 0;
			if(pids[i] != 0 && waitpid(pids[i], &status, WNOHANG) == pids[i])
			{
				pids[i] = 0;
				pending--;
				if(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS)
					passed++;
			}
		}
		if(pending == 0)
			break;
		struct timespec now = { 0 };
		clock_gettime(CLOCK_MONOTONIC, &now);
		if(now.tv_sec - start.tv_sec >= FORK_TEST_TIMEOUT_S)
		{
			timed_out = true;
			break;
		}
		const struct timespec nap = { .tv_nsec = 1000000 };
		nanosleep(&nap, NULL);
	}

	// Kill and reap the children that did not finish in time
	unsigned int killed = 0;
	for(unsigned int i = 0; i < forked; i++)
	{
		if(pids[i] == 0)
			continue;
		kill(pids[i], SIGKILL);
		waitpid(pids[i], NULL, 0);
		killed++;
	}

	atomic_store(&lock_thread_stop, true);
	pthread_join(thread, NULL);

	printf("rust fork test: %u/%u children ok\n", passed, children);
	if(timed_out)
		printf("rust fork test: timed out after %d s, killed %u children\n",
		       FORK_TEST_TIMEOUT_S, killed);
	return passed == children ? EXIT_SUCCESS : EXIT_FAILURE;
}

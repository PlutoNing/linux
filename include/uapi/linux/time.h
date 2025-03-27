/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TIME_H
#define _UAPI_LINUX_TIME_H

#include <linux/types.h>
#include <linux/time_types.h>

#ifndef __KERNEL__
#ifndef _STRUCT_TIMESPEC
#define _STRUCT_TIMESPEC
struct timespec {
	__kernel_old_time_t	tv_sec;		/* seconds */
	long			tv_nsec;	/* nanoseconds */
};
#endif

struct timeval {
	__kernel_old_time_t	tv_sec;		/* seconds */
	__kernel_suseconds_t	tv_usec;	/* microseconds */
};

struct itimerspec {
	struct timespec it_interval;/* timer period */
	struct timespec it_value;	/* timer expiration */
};

struct itimerval {
	struct timeval it_interval;/* timer interval */
	struct timeval it_value;	/* current value */
};
#endif

struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

/*
 * Names of the interval timers, and structure
 * defining a timer setting:
 */
#define	ITIMER_REAL		0
#define	ITIMER_VIRTUAL		1
#define	ITIMER_PROF		2

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 不同的系统时钟的ID（用于POSIX.1b间隔计时器）：
 */
#define CLOCK_REALTIME			0
/* 系统的实时时钟，表示当前的日期和时间。
以 1970年1月1日… 为起点，随 time-of-day 被修改的时候而改变（例如，NTP网络时间协议）
*/
#define CLOCK_MONOTONIC			1
/* 单调递增的时钟，不受系统时间更改的影响，通常用于测量时间间隔。
代表从过去某个固定的时间点开始的绝对的逝去时间，它不受任何系统time-of-day时钟修改的影响，
在没有机器重启的情况下，若你想计算出两个事件发生的间隔时间的话，那么它将是最好的选择。
但是 CLOCK_MONOTONIC 在系统 suspend 时并不会增长。
*/
#define CLOCK_PROCESS_CPUTIME_ID	2
#define CLOCK_THREAD_CPUTIME_ID		3
#define CLOCK_MONOTONIC_RAW		4
/* 与 CLOCK_MONOTONIC 相似，虽然 CLOCK_MONOTONIC 不受 NTP 的影响，
但是随着 NTP 了解本地振荡器和上游服务器之间存在错误时，它的频率确实会发生变化，
而 CLOCK_MONOTONIC_RAW 完全取决于本地振荡器。 */
#define CLOCK_REALTIME_COARSE		5
#define CLOCK_MONOTONIC_COARSE		6
#define CLOCK_BOOTTIME			7
// 系统启动后的时间，包括系统休眠时间
#define CLOCK_REALTIME_ALARM		8
#define CLOCK_BOOTTIME_ALARM		9
/*
 * The driver implementing this got removed. The clock ID is kept as a
 * place holder. Do not reuse!
 */
#define CLOCK_SGI_CYCLE			10
#define CLOCK_TAI			11

#define MAX_CLOCKS			16
#define CLOCKS_MASK			(CLOCK_REALTIME | CLOCK_MONOTONIC)
#define CLOCKS_MONO			CLOCK_MONOTONIC

/*
 * The various flags for setting POSIX.1b interval timers:
 */
#define TIMER_ABSTIME			0x01

#endif /* _UAPI_LINUX_TIME_H */

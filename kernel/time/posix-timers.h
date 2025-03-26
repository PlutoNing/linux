/* SPDX-License-Identifier: GPL-2.0 */
#define TIMER_RETRY 1
/*
clock，实际上就是一种计时工具，可能是硬件，也可能是软件，当然对于POSIX clock而言，
当然是指软件抽象了。clock能够记录一段时间的流逝，这段时间可能是真实的墙上时间，
也可能是虚拟的时间，例如基于某个进程或者线程的CPU执行时间。在linux kernel中，
用struct k_clock来抽象，具体定义如下：
*/
struct k_clock {
	/* 通过clock_getres函数可以获取该clock的时间精度，需要说明的是这个精度是和timer相关的，
	用于将用户设定的timer超时时间规整到clock精度允许的数值上。 */
	int	(*clock_getres)(const clockid_t which_clock,
				struct timespec64 *tp);
	/* clock_get和clock_set函数可以分别获取和设定当前的时间，这个时间值是一个绝对时间值
	（对于时间轴而言，这个绝对时间也是相对的，是相对于该timeline的epoch而言），标记了当前时间点。
	clock计时有可能是不准确的，例如基于系统晶振的clock。一方面本身晶振的精度有限，时间累积长了
	会出现较大误差。另外，晶振也会随着使用时间的推移、温度的变化等等因素而导致误差。 */
	int	(*clock_set)(const clockid_t which_clock,
			     const struct timespec64 *tp);
	/* Returns the clock value in the current time namespace. */
	int	(*clock_get_timespec)(const clockid_t which_clock,
				      struct timespec64 *tp);
	/* Returns the clock value in the root time namespace. */
	ktime_t	(*clock_get_ktime)(const clockid_t which_clock);
	/* clock_adj函数允许系统根据外部的精确时间信息对本clock进行调整。
	nsleep和nsleep_restart这两个成员函数可以让进程sleep一段时间。 */
	int	(*clock_adj)(const clockid_t which_clock, struct __kernel_timex *tx);
	/* timer_xxx系列函数是和POSIX interval timer相关，具体会在POSIX timer文档中描述 */
	int	(*timer_create)(struct k_itimer *timer);
	int	(*nsleep)(const clockid_t which_clock, int flags,
			  const struct timespec64 *);
	int	(*timer_set)(struct k_itimer *timr, int flags,
			     struct itimerspec64 *new_setting,
			     struct itimerspec64 *old_setting);
	int	(*timer_del)(struct k_itimer *timr);
	void	(*timer_get)(struct k_itimer *timr,
			     struct itimerspec64 *cur_setting);
	void	(*timer_rearm)(struct k_itimer *timr);
	s64	(*timer_forward)(struct k_itimer *timr, ktime_t now);
	ktime_t	(*timer_remaining)(struct k_itimer *timr, ktime_t now);
	int	(*timer_try_to_cancel)(struct k_itimer *timr);
	void	(*timer_arm)(struct k_itimer *timr, ktime_t expires,
			     bool absolute, bool sigev_none);
	void	(*timer_wait_running)(struct k_itimer *timr);
};

extern const struct k_clock clock_posix_cpu;
extern const struct k_clock clock_posix_dynamic;
extern const struct k_clock clock_process;
extern const struct k_clock clock_thread;
extern const struct k_clock alarm_clock;

int posix_timer_event(struct k_itimer *timr, int si_private);

void common_timer_get(struct k_itimer *timr, struct itimerspec64 *cur_setting);
int common_timer_set(struct k_itimer *timr, int flags,
		     struct itimerspec64 *new_setting,
		     struct itimerspec64 *old_setting);
int common_timer_del(struct k_itimer *timer);

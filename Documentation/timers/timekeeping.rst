===========================================================
Clock sources, Clock events, sched_clock() and delay timers
时钟源, 时钟事件, sched_clock() 和延迟定时器
===========================================================

This document tries to briefly explain some basic kernel timekeeping
abstractions. It partly pertains to the drivers usually found in
drivers/clocksource in the kernel tree, but the code may be spread out
across the kernel.
文档尝试简短解释一些基本的内核时间抽象。它部分涉及通常在内核树中的drivers/clocksource
中找到的驱动程序，但代码可能分布在整个内核中。
If you grep through the kernel source you will find a number of architecture-
specific implementations of clock sources, clockevents and several likewise
architecture-specific overrides of the sched_clock() function and some
delay timers.
如果你在内核源码中使用grep，你会发现一些特定于体系结构的时钟源、时钟事件的实现，
以及一些类似的特定于体系结构的sched_clock()函数的覆盖和一些延迟定时器。
To provide timekeeping for your platform, the clock source provides
the basic timeline, whereas clock events shoot interrupts on certain points
on this timeline, providing facilities such as high-resolution timers.
sched_clock() is used for scheduling and timestamping, and delay timers
provide an accurate delay source using hardware counters.
为了为您的平台提供时间保持，时钟源提供基本时间线，而时钟事件在这个时间线上的某些
点触发中断，提供高分辨率定时器等功能。sched_clock()用于调度和时间戳，延迟定时器
使用硬件计数器提供准确的延迟源。

Clock sources
-------------

The purpose of the clock source is to provide a timeline for the system that
tells you where you are in time. For example issuing the command 'date' on
a Linux system will eventually read the clock source to determine exactly
what time it is.
时钟源的目的是为系统提供一个时间线，告诉您时间的位置。例如，在Linux系统上发出
'date'命令最终将读取时钟源来确定确切的时间。
Typically the clock source is a monotonic, atomic counter which will provide
n bits which count from 0 to (2^n)-1 and then wraps around to 0 and start over.
It will ideally NEVER stop ticking as long as the system is running. It
may stop during system suspend.
典型的时钟源是一个单调的、原子的计数器，它将提供n位，从0计数到(2^n)-1，然后
回绕到0并重新开始。只要系统运行，它理想上永远不会停止。它可能在系统挂起期间停止。
The clock source shall have as high resolution as possible, and the frequency
shall be as stable and correct as possible as compared to a real-world wall
clock. It should not move unpredictably back and forth in time or miss a few
cycles here and there.
这个时钟源应该具有尽可能高的分辨率，频率应该尽可能稳定和正确，与现实世界的挂钟
相比。它不应该在时间上不可预测地来回移动，也不应该偶尔错过一些周期。

It must be immune to the kind of effects that occur in hardware where e.g.
the counter register is read in two phases on the bus lowest 16 bits first
and the higher 16 bits in a second bus cycle with the counter bits
potentially being updated in between leading to the risk of very strange
values from the counter.
他必须免疫硬件中发生的那种效果，例如，计数器寄存器首先在总线上的两个阶段中读取
最低的16位，然后在第二个总线周期中读取更高的16位，计数器位在两者之间可能被更新，
导致计数器的非常奇怪的值。
When the wall-clock accuracy of the clock source isn't satisfactory, there
are various quirks and layers in the timekeeping code for e.g. synchronizing
the user-visible time to RTC clocks in the system or against networked time
servers using NTP, but all they do basically is update an offset against
the clock source, which provides the fundamental timeline for the system.
These measures does not affect the clock source per se, they only adapt the
system to the shortcomings of it.
当时钟源的挂钟精度不令人满意时，有各种各样的技巧和时间保持代码层，例如将用户
可见时间与系统中的RTC时钟同步，或者与使用NTP的网络时间服务器同步，但它们基本上
只是根据时钟源更新偏移量，为系统提供基本时间线。这些措施并不影响时钟源本身，
它们只是使系统适应它的缺点。
The clock source struct shall provide means to translate the provided counter
into a nanosecond value as an unsigned long long (unsigned 64 bit) number.
Since this operation may be invoked very often, doing this in a strict
mathematical sense is not desirable: instead the number is taken as close as
possible to a nanosecond value using only the arithmetic operations
multiply and shift, so in clocksource_cyc2ns() you find:
时钟源的结构应提供将提供的计数器转换为纳秒值的方法，作为一个无符号长长整数
(unsigned 64位)。由于这个操作可能经常被调用，严格地进行这个操作是不可取的：
相反，只使用乘法和移位运算，将数字尽可能接近纳秒值，因此在clocksource_cyc2ns()
中，你会发现：
  ns ~= (clocksource * mult) >> shift

You will find a number of helper functions in the clock source code intended
to aid in providing these mult and shift values, such as
clocksource_khz2mult(), clocksource_hz2mult() that help determine the
mult factor from a fixed shift, and clocksource_register_hz() and
clocksource_register_khz() which will help out assigning both shift and mult
factors using the frequency of the clock source as the only input.
你会在时钟源代码中找到一些辅助函数，旨在帮助提供这些mult和shift值，例如
clocksource_khz2mult()、clocksource_hz2mult()，它们有助于从固定移位确定mult
因子，clocksource_register_hz()和clocksource_register_khz()将帮助分配移位和
mult因子，使用时钟源的频率作为唯一输入。
For real simple clock sources accessed from a single I/O memory location
there is nowadays even clocksource_mmio_init() which will take a memory
location, bit width, a parameter telling whether the counter in the
register counts up or down, and the timer clock rate, and then conjure all
necessary parameters.
对于从单个I/O内存位置访问的真正简单的时钟源，现在甚至有clocksource_mmio_init()，
它将采用一个内存位置、位宽、一个参数，告诉寄存器中的计数器是向上还是向下计数，
以及计时器时钟速率，然后产生所有必要的参数。
Since a 32-bit counter at say 100 MHz will wrap around to zero after some 43
seconds, the code handling the clock source will have to compensate for this.
That is the reason why the clock source struct also contains a 'mask'
member telling how many bits of the source are valid. This way the timekeeping
code knows when the counter will wrap around and can insert the necessary
compensation code on both sides of the wrap point so that the system timeline
remains monotonic.
翻译: 由于32位计数器在100 MHz下在大约43秒后会回绕到零，处理时钟源的代码将不得不
对此进行补偿。这就是为什么时钟源结构也包含一个'mask'成员，告诉源的多少位是有效的。
这样，时间保持代码就知道计数器何时会回绕，并且可以在回绕点的两侧插入必要的补偿
代码，以便系统时间线保持单调。

Clock events
------------

Clock events are the conceptual reverse of clock sources: they take a
desired time specification value and calculate the values to poke into
hardware timer registers.
时钟事件是时钟源的概念反转：它们接受一个期望的时间规范值，并计算要插入硬件计时器
寄存器的值。
Clock events are orthogonal to clock sources. The same hardware
and register range may be used for the clock event, but it is essentially
a different thing. The hardware driving clock events has to be able to
fire interrupts, so as to trigger events on the system timeline. On an SMP
system, it is ideal (and customary) to have one such event driving timer per
CPU core, so that each core can trigger events independently of any other
core.
时钟事件与时钟源正交。相同的硬件和寄存器范围可以用于时钟事件，但它本质上是不同的。
驱动时钟事件的硬件必须能够触发中断，以便在系统时间线上触发事件。在SMP系统上，
最理想的（也是习惯的）是每个CPU核心有一个这样的事件驱动定时器，以便每个核心
可以独立于任何其他核心触发事件。
You will notice that the clock event device code is based on the same basic
idea about translating counters to nanoseconds using mult and shift
arithmetic, and you find the same family of helper functions again for
assigning these values. The clock event driver does not need a 'mask'
attribute however: the system will not try to plan events beyond the time
horizon of the clock event.
你会注意到，时钟事件设备代码基于相同的基本思想，使用mult和shift算术将计数器转换
为纳秒，再次找到相同的辅助函数族，用于分配这些值。时钟事件驱动程序不需要'mask'
属性：系统不会尝试计划超出时钟事件时间范围的事件。

sched_clock()
-------------

In addition to the clock sources and clock events there is a special weak
function in the kernel called sched_clock(). This function shall return the
number of nanoseconds since the system was started. An architecture may or
may not provide an implementation of sched_clock() on its own. If a local
implementation is not provided, the system jiffy counter will be used as
sched_clock().
除了时钟源和时钟事件之外，内核中还有一个特殊的弱函数，称为sched_clock()。这个函数
应该返回自系统启动以来的纳秒数。一个体系结构可能会或可能不会提供sched_clock()的
实现。如果没有提供本地实现，系统jiffy计数器将被用作sched_clock()。
As the name suggests, sched_clock() is used for scheduling the system,
determining the absolute timeslice for a certain process in the CFS scheduler
for example. It is also used for printk timestamps when you have selected to
include time information in printk for things like bootcharts.
正如其名称所示，sched_clock()用于调度系统，例如，在CFS调度程序中确定某个进程的
绝对时间片。当您选择在printk中包含时间信息以用于引导图表等时，它也用于printk时间戳。
Compared to clock sources, sched_clock() has to be very fast: it is called
much more often, especially by the scheduler. If you have to do trade-offs
between accuracy compared to the clock source, you may sacrifice accuracy
for speed in sched_clock(). It however requires some of the same basic
characteristics as the clock source, i.e. it should be monotonic.
与时钟源相比，sched_clock()必须非常快：它被调用的频率更高，特别是由调度程序。
如果您必须在与时钟源相比的准确性之间进行权衡，您可能会牺牲sched_clock()的准确性
以换取速度。但是，它需要一些与时钟源相同的基本特征，即它应该是单调的。
The sched_clock() function may wrap only on unsigned long long boundaries,
i.e. after 64 bits. Since this is a nanosecond value this will mean it wraps
after circa 585 years. (For most practical systems this means "never".)
这个sched_clock()函数只能在无符号长长整数边界上回绕，即在64位之后。由于这是一个
纳秒值，这意味着它在大约585年后回绕。（对于大多数实际系统，这意味着“永远”）。
If an architecture does not provide its own implementation of this function,
it will fall back to using jiffies, making its maximum resolution 1/HZ of the
jiffy frequency for the architecture. This will affect scheduling accuracy
and will likely show up in system benchmarks.
如果一个体系结构没有提供自己的实现，它将退回到使用jiffies，使其最大分辨率为
体系结构的jiffy频率的1/HZ。这将影响调度的准确性，并可能在系统基准测试中显示出来。

The clock driving sched_clock() may stop or reset to zero during system
suspend/sleep. This does not matter to the function it serves of scheduling
events on the system. However it may result in interesting timestamps in
printk().
驱动sched_clock()的时钟可能在系统挂起/睡眠期间停止或重置为零。这对它服务的调度
系统上的事件的功能并不重要。但是，它可能导致printk()中有趣的时间戳。
The sched_clock() function should be callable in any context, IRQ- and
NMI-safe and return a sane value in any context.
这个sched_clock()函数应该在任何上下文中调用，IRQ-和NMI安全，并在任何上下文中返回
一个合理的值。
Some architectures may have a limited set of time sources and lack a nice
counter to derive a 64-bit nanosecond value, so for example on the ARM
architecture, special helper functions have been created to provide a
sched_clock() nanosecond base from a 16- or 32-bit counter. Sometimes the
same counter that is also used as clock source is used for this purpose.
一些体系结构可能有一组有限的时间源，缺乏一个很好的计数器来推导一个64位纳秒值，
因此例如在ARM体系结构上，特殊的辅助函数已经被创建，以提供一个sched_clock()
纳秒基础，从一个16位或32位计数器。有时，也用于时钟源的相同计数器用于此目的。

On SMP systems, it is crucial for performance that sched_clock() can be called
independently on each CPU without any synchronization performance hits.
Some hardware (such as the x86 TSC) will cause the sched_clock() function to
drift between the CPUs on the system. The kernel can work around this by
enabling the CONFIG_HAVE_UNSTABLE_SCHED_CLOCK option. This is another aspect
that makes sched_clock() different from the ordinary clock source.
在SMP系统上，sched_clock()可以在每个CPU上独立调用，而不会有任何同步性能损失，
这对性能至关重要。一些硬件（如x86 TSC）将导致系统上的CPU之间的sched_clock()
函数漂移。内核可以通过启用CONFIG_HAVE_UNSTABLE_SCHED_CLOCK选项来解决这个问题。
这是使sched_clock()与普通时钟源不同的另一个方面。

Delay timers (some architectures only)
--------------------------------------

On systems with variable CPU frequency, the various kernel delay() functions
will sometimes behave strangely. Basically these delays usually use a hard
loop to delay a certain number of jiffy fractions using a "lpj" (loops per
jiffy) value, calibrated on boot.
在具有可变CPU频率的系统上，各种内核delay()函数有时会表现得很奇怪。基本上，
这些延迟通常使用一个硬循环来延迟一定数量的jiffy分数，使用一个在启动时校准的
"lpj"（每个jiffy的循环）值。
Let's hope that your system is running on maximum frequency when this value
is calibrated: as an effect when the frequency is geared down to half the
full frequency, any delay() will be twice as long. Usually this does not
hurt, as you're commonly requesting that amount of delay *or more*. But
basically the semantics are quite unpredictable on such systems.
我们希望在校准这个值时，您的系统正在运行在最大频率上：当频率降低到全频率的一半时，
任何delay()都会变长一倍。通常这不会有什么影响，因为您通常请求的延迟量*或更多*。
但基本上，在这种系统上，语义是相当不可预测的。
Enter timer-based delays. Using these, a timer read may be used instead of
a hard-coded loop for providing the desired delay.
进入基于定时器的延迟。使用这些，可以使用定时器读取来提供所需的延迟，而不是
硬编码循环。
This is done by declaring a struct delay_timer and assigning the appropriate
function pointers and rate settings for this delay timer.
这是通过声明一个struct delay_timer并为这个延迟定时器分配适当的函数指针和速率设置
来完成的。
This is available on some architectures like OpenRISC or ARM.
这在一些体系结构上是可用的，如OpenRISC或ARM。
.. _readme:

Linux kernel release 6.x <http://kernel.org/>
=============================================

这些是Linux 6版本的发行说明.请仔细阅读,因为它们会告诉你这是什么,
解释如何安装内核,以及如果出现问题该怎么办.

What is Linux?
--------------
Linux 是一个类 Unix 操作系统,由 Linus Torvalds 从头开始编写,并得到了网络上一群
松散组织的黑客团队的协助.它旨在符合 POSIX 和单一 UNIX 规范.

它具有现代全功能 Unix 所期望的所有功能，包括真正的多任务处理/虚拟内存、共享库、
按需加载、共享写时复制可执行文件、适当的内存管理和多栈网络（包括 IPv4 和 IPv6）。

它是根据 GNU 通用公共许可证 v2 发行的 - 有关更多详细信息,请参阅随附的 COPYING 
文件.

On what hardware does it run?
-----------------------------

  Although originally developed first for 32-bit x86-based PCs (386 or higher),
  today Linux also runs on (at least) the Compaq Alpha AXP, Sun SPARC and
  UltraSPARC, Motorola 68000, PowerPC, PowerPC64, ARM, Hitachi SuperH, Cell,
  IBM S/390, MIPS, HP PA-RISC, Intel IA-64, DEC VAX, AMD x86-64 Xtensa, and
  ARC architectures.
  Linux 很容易移植到大多数通用的 32 位或 64 位架构,只要它们有分页内存管理单元 (PMMU) 和 
  GNU C 编译器 (gcc)(GNU 编译器集合的一部分)的端口。Linux 也已移植到许多没有 PMMU 的架构上,
  尽管功能显然有所限制.
  Linux 也已移植到自身.您现在可以将内核作为用户空间应用程序运行 - 这称为 UserMode Linux (UML)。
  
Documentation
-------------

 - There is a lot of documentation available both in electronic form on
   the Internet and in books, both Linux-specific and pertaining to
   general UNIX questions.  I'd recommend looking into the documentation
   subdirectories on any Linux FTP site for the LDP (Linux Documentation
   Project) books.  This README is not meant to be documentation on the
   system: there are much better sources available.

 - There are various README files in the Documentation/ subdirectory:
   these typically contain kernel-specific installation notes for some
   drivers for example. Please read the
   :ref:`Documentation/process/changes.rst <changes>` file, as it
   contains information about the problems, which may result by upgrading
   your kernel.

Installing the kernel source
----------------------------

 - If you install the full sources, put the kernel tarball in a
   directory where you have permissions (e.g. your home directory) and
   unpack it::

     xz -cd linux-6.x.tar.xz | tar xvf -

   Replace "X" with the version number of the latest kernel.

   Do NOT use the /usr/src/linux area! This area has a (usually
   incomplete) set of kernel headers that are used by the library header
   files.  They should match the library, and not get messed up by
   whatever the kernel-du-jour happens to be.

 - You can also upgrade between 6.x releases by patching.  Patches are
   distributed in the xz format.  To install by patching, get all the
   newer patch files, enter the top level directory of the kernel source
   (linux-6.x) and execute::

     xz -cd ../patch-6.x.xz | patch -p1

   Replace "x" for all versions bigger than the version "x" of your current
   source tree, **in_order**, and you should be ok.  You may want to remove
   the backup files (some-file-name~ or some-file-name.orig), and make sure
   that there are no failed patches (some-file-name# or some-file-name.rej).
   If there are, either you or I have made a mistake.

   Unlike patches for the 6.x kernels, patches for the 6.x.y kernels
   (also known as the -stable kernels) are not incremental but instead apply
   directly to the base 6.x kernel.  For example, if your base kernel is 6.0
   and you want to apply the 6.0.3 patch, you must not first apply the 6.0.1
   and 6.0.2 patches. Similarly, if you are running kernel version 6.0.2 and
   want to jump to 6.0.3, you must first reverse the 6.0.2 patch (that is,
   patch -R) **before** applying the 6.0.3 patch. You can read more on this in
   :ref:`Documentation/process/applying-patches.rst <applying_patches>`.

   Alternatively, the script patch-kernel can be used to automate this
   process.  It determines the current kernel version and applies any
   patches found::

     linux/scripts/patch-kernel linux

   The first argument in the command above is the location of the
   kernel source.  Patches are applied from the current directory, but
   an alternative directory can be specified as the second argument.

 - Make sure you have no stale .o files and dependencies lying around::

     cd linux
     make mrproper

   You should now have the sources correctly installed.

Software requirements
---------------------

   Compiling and running the 6.x kernels requires up-to-date
   versions of various software packages.  Consult
   :ref:`Documentation/process/changes.rst <changes>` for the minimum version numbers
   required and how to get updates for these packages.  Beware that using
   excessively old versions of these packages can cause indirect
   errors that are very difficult to track down, so don't assume that
   you can just update packages when obvious problems arise during
   build or operation.

Build directory for the kernel
------------------------------

   When compiling the kernel, all output files will per default be
   stored together with the kernel source code.
   Using the option ``make O=output/dir`` allows you to specify an alternate
   place for the output files (including .config).
   Example::
   编译内核时,所有输出文件默认将与内核源代码一起存储.
   使用选项 ``make O=output/dir`` 可以指定输出文件(包括 .config)的备用位置.
   例如::

     kernel source code: /usr/src/linux-6.x
     build directory:    /home/name/build/kernel

   To configure and build the kernel, use::

     cd /usr/src/linux-6.x
     make O=/home/name/build/kernel menuconfig
     make O=/home/name/build/kernel
     sudo make O=/home/name/build/kernel modules_install install

   Please note: If the ``O=output/dir`` option is used, then it must be
   used for all invocations of make.

Configuring the kernel
----------------------

   Do not skip this step even if you are only upgrading one minor
   version.  New configuration options are added in each release, and
   odd problems will turn up if the configuration files are not set up
   as expected.  If you want to carry your existing configuration to a
   new version with minimal work, use ``make oldconfig``, which will
   only ask you for the answers to new questions.
   不要跳过这一步,即使你只是升级一个次要版本.每个版本都会添加新的配置选项,如果配置文件没有按预期设置,
    将会出现奇怪的问题.如果你想将现有配置带到新版本,并且工作量最小,请使用 ``make oldconfig``,
    它只会要求你回答新问题.
 - Alternative configuration commands are::

     "make config"      Plain text interface.

     "make menuconfig"  Text based color menus, radiolists & dialogs.

     "make nconfig"     Enhanced text based color menus.

     "make xconfig"     Qt based configuration tool.

     "make gconfig"     GTK+ based configuration tool.

     "make oldconfig"   Default all questions based on the contents of
                        your existing ./.config file and asking about
                        new config symbols.

     "make olddefconfig"
                        Like above, but sets new symbols to their default
                        values without prompting.

     "make defconfig"   Create a ./.config file by using the default
                        symbol values from either arch/$ARCH/defconfig
                        or arch/$ARCH/configs/${PLATFORM}_defconfig,
                        depending on the architecture.

     "make ${PLATFORM}_defconfig"
                        Create a ./.config file by using the default
                        symbol values from
                        arch/$ARCH/configs/${PLATFORM}_defconfig.
                        Use "make help" to get a list of all available
                        platforms of your architecture.

     "make allyesconfig"
                        Create a ./.config file by setting symbol
                        values to 'y' as much as possible.

     "make allmodconfig"
                        Create a ./.config file by setting symbol
                        values to 'm' as much as possible.

     "make allnoconfig" Create a ./.config file by setting symbol
                        values to 'n' as much as possible.

     "make randconfig"  Create a ./.config file by setting symbol
                        values to random values.

     "make localmodconfig" Create a config based on current config and
                           loaded modules (lsmod). Disables any module
                           option that is not needed for the loaded modules.

                           To create a localmodconfig for another machine,
                           store the lsmod of that machine into a file
                           and pass it in as a LSMOD parameter.

                           Also, you can preserve modules in certain folders
                           or kconfig files by specifying their paths in
                           parameter LMC_KEEP.

                   target$ lsmod > /tmp/mylsmod
                   target$ scp /tmp/mylsmod host:/tmp

                   host$ make LSMOD=/tmp/mylsmod \
                           LMC_KEEP="drivers/usb:drivers/gpu:fs" \
                           localmodconfig

                           The above also works when cross compiling.

     "make localyesconfig" Similar to localmodconfig, except it will convert
                           all module options to built in (=y) options. You can
                           also preserve modules by LMC_KEEP.

     "make kvm_guest.config"   Enable additional options for kvm guest kernel
                               support.

     "make xen.config"   Enable additional options for xen dom0 guest kernel
                         support.

     "make tinyconfig"  Configure the tiniest possible kernel.

   You can find more information on using the Linux kernel config tools
   in Documentation/kbuild/kconfig.rst.
   你可以在 Documentation/kbuild/kconfig.rst 中找到更多关于使用 Linux 内核配置工具的信息.
 - NOTES on ``make config``:

    - Having unnecessary drivers will make the kernel bigger, and can
      under some circumstances lead to problems: probing for a
      nonexistent controller card may confuse your other controllers.
      包含不必要的驱动程序会使内核变得更大,并且在某些情况下可能会导致问题:
      探测不存在的控制器卡可能会混淆其他控制器.
    - A kernel with math-emulation compiled in will still use the
      coprocessor if one is present: the math emulation will just
      never get used in that case.  The kernel will be slightly larger,
      but will work on different machines regardless of whether they
      have a math coprocessor or not.
      一个编译了数学仿真的内核仍然会使用协处理器,如果存在的话:在这种情况下,数学仿真将永远不会被使用.
      内核会稍微变大,但无论机器是否有数学协处理器,它都可以在不同的机器上工作.
    - The "kernel hacking" configuration details usually result in a
      bigger or slower kernel (or both), and can even make the kernel
      less stable by configuring some routines to actively try to
      break bad code to find kernel problems (kmalloc()).  Thus you
      should probably answer 'n' to the questions for "development",
      "experimental", or "debugging" features.
      kernel hacking的配置细节通常会导致内核变得更大或更慢(或两者兼有),甚至
      可以通过配置一些例程来积极尝试
      打破坏代码来查找内核问题(kmalloc())来使内核不稳定.因此,你可能应该对“开发”、
      “实验”或“调试”功能的问题回答“n”.
Compiling the kernel
--------------------

 - Make sure you have at least gcc 5.1 available.
   For more information, refer to :ref:`Documentation/process/changes.rst <changes>`.

 - Do a ``make`` to create a compressed kernel image. It is also
   possible to do ``make install`` if you have lilo installed to suit the
   kernel makefiles, but you may want to check your particular lilo setup first.

   To do the actual install, you have to be root, but none of the normal
   build should require that. Don't take the name of root in vain.

 - If you configured any of the parts of the kernel as ``modules``, you
   will also have to do ``make modules_install``.

 - Verbose kernel compile/build output:

   Normally, the kernel build system runs in a fairly quiet mode (but not
   totally silent).  However, sometimes you or other kernel developers need
   to see compile, link, or other commands exactly as they are executed.
   For this, use "verbose" build mode.  This is done by passing
   ``V=1`` to the ``make`` command, e.g.::
   正常情况下,内核构建系统以相当安静的模式运行(但不是完全静音).然而,有时你或其他内核开发人员需要
    看到编译、链接或其他命令的确切执行方式.为此,使用“详细”构建模式.这是通过将 ``V=1`` 传递给 ``make`` 命令来完成的,例如::
     make V=1 all

   To have the build system also tell the reason for the rebuild of each
   target, use ``V=2``.  The default is ``V=0``.
   为了让构建系统还告诉每个目标重新构建的原因,使用 ``V=2``.默认值是 ``V=0``.
 - Keep a backup kernel handy in case something goes wrong.  This is
   especially true for the development releases, since each new release
   contains new code which has not been debugged.  Make sure you keep a
   backup of the modules corresponding to that kernel, as well.  If you
   are installing a new kernel with the same version number as your
   working kernel, make a backup of your modules directory before you
   do a ``make modules_install``.

   Alternatively, before compiling, use the kernel config option
   "LOCALVERSION" to append a unique suffix to the regular kernel version.
   LOCALVERSION can be set in the "General Setup" menu.

 - In order to boot your new kernel, you'll need to copy the kernel
   image (e.g. .../linux/arch/x86/boot/bzImage after compilation)
   to the place where your regular bootable kernel is found.
   为了启动新内核,你需要将内核映像(例如.../linux/arch/x86/boot/bzImage)
   复制到常规可引导内核所在的位置.
 - Booting a kernel directly from a floppy without the assistance of a
   bootloader such as LILO, is no longer supported.
   直接从软盘引导内核而不使用 LILO 等引导加载程序的支持已不再受支持.
   If you boot Linux from the hard drive, chances are you use LILO, which
   uses the kernel image as specified in the file /etc/lilo.conf.  The
   kernel image file is usually /vmlinuz, /boot/vmlinuz, /bzImage or
   /boot/bzImage.  To use the new kernel, save a copy of the old image
   and copy the new image over the old one.  Then, you MUST RERUN LILO
   to update the loading map! If you don't, you won't be able to boot
   the new kernel image.
   如果你从硬盘引导 Linux,你很可能使用 LILO,它使用 /etc/lilo.conf 文件中指定的内核映像.
    内核映像文件通常是 /vmlinuz, /boot/vmlinuz, /bzImage 或 /boot/bzImage.为了使用新内核,
    保存旧映像的副本,并将新映像复制到旧映像上.然后,你必须重新运行 LILO 来更新加载映射!
    如果不这样做,你将无法引导新的内核映像.
   Reinstalling LILO is usually a matter of running /sbin/lilo.
   You may wish to edit /etc/lilo.conf to specify an entry for your
   old kernel image (say, /vmlinux.old) in case the new one does not
   work.  See the LILO docs for more information.

   After reinstalling LILO, you should be all set.  Shutdown the system,
   reboot, and enjoy!

   If you ever need to change the default root device, video mode,
   etc. in the kernel image, use your bootloader's boot options
   where appropriate.  No need to recompile the kernel to change
   these parameters.

 - Reboot with the new kernel and enjoy.

If something goes wrong
-----------------------

If you have problems that seem to be due to kernel bugs, please follow the
instructions at 'Documentation/admin-guide/reporting-issues.rst'.

Hints on understanding kernel bug reports are in
'Documentation/admin-guide/bug-hunting.rst'. More on debugging the kernel
with gdb is in 'Documentation/dev-tools/gdb-kernel-debugging.rst' and
'Documentation/dev-tools/kgdb.rst'.

eBPF sample programs
====================
这个目录包含测试stubs、verifier测试套件和使用 eBPF 的示例。示例使用来自 tools/lib/bpf 的 libbpf。
注意，特定于 XDP 的示例已从此目录中移除，并迁移到 xdp-tools 仓库：https://github.com/xdp-project/xdp-tools
请参阅从此目录中移除每个工具的提交消息，以了解如何将特定命令调用从旧示例转换为 xdp-tools 中的实用程序。

Build dependencies
==================

Compiling requires having installed:
 * clang
 * llvm
 * pahole

请参阅 :ref:`Documentation/process/changes.rst <changes>` 以了解所需的最低版本号以及如何
更新它们。请注意，LLVM 的工具 'llc' 必须支持目标 'bpf'，可以通过以下命令列出版本和支持的目标：
``llc --version``

Clean and configuration
-----------------------

在尝试新的架构或进行某些更改后（按需），可能需要清理工具、示例或内核::
 make -C tools clean
 make -C samples/bpf clean
 make clean

Configure kernel, defconfig for instance
(see "tools/testing/selftests/bpf/config" for a reference config)::

 make defconfig

Kernel headers
--------------

通常需要当前内核的头文件作为依赖项。
为了避免以普通用户身份在系统范围内安装开发内核头文件，只需调用以下命令::
 make headers_install
这将在 git/build 顶层目录中创建一个本地的 "usr/include" 目录，make 系统会优先自动使用该目录。

Compiling
=========

要构建 BPF 示例，请从内核顶层目录运行以下命令::

 make M=samples/bpf

也可以从此目录调用 make。这将隐藏上述 make 的调用方式。

Manually compiling LLVM with 'bpf' support
------------------------------------------

自版本 3.7.0 起，LLVM 为 BPF 字节码架构添加了一个正式的 LLVM 后端目标。

默认情况下，LLVM 将构建所有非实验性后端，包括 BPF。
为了生成更小的 llc 二进制文件，可以使用以下命令::

 -DLLVM_TARGETS_TO_BUILD="BPF"

我们建议希望获得最快增量构建的开发人员使用 Ninja 构建系统，您可以在系统的包管理器中找到它，通常包名为 ninja 或 ninja-build。

手动编译 LLVM 和 clang 的快速片段
（构建依赖项包括 ninja、cmake 和 gcc-c++）::

 $ git clone https://github.com/llvm/llvm-project.git
 $ mkdir -p llvm-project/llvm/build
 $ cd llvm-project/llvm/build
 $ cmake .. -G "Ninja" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
            -DLLVM_ENABLE_PROJECTS="clang"    \
            -DCMAKE_BUILD_TYPE=Release        \
            -DLLVM_BUILD_RUNTIME=OFF
 $ ninja

还可以通过在 make 命令行中重新定义 LLC 或 CLANG，将 make 指向新编译的 'llc' 或 'clang' 命令::

 make M=samples/bpf LLC=~/git/llvm-project/llvm/build/bin/llc CLANG=~/git/llvm-project/llvm/build/bin/clang

Cross compiling samples
-----------------------
为了交叉编译，例如针对 arm64 目标，在调用 make 之前，先导出 CROSS_COMPILE 和 ARCH 环境变量。
但请在上述清理、配置和头文件安装步骤之前执行此操作。这将指示 make 为交叉目标构建示例程序::

 export ARCH=arm64
 export CROSS_COMPILE="aarch64-linux-gnu-"

Headers can be also installed on RFS of target board if need to keep them in
sync (not necessarily and it creates a local "usr/include" directory also)::

 make INSTALL_HDR_PATH=~/some_sysroot/usr headers_install

Pointing LLC and CLANG is not necessarily if it's installed on HOST and have
in its targets appropriate arm64 arch (usually it has several arches).
Build samples::

 make M=samples/bpf

Or build samples with SYSROOT if some header or library is absent in toolchain,
say libelf, providing address to file system containing headers and libs,
can be RFS of target board::

 make M=samples/bpf SYSROOT=~/some_sysroot

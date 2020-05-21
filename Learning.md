## Day1

- 学习了紫密前辈的Paper: `Different is Good: Detecting the Use of Uninitialized Variables through Differential Replay`。
  - 通过差异重放技术和符号化的污点分析技术挖掘window kernel中的信息泄漏漏洞。
  - 差异重放：对程序执行进行重放，一次是正常执行，一次则将堆和栈的初始化值进行修改劫持，如果两者在某个程序点的引用的内存值存在差异，则说明存在未初始化
  - 符号化的污点分析：src点为劫持的堆和栈初始化点，sink点为未初始化变量引用点，进行污点分析，判断allocated位置

- Mark文章中涉及到的二进制程序分析的项目：
  - PANDA
  - SimuVex（angr的符号执行框架，基于vex ir进行符号执行）
  - reactOS

## Day2

- 复习Modern Windows Exploit和Exploit编写教程（用户态的windows exploit）
  - 基础栈溢出
  - 基于SEH的栈溢出
  - Unicode Exploit
  - Windows ROP
- Windows Kernel Exploit环境配置（<https://bbs.pediy.com/thread-252309.htm>）
  - 安装Windows 7 x86 sp1虚拟机
  - 安装VirtualKD
  - 成功启动内核调试

## Day3

- 阅读《Windows内核原理与实现》1~33页

  - 第一章：概述

    - 操作系统概述
      - 计算机系统的硬件资源管理
      - 为应用程序提供执行环境
    - Windows发展历史
    - 操作系统研究进展

  - 第二章：Windows系统总述

    - 现代操作系统的基本结构
    - Windows系统结构
      - Windows系统结构图
        - HAL、内核、执行体、ntdll.dll、设备驱动程序、WIndows子系统内核模块
      - Windows内核结构
      - Windows内核中的关键组件
        - HAL hal.dll
        - 内核（微内核）ntoskrnl.exe的下层
        - 执行体 ntoskrnl.exe的上层：线程和进程管理、内存管理器、安全引用监视器、I/O管理器、缓存管理器、配置管理器、即插即用管理器、电源管理器；支持函数：对象管理器、LPC设施、运行时库函数、执行体支持例程
        - 设备驱动程序
        - 文件系统/存储管理：NTFS、FAT
        - 网络：Winsock、WinInet等等
      - Windows子系统
        - 包含
          - 用户态：csrss.exe、一组DLL（kernel32.dll, user32.dll, gdi32.dll, advapi.dll）
            - 前者负责控制台窗口的功能和进程、线程创建；后者实现文档化的Win32 API，有些可以在用户态完成，大多需要调用执行体API活win32k.sys提供的服务
          - 内核态：win32k.sys
            - 窗口管理和图形设备管理

## Day4

- 编译HEVD
  - 安装VS 2015 + Windows SDK + Windows Driver Kit 10
  - 解决编译错误
    - 创建测试签名
    - lnf2Cat使用local时间
- 环境配置问题

  - VMware 14与宿主机Win 10 1903的兼容性不好（由于Win10的沙盒机制），更新到Vmware 15.5
  - Vmware 15.5与VirtualKD不兼容，改用VirtualKD-Redux

- 阅读MSRC的《Solving Uninitialized Stack Memory on Windows》（https://msrc-blog.microsoft.com/2020/05/13/solving-uninitialized-stack-memory-on-windows/）
  - 未初始化内存漏洞的潜在解决方案
    - 静态分析（编译时和编译后）
      - VS提供静态分析warning，但比较保守，为了减少误报
      - codeql规则，误报太多
    - Fuzzing
      - 未初始化漏洞不会crash，不容易监控
    - 代码审计
    - **自动初始化 InitAll——自动化的编译时栈变量初始化**
      - kernel态代码、Hyper-V代码和一些其他代码开启
      - 在编译器前端实现
      - 初始化为0：比较好的一种方式
      - 在Win 10 1903开始引入
  - 因InitAll引入的UAF漏洞

## Day5 & Day6

调试学习了HEVD的`UseAfterFreeNonPagedPool`

## Day7

调试学习了HEVD的`BufferOverflowStack`

## Day8 & Day9

调试学习了HEVD的`TriggerBufferOverflowStackGS`


















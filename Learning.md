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




# CVE-2024-51324

前两天看到微步发的文章（https://mp.weixin.qq.com/s/d79eCU9UikVDiLpkafafuQ），一个银狐利用了百度的一个漏洞驱动。刚好最近也在学windows kernel，就分析了一下这个驱动，写一下EXP。当然这个驱动已经被很多杀软拉黑了，主要就是学下驱动EXP编写。

![8f2799ed6ed1c3b2365cd4573f301834](README.assets/8f2799ed6ed1c3b2365cd4573f301834.png)

首先找到`IRP_MJ_DEVICE_CONTROL`的派遣函数。

![image-20251112142400879](README.assets/image-20251112142400879.png)

IoControlCode为`0x800024B4`时进入`sub_15230`函数。

![image-20251112142515003](README.assets/image-20251112142515003.png)

此函数接受R3层传入的PID，首先需要确保输入缓冲区为4字节。即一个DWORD类型，刚好表示PID，在调用`sub_152B0`函数。

![image-20251112142727438](README.assets/image-20251112142727438.png)

根据进程PID，先获取此进程句柄，然后经典调用ZwTerminateProcess。

![image-20251112143020910](README.assets/image-20251112143020910.png)
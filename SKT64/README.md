# SKT64.sys分析

分析一个ARK工具（ https://github.com/PspExitThread/SKT64 ），这个工具只有一个exe，运行过程中可能会释放驱动。可以使用360查看释放驱动的位置，可以得到`SKT64.sys`。



![image-20251124094158946](README.assets/image-20251124094158946.png)

此驱动加了VMProtect壳，难以分析。

![image-20251124095717254](README.assets/image-20251124095717254.png)

可以看一下原程序，在其中实现了三个函数，名字意思就可以看出是和内核终止程序相关的。

![image-20251124100153381](README.assets/image-20251124100153381.png)

在`KernelTerminateProcess`中向驱动设备对象发出了一个IOCTL请求，猜测用于终止进程。

![image-20251124100401696](README.assets/image-20251124100401696.png)

其余两个函数除了IO控制码不一样，其余都一致。

![image-20251124100546242](README.assets/image-20251124100546242.png)

![image-20251124100605528](README.assets/image-20251124100605528.png)

根据在IDA中的偏移，在x64dbg中下这三个函数的断点。例如KernelTerminateProcess断点位置在`7FF60C0C0000 + 69C0 = 7FF60C0C69C0`。

![image-20251124101116425](README.assets/image-20251124101116425.png)

![image-20251124100947332](README.assets/image-20251124100947332.png)

三个地方打上断点后，在x64dbg中进行一些设置，将这些选项全部取消勾选，确保只能运行到我打的条件断点才断下来。

![image-20251124101802048](README.assets/image-20251124101802048.png)

然后重新运行。在启动的界面中，Terminate一个进程。

![image-20251124102030290](README.assets/image-20251124102030290.png)

断在了KernelTerminateProcess。

![image-20251124102106292](README.assets/image-20251124102106292.png)

到这里就很明了了。并且通过Winobj可以发现创建的符号链接为`\\.\ArkDrv64`

![image-20251124104532915](README.assets/image-20251124104532915.png)

![image-20251124104549966](README.assets/image-20251124104549966.png)
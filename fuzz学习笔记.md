### 注意：图片在同名文件夹下

## 参考资料
* [AFL](https://github.com/google/AFL)
* [AFL-PLUSPLUS](https://github.com/AFLplusplus/AFLplusplus)
*  [opposrc:针对cajviewer进行无源码fuzz/cajviewer逆向分析与漏洞挖掘](https://mp.weixin.qq.com/s/7STPL-2nCUKC3LHozN6-zg)及其系列文章
* [Fuzzing101](https://github.com/antonio-morales/Fuzzing101) [afl-training](https://github.com/mykter/afl-training)
* [利用WinAFL对闭源软件进行漏洞挖掘](https://www.sohu.com/a/416424805_750628)
* fuzz rdp or other remote desktop browser tools


## 基础知识
### linux安装软件
一般是三步：
1. ./Configure  
configure是一个脚本，一般由Autoconf工具生成，它会检验当前的系统环境，看是否满足安装软件所必需的条件：比如当前系统是否支持待安装软件，是否已经安装软件依赖等。configure脚本最后会生成一个Makefile文件.
* --prefix=PREFIX  #指定程序包的安装目录,把所有安装文件放在指定路径中，不会杂乱
* CC=  #.c文件的编译命令，示例CC=/usr/bin/mipsel-linux-gcc
* CXX=  #c++文件的编译命令，示例CXX=/usr/bin/mipsel-linux-g++
* 示例：`CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"`
2. make  
  使用Makefile文件，如果只有"make"命令，而没有指明"目标"，一般情况下是编译源码
3. make install  
  make install表示运行"目标为install的make命令"，即将编译后的结果复制到相应目录中
### 进程间通信IPC
* 匿名/命名管道 管道本质上就是内核中的一个缓存，当进程创建一个管道后，系统会返回两个文件描述符，可以通过这两个描述符往管道写入数据或者读取数据。管道是一种单向通信，即管道的一端只用于读数据，另一端只用于写数据，只有写完数据之后另一个进程才能去读。
* 信号量
* 消息队列
* 共享内存
* 套接字
### execve()函数
* execve()系统调用的作用是运行另外一个指定的程序。它会把新程序加载到当前进程的内存空间内，当前的进程会被丢弃，它的代码段、堆、栈和所有的段数据都会被新进程相应的部分代替，然后会从新程序的初始化代码和main函数开始运行。不生成新进程，进程的ID将保持不变。
### 编译过程
* 预处理：.c生成.i
* 编译：.i生成.s，到汇编语言
* 汇编：.s生成.o，汇编语言到机器语言
* 链接：由.o生成可执行文件
### LLVM
* 传统的编译器通常分为三个部分，前端（frontEnd），优化器（Optimizer）和后端（backEnd）. 在编译过程中，前端主要负责词法和语法分析，将源代码转化为抽象语法树；优化器则是在前端的基础上，对得到的中间代码进行优化，使代码更加高效；后端则是将已经优化的中间代码转化为针对各自平台的机器代码。
* IR：高级语言到汇编的中间语言，可以解决平台间的差异。llvm负责IR到汇编语言的转化。
* ![Alt text](./fuzz学习笔记/编译过程.png)
* ![Alt text](./fuzz学习笔记/llvm编译器.png)
* ![Alt text](./fuzz学习笔记/llvm编译器框架.png)
* Clang是苹果开发的，作为整个编译器的前端，用来编译C、C++和Objective-C，转化为llvm IR
* 参考[LLVM基本概念入门](https://zhuanlan.zhihu.com/p/140462815)、[详解三大编译器：gcc、llvm 和 clang](https://zhuanlan.zhihu.com/p/357803433)

### gcc
* 编译过程：预处理-编译-汇编-链接。
* as是 GNU 汇编器，主要用来编译 GNU C 编译器 gcc 输出的汇编文件，它将汇编代码转换成二进制代码，并存放到一个 object 文件中，该目标文件将由连接器 ld 连接.
* 简单的例子：gcc xxx.c -o xxx 

### dll注入
* [DLL 注入技术的 N 种姿势](https://zhuanlan.zhihu.com/p/28537697)
* 将dll强行加载在运行的进程中，注入的dll拥有正常访问进程内存的权限，且隐藏在正常进程中。
* 将dll放进某个进程的地址空间里，这样该进程和dll共享同一内存空间，dll可以使用该进程的所有资源，随时监控程序运行。
* dll加载后会自动执行DllMain()函数，利用该特性可为程序添加功能和修复bug等
  ```c
  BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
  {
      switch( dwReason )
      {
          case DLL_PROCESS_ATTACH:
              // 添加想执行的代码
              break;
          case DLL_THREAD_ATTACH:
              break;
          case DLL_THREAD_DETACH:
              break;	
          case DLL_PROCESS_DETACH:
              break;	
      }

      return TRUE;
  }
  ```
* 常见流程
  ```c
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);

  // 在远程进程中为路径名称分配空间
  LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, strlen(dllpath), MEM_COMMIT, PAGE_READWRITE);

  // 将DLL路径名称复制到远程进程地址空间
  DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)dllpath, strlen(dllpath), NULL);

  // 获取Kernel32.dll中的LoadLibraryW函数的真正地址
  PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

  // 创建远程线程调用LoadLibraryW(DLLPathname)
  HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
    
  ```

###  hook
* hook经常借助dll注入来实现。先创建好DLL形态的钩取函数，再将其轻松注入要钩取的目标进程，这样就完成了API钩取。
* 钩子的概念源于Windows的消息处理机制，通过设置钩子，应用程序可以对所有的消息事件进行拦截，然后执行钩子函数，对消息进行想要的处理方式。钩子的本质是一段用以处理系统消息的程序，通过系统调用，将其挂入到系统。钩子的种类有很多，每一种钩子负责截获并处理相应的消息。钩子机制允许应用程序截获并处理发往指定窗口的消息或特定事件。在特定的消息发出，并在到达目的窗口之前，钩子程序先行截获此消息并得到对其的控制权。此时在钩子函数中就可以对截获的消息进行各种修改处理，甚至强行终止该消息的继续传递。
* 全局钩子：钩取所有进程都使用的某个函数  
  局部钩子：只钩取某个进程中的某个函数

### 插桩(code instrumentation) 
* 插桩方法可以有两种类型：源插桩（Source instrumentation）和二进制插桩。也叫静态插桩(static binary instrumentation)和动态插桩(dynamic binary instrumentation)
* 动态二进制插桩（dynamic binary instrumentation,DBI）技术在程序执行过程中插入特定分析代码，实现对程序动态执行过程的监控与分析，并提供编程接口获取、更改程序动态执行期间的指令、内存和寄存器以及函数参数、返回值和程序运行上下文等信息，实现细粒度的动态监控，如覆盖率获取、程序执行路径获取、函数hook等。可用于流程分析、污点分析、模糊测试、代码覆盖、生成测试历程、逆向工程、调试、漏洞插桩，甚至是修补漏洞以及自动利用等。分为3个不同的运行权限级别：指令级(Instruction level)、基本块级(Basic block level)、函数级(Function level).
* 常用工具：DynamoRIO 、Pin、frida
* ![Alt text](./fuzz学习笔记/插桩.png)
* dynamorio的工作机制是不断地去翻译被插桩程序的代码来构建基本块，然后对构建好的基本块进行操作（比如增删代码等），最后把基本块转换成二进制代码保存到code cache里面，之后被插桩程序会从code cache里面执行代码，而被插桩程序原始的代码则永远不会被执行。
* 静态插桩 参考《二进制分析实战》
  * 最简单的：直接使用jmp指令跳转到插桩指令，但由于jmp指令较长对短指令插桩时可能会破坏下一条指令。
  * int3插桩：int3 0xcc一个字节 生成软中断sigtrap，使用ptrace找到中断地址，然后调用插桩代码。但是频繁中断开销大、与调试冲突。
  * 跳板方法(trampoline)：新建代码段.text.instrum作为副本，并使用jmp指令覆盖原函数的第一条指令，使jmp跳板到副本中对应的函数。副本函数开头是一些nop指令，或指向插桩代码的jmp/call指令。插桩代码先保存状态，如寄存器内容，再运行插桩代码，最后恢复状态。  
    对于pie程序，插桩时会影响`jmp 相对偏移`指令，所以会修改相对偏移的值。
  * 缺点是对于间接跳转和switch-to语句，静态插桩可能会破坏程序。
* Pin动态插桩 
  * pin可以在指令、基本块、踪迹、函数及映像粒度上插桩。
  * pintool包含插桩程序和分析程序，插桩程序告诉pin要插桩的代码和位置，分析程序包含实际的插桩代码，在每次插桩代码序列被执行时调用。
  * 


## 工具
* 符号执行 angr 
* 模糊测试 peach(基于生成的fuzz) aflfuzz(基于覆盖引导率的fuzz) boofuzz(针对网络协议的基于生成的fuzz) mutiny-fuzzer(基于变异的协议fuzz)
* 模拟器 qemu unicorn unicorn基于qemu实现，与qemu不一样的是unicorn提供了丰富的接口，让用户可以控制并监控目标程序的执行。比如用户可以设置模拟环境中的寄存器的值，映射内存以及设置内存的值等，此外还可以通过注册事件回调函数的方式来监控代码的执行流程。
* hook frida是使用动态二进制插桩技术的基于python + java 的hook框架，常用于安卓逆向调试。动静态修改内存实现作弊一直是刚需，使用frida可以“看到”平时看不到的东西。出于编译型语言的特性，机器码在CPU和内存上执行的过程中，其内部数据的交互和跳转，对用户来讲是看不见的。当然如果手上有源码，甚至哪怕有带调试符号的可执行文件包，也可以使用gdb、lldb等调试器连上去看。那如果没有呢？如果是纯黑盒呢？又要对app进行逆向和动态调试、甚至自动化分析以及规模化收集信息的话，我们需要的是细粒度的流程控制和代码级的可定制体系，以及不断对调试进行动态纠正和可编程调试的框架，这就是frida。https://juejin.cn/post/7308240524964134924
* [WinAppDbg](https://github.com/MarioVilas/winappdbg)
* 

## Fuzz技术综述
* Fuzzing是一种高效的漏洞挖掘方法，它通过不断地让被测程序处理各种畸形测试数据来挖掘软件漏洞。
* 一个Fuzz工具由三个基础模块组成，分别是测试用例生成模块、程序执行模块以及异常检测模块。各个模块的作用以及模块间的交互如下：  
测试用例生成模块负责不断的生成测试用例，然后会把测试用例交给程序执行模块。  
程序执行模块根据被测程序接收数据的方式启动程序并把测试用例交给目标程序处理。  
异常检测模块负责监控程序在处理测试用例时是否发生异常，如果发生了异常就保存异常信息。
* Fuzz工具按照生成测试数据的方式可以分为基于生成的Fuzz工具(Generation Based Fuzzer)和基于变异的Fuzz工具(Mutation Based Fuzzer)。
* Generation Based Fuzzer通过用户提供的数据格式描述文档(比如peach的pit文件)来生成测试数据
* Mutation-Based Fuzzer通过对用户提供的初始数据进行一系列变换（比如Bit翻转，随机插入数据等）来生成测试数据
* 基于覆盖率引导的Fuzz工具（Coverage Guided Fuzzer）会在Fuzz的过程中为Fuzzer提供覆盖率信息，之后Fuzzer会将能够产生新代码覆盖率的用例保存下来用于后续的Fuzz，通过这种方式可以逐步提升Fuzzing测试的覆盖率。一般来说覆盖率越高，挖出漏洞的概率也就越大。一个比较好的样本集可以让程序在Fuzz的一开始就达到很高的覆盖率。同样Fuzz的速度越快，相同时间内Fuzz的次数也就越多，也就能测试更多的代码。
* 获取到一个高质量的初始样本集首先我们需要获取到足够数量的样本，常见的样本获取途径有以下几种：从一些提供样本集的在线站点获取；通过搜索引擎的语法爬取大量的样本文件；一些开源项目会带一些测试用例来测试程序；Fuzz其他类似软件时生成的样本文件；目标程序或者类似程序的bug提交页面；用格式转换工具生成。
  ```
  //一些常用的在线样本集获取网址
  https://files.fuzzing-project.org/
  http://samples.ffmpeg.org/
  http://lcamtuf.coredump.cx/afl/demo/
  https://github.com/MozillaSecurity/fuzzdata
  https://github.com/strongcourage/fuzzing-corpus
  https://github.com/Cisco-Talos/clamav-fuzz-corpus
  https://github.com/mozilla/pdf.js/tree/master/test/pdfs
  https://github.com/codelibs/fess-testdata
  https://github.com/google/honggfuzz/tree/master/examples/apache-httpd
  ```
* 获取到大量的测试样本后还需要对样本集进行精简，因为其中的很多样本能触发的路径是一样的，这样会导致Fuzzer可能花了大量的时间在测试同一块代码，从而降低Fuzzing效率。
* fuzz步骤
  1. 确定并分析Fuzz目标。 编写语言、是否开源、是否最新版本、是否有测试用例、项目规模、程序历史漏洞
  2. 初步运行Fuzz工具保证能够正常开始Fuzz。
  3. 收集大量初始用例并对初始用例去重。
  4. 用去重后的初始用例开始Fuzz。
  5. 在Fuzz过程中当代码覆盖率长时间没有增长时，人工介入分析代码覆盖率，想办法提升代码覆盖率。
  6. 对发现的Crash去重。

### 文件fuzz
* 从头开始实现一个基于变异的文件Fuzzer
  * 定义变异函数
    * 数据变异方式
    * 数据变异位置 随机选择 
    * 数据变异的比率 
    * 变异后的callback，如crc等
  * 使用 winappdbg 来启动程序并监控程序的执行
    1. 随机从初始样本集中选取一个样本进行变异
    2. 把生成的变异数据写入文件
    3. 然后用winappdbg启动目标程序处理数据
    4. 然后新建一个线程 timeout_killer ，这个线程在指定的超时时间后杀掉目标进程（这样做非常生硬，没有根据程序执行情况来判断，后续会优化）
    5. debugger.loop()用于等待被测进程结束
  * 优化
    * 提高fuzz速度，使程序只运行需要fuzz的相关代码或函数。
    * 使用插桩查看程序执行流，执行到无关代码时就patch为ExitProcess。
    * 监测cpu占用率，cpu占用率降至0代表执行完毕

### 协议fuzz
* 使用boofuzz描述协议格式，使用boofuzz提供的发包器和fuzz引擎，自定义服务存活检测函数以及服务重启函数，就可以开始fuzz了
* mutiny-fuzzer、decept代理服务器
  1. 首先使用decept来监听客户端和服务端的通信数据，生成一个 .fuzzer 文件。
  2. 然后 mutiny-fuzzer 基于 .fuzzer 文件来进行协议Fuzz。

### 基于hook的fuzz
* 对于一些自定义加密、压缩算法的私有协议或者交互比较复杂的协议，分析协议并构造一个fuzzer会投入很大的工作量。在服务端对接受的数据预处理完毕、正式解析之前，对数据进行变异来实现fuzz，可以简化fuzz流程和工作量。
* 使用frida进行hook

### 内存fuzz
* 内存Fuzz的原理是在内存中不断的生成测试数据，然后调用目标函数来实现Fuzz.

### syzkaller 内核fuzz

## AFL使用
* 安装AFL todo  
  Install the dependencies
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential python3-dev automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
  sudo apt-get install -y lld-11 llvm-11 llvm-11-dev clang-11 || sudo apt-get install -y lld llvm llvm-dev clang 
  sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/.* //'|sed 's/\..*//')-dev
  ```

  Checkout and build AFL++
  ```bash
  cd $HOME
  git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
  export LLVM_CONFIG="llvm-config-11"
  make distrib
  sudo make install
  ```
* afl-fuzz的编译器有afl-gcc、afl-g++、afl-clang、afl-clang++，clang为llvm_mode的编译器前端
* AFL是Coverage Guided Fuzzer的代表，AFL通过在编译时插桩来获取程序执行的覆盖率，AFL可以获取基本块覆盖率和边覆盖率。边是指从基本块A执行到基本块B，为一条边。边覆盖率比基本块覆盖率更能表示程序的执行状态，所以一般也推荐使用边覆盖率。
* AFL的forkserver机制大大提升了Fuzz的测试速度，其覆盖率反馈机制则让AFL能够自动化的生成一个质量比较高的样本集。
* AFL通过源码插桩的方式在程序的每个基本块前面插入 _afl_maybe_log 函数，当执行第一个基本块时会启动forkserver，afl-fuzz和forkserver之间通过管道通信，每当afl-fuzz生成一个测试用例，就会通知forkserver去fork一个子进程，然后子进程会从forkserver的位置继续往下执行并处理数据，而forkserver则继续等待afl-fuzz的请求
* 通过插桩，AFL可以在运行时获取到程序处理每个样本的覆盖率，AFL会把能够产生新用例的路径保存到样本队列中，这样随着Fuzzing的进行，AFL会得到一个质量比较高的样本集。
* AFL源码插桩  AFL适合对C语言源码的项目进行fuzz
* qemu二进制插桩，AFL 的 qemu 模式的实现机制是在执行基本块的和翻译基本块的前面增加一些代码来获取代码覆盖率以及启动forkserver。AFL qemu模式下默认会在可执行程序的入口点出初始化fork server并开始插桩基本块，我们可以通过环境变量来控制AFL的fork server的初始化位置(AFL_ENTRYPOINT)以及基本块插桩的范围(AFL_CODE_START、AFL_CODE_END)。在Fuzz开始时会在AFL_ENTRYPOINT启动forkserver，在之后的每次Fuzz时，程序都会从AFL_ENTRYPOINT处开始往下执行。AFL_CODE_START和AFL_CODE_END分别表示要插桩的起始位置和结束位置，afl只记录插桩代码的执行路径。
* 编写loader加载dll或so文件中的函数进行fuzz
* 内存fuzz
  * 内存Fuzz的原理是在内存中不断的生成测试数据，然后调用目标函数来实现Fuzz
  * 使用dll注入技术将目标函数hook，然后dll会将目标函数的输入在内存中不断变异来进行fuzz。建议用windbg附加进程，方便调试和查看信息。
* WinAFL会使用dynamorio来hook目标函数，当执行到被测函数时，首先执行pre_fuzz_handler，该函数会完成和AFL的通信并且会把统计覆盖率的共享内存初始化，最后退出函数继续往下会执行目标函数，执行完后会进入post_fuzz_handler，这里面会再次跳转到pre_fuzz_handler等待下次Fuzz。示例：`afl-fuzz.exe -i dwg -o dwgoutput -D C:\Users\XinSai\Desktop\winafl-master\DynamoRIO-Windows-7.91.18187-0\bin32 -t 20000 -- -coverage_module BabaCAD4Image.dll -fuzz_iterations 50000 -target_module BabaCAD4Image.dll -target_offset 0x1C20 -nargs 1 -- "C:\Program Files (x86)\IrfanView\i_view32.exe" @@`
* AFLplusplus的unicorn模式:使用unicorn来进行Fuzz的场景主要是测试一些难以正常执行的程序中的一些关键的代码片段，比如IOT固件程序，内核及TrustZone中的程序。这些类型的程序难以在常规的Linux服务器中运行，于是我们可以通过unicorn来模拟执行程序中的处理数据的高风险函数，实现程序的局部Fuzz。
  
* 使用
  1. 编译文件并插桩：afl-gcc -g -o xxx.c  
  2. 新建目录fuzz_in和fuzz_out,fuzz_in目录下新建testcase文件(testcase存放语料库)，fuzz_out存放fuzz结果
  3. 进行fuzz：afl-fuzz -i ./fuzz_in/ -o ./fuzz_out/ test  
    fuzz时不会停止，可以使用ctrl+c终止fuzz，或者使用screen命令保持执行
  4. 进入fuzz_out/crash目录
   
## AFL源码及结构
* 










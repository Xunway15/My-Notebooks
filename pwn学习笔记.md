### 注意：图片在同名文件夹下

# pwn学习笔记
* Written by <font color=red>WX</font>
* Begin:2023.12.29 
  
## 参考资料
* 《程序员的自我修养》
* [漏洞挖掘指南](https://www.theseus.top/2023/03/10/%E6%BC%8F%E6%B4%9E%E6%8C%96%E6%8E%98%E6%8C%87%E5%8D%97/) 这个链接有很多学习资料推荐
* 《0day2》
* 《Glibc内存管理:Ptmalloc2源代码分析-华庭（庄明强）》
* 《从0到1》《pwn篇》
* pwnable.kr pwnable.tw
* howtoheap
* 

## 基础知识
### 工具
* `python zuoti.py -u url_of_binary -n name`
* pwntools 
  * `from pwn import * `
  * `context.arch='amd64'` 设置系统
  * `context.log_level = 'debug'` 
  * 连接主机 执行目标文件
    ```python
    #ssh连接
    server = ssh('passcode', 'pwnable.kr', 2222, 'guest')
    io = server.process('./passcode')
    io.close()
    server.close()
    #---------------
    p = process('./elf')# 本地
    p = remote('8.8.8.8', 8888)# 远程

    ```
  * 发送和接受数据的函数
    ```python
    send(payload)发送payload；
    sendline(payload) 发送payload，并进行换行（末尾\n）；
    sendafter(some_string, payload)接收到 some_string 后，发送你的 payload；
    recvn(N) 接受 N(数字) 字符；
    recvline() 接收一行输出；
    recvlines(N)接收 N(数字) 行输出；
    recvuntil(some_string)接收到 some_string 为止。
    ```
  * 数据转换
    ```python
    # 将数据解包
    u32()
    u64()
    # 将数据打包
    p32()
    p64()
    ```
  * 编写shellcode  
    ```python
    context.arch='amd64'
    shellcode=''
    shellcode+=shellcraft.pushstr('flag')  #通过push将flag文件放入到栈里面
    shellcode += shellcraft.open('rsp',0,0)  #open打开该文件
    shellcode += shellcraft.read('rax','rsp',0x80)  #读取0x80个字节到rsp中
    shellcode += shellcraft.write(1,'rsp',0x80)  #1代表stdout，从rsp开始读取0x80个字节
    asm(shellcode)
    ```
  * elf.symbol
* 做题模板
  ```python
  from pwn import * 
  # 本地
  p = process('')
  # 远程
  p = remote('8.8.8.8', 8888)
  shellcode = ''
  p.snedline(shellcode)
  p.recv()
  p.interactive() #交互
  ```
* gdb(peda)
  * install : $ git clone https://github.com/longld/peda.git ~/peda  
              $ echo "source ~/peda/peda.py" >> ~/.gdbinit
  * [gdb使用](https://blog.csdn.net/zino00/article/details/122716412)
  * b 下断点  
    b *addr 在addr处下断点  
    delete b num 删除断点  
  * r 执行  c 继续执行
  * bt n/变量名 查看backtrace，程序的调用栈
  * s/si step 单步步入 si是汇编代码级的
  * n/ni 单步步过 
  * finish 结束函数
  * p /x $ebp 查看ebp的值; x /10x addr 查看addr地址处的内存数据
* pwndbg
  * git clone https://gitee.com/xunway_1_1165175713/pwndbg.git
  * 编辑文件~/.gdbinit
  * 

## 操作系统

### X64 ARM64 X86_64 ARM
### 大小端
* 参考[CTFwiki-heap-off by one](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/off-by-one/)
* 我们通常使用的 CPU 的字节序都是小端序的，比如一个 DWORD 值在使用小端序的内存中是这样储存的：
  ```
  DWORD 0x41424344
  内存（地址从低到高）  0x44,0x43,0x42,0x41
  ```
  gdb调试信息如下，数据和内存中存储方向不同。
  ```
  0x602000:   0x0000000000000000  0x0000000000000021 <=== chunk1
  0x602010:   0x0000000000000000  0x0000000000000000
  0x602020:   0x0000000000000000  0x0000000000000411 <=== next chunk
  ```
  在我们输入'A'*24 后执行 strcpy，copy了结尾的'\x00'，覆盖了0x602029处为0x00：
  ```
  0x602000:   0x0000000000000000  0x0000000000000021
  0x602010:   0x4141414141414141  0x4141414141414141
  0x602020:   0x4141414141414141  0x0000000000000400
  ```
### 安全保护
* **checksec** binary
  ```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
  ```
* PIE(position-independent executable, 地址无关可执行文件)，编译时PIE 开启后会随机化代码段（ .text ）、初始化数据段（ .data ）、未初始化数据段（ .bss ）的加载地址。对性能有一定影响  
  * 访问模块内数据：通过call get_pc_thunk(){ mov [esp],ecx; ret }，将当前指令地址赋值给ecx。
  * [**PIE的几种绕过**](https://www.cnblogs.com/ichunqiu/p/11350476.html)  
  1.partial write.PIE随机化只是在同一页内存进行，一页内存大小为0x1000，所以指令的低12位地址（3位十六进制）是固定的，其余地址可以通过爆破获得。  
  2.泄露地址.PIE影响的只是程序加载基址，并不会影响指令间的相对地址，因此我们如果能泄露出程序或libc的某些地址，我们就可以利用偏移来达到目的。  
  3.使用vdso/vsyscall bypass PIE ？
* ASLR（Address Space Layout Randomization，地址空间随机化）加载程序时将栈基地址（stack）、共享库（.so\libraries）、mmap 基地址、堆初始地址等进行随机化。
  * 参考链接：[ASLR是如何保护Linux系统免受缓冲区溢出攻击的](https://zhuanlan.zhihu.com/p/58419878)  
  * ASLR 的有效性依赖于整个地址空间布局是否对于攻击者保持未知。此外，只有编译时作为 位置无关可执行文件(Position Independent Executable)（PIE）的可执行程序才能得到 ASLR 技术的最大保护，因为只有这样，可执行文件的所有代码节区才会被加载在随机地址。PIE 机器码不管绝对地址是多少都可以正确执行。

机制|作用位置|如何使用|作用时间
----|:-------:|-----:|---:
ASLR|栈基地址（stack）、共享库（.so\libraries）、mmap 基地址、堆初始地址|属于操作系统的功能，sudo cat /proc/sys/kernel/randomize_va_space | 可执行文件装载时
PIE|代码段（ .text ）、初始化数据段（ .data ）、未初始化数据段（ .bss ）地址|编译器，使用 gcc 编译时加入参数-fPIE|程序每次运行时随机化地址
---

* NX
* Canary
* FUll RELRO

### Linux

* glibc 参考程序员的自我修养
  * C语言的运行库可以看作是C语言的程序和不同操作系统平台之间的抽象层，给程序员提供相同的库函数，而不必关心操作系统的实现。
  * linux下C语言运行库是glibc(GNU C library)，windows下是MSVCRT(Microsoft Visual C Run-time)，都是C语言运行库的超集，对C标准库的功能进行了一些拓展。
  * libc.so.5早期的C运行库，现在是libc.so.6即glibc，`ldd --version`查看版本。
  
* 程序装载时，由可执行文件的sections变为进程空间的segments，操作系统将权限相同的sections合并为同一个segment。
* readelf
* cat /proc/pidxxx/maps
* xxd linux查看文件的16进制内容
* 使用软链接链接flag文件 `ln -s /home/input2/flag flag`
---
* 动态链接（参考《程序员的自我修养》）
  * gcc -fPIC -shared -o Lib.so LIb.c 生成动态链接库。
  * 把链接的过程推迟到运行（装载）时再进行，由操作系统的动态链接器（ld.so）进行,其映射到进程空间，完成动态链接工作后再开始执行程序。
  * 动态链接库的装载地址（进程空间布局）在编译时不确定，装载时由装载器动态分配。
  * got表、plt表 与**符号**的关系


---
### C语言常见函数、语法
  * 常见危险函数：
    * 输入：gets，直接读取一行，忽略 '\x00'；scanf；vscanf；  
      输出：sprintf；  
      strcpy，字符串复制，遇到 '\x00' 停止；  
      strcat，字符串拼接，遇到 '\x00' 停止；  
      bcopy；  
      strlen函数遇到'\x00'停止，在计算字符串长度时是不把结束符 '\x00' 计算在内的。  
      但是strcpy 在复制字符串时会拷贝结束符 '\x00'。
  * scanf函数
    * scanf参数都为指针
    * %100s为输入100个字符，但是scanf会在字符串后自动添加一个\x00。如果输入100个字符，就会溢出\x00。
---
### **ptmolloc堆分配机制**  
  * 参考：[Linux堆内存管理深入分析-阿里聚安全](https://zhuanlan.zhihu.com/p/24753861)、Glibc内存管理:Ptmalloc2源代码分析pdf、《CTF竞赛权威指南 pwn篇》
  * 事实上 ptmalloc 分配出来的大小是对齐的。这个长度一般是字长的 2 倍，比如 32 位系统是 8 个字节(2\*4)，64 位系统是 16 个字节(2\*8)。但是对于不大于 2 倍字长的请求，malloc 会直接返回 2 倍字长的块也就是最小 chunk，比如 64 位系统执行malloc(0)会返回用户区域为 16 字节的块。注意用户区域的大小不等于 chunk_head.size，chunk_head.size = 用户区域大小 + 2 * 字长。同时还有可能使用下一个物理相邻chunk的prev_size字段。
  * ptmolloc相关实现（源码）
    * realloc(ptr,size)尝试重新调整之前调用 malloc 或 calloc 所分配的 ptr 所指向的内存块的大小
    * malloc(0x10)函数返回chunk的数据区域起始地址。
    * calloc(0x10)，calloc区别在于分配空间后会清空内存中的内容。
    * malloc_hook 函数是GNU C库（glibc）中的一个特殊函数，它可以被用来重写 malloc()、realloc()、free() 等内存管理函数的实现，从而对程序的内存分配和释放过程进行自定义的控制和监测。  
    通过设置 malloc_hook 函数指针，我们可以在程序调用 malloc()、realloc() 等函数时，先执行我们自定义的一些操作或者根据一些条件来决定是否执行标准的内存分配/释放操作，比如检测内存泄漏、记录内存分配/释放信息等等。同时，还可以将自定义的实现与标准的内存管理函数结合起来，实现更加灵活的内存管理策略。  
    在每次调用malloc和realloc，free之前，都会先调用malloc_hook，从而达到检测和自定义函数的目的。free函数也有hook，会先执行hook。
    * free函数只根据当前chunk head判断释放chunk大小和chunk前向合并大小。
    * 
  * mmap brk  
  ![函数调用关系](./pwn学习笔记/brk_and_mmap.png)
  brk更改heap空间；mmap映射物理空间到进程虚拟内存。
  * 进程内存
  ![系统内存分配图](./pwn学习笔记/prcess_mem.png)
  * main arean  
    一个进程只有一个主分配区（主线程），但可有多个非主分配区（non main arean），主分配区与非主分配区用环形链表进行管理。每一个分配区利用互斥锁（mutex）使线程对于该分配区的访问互斥。\
    主分配区可访问进程的 heap 区域和 mmap 映射区域，即主分配区可以使用 sbrk 和 mmap向操作系统申请虚拟内存。而非主分配区只能访问进程的 mmap 映射区域。
  * chunk的数据结构
    * 最小chunk大小为2\*SIZE_SZ，其中32位系统SIZE_SZ=4，64位系统SIZE_SZ=8。
    * 已分配chunk
      ![已分配chunk](./pwn学习笔记/chunk_alloced.png)  
      1. prev_size表示前一个chunk的size，程序可以使用这个值来找到前一个 chunk的开始地址。
      2. size of chunk in bytes，最后3bits空闲，分别为A、M、P。这个size包含chunk头部和用户区域。
      3. P表示**前一个块**是否分配，0表示前一个chunk空闲，这时chunk的第一个域 prev_size才有效，否则prev_size为上一个chunk的数据。
      4. A表示该chunk属于主分配区或者非主分配区，1：非主分配区，0：主分配区。
      5. M表示当前chunk是从哪个内存区域获得的虚拟内存，1：mmapped chunk，*0：heap区域*。
    * 空闲chunk
      ![空闲chunk](./pwn学习笔记/chunk_free.jpeg)
      * M位不存在
      * fd指针指向后一个空闲chunk，bk指针指向前一个空闲chunk，双向链表。指针类型是malloc_chunk*。
      * large_bin中的空闲chunk还有fd_nextsize和bk_nextsize指针
  * bins
    * 维护相似大小的chunk的双向链表称为bin。ptmalloc共维护126个bin，并用一个数组存储。
    * 数组中第1个是unsorted bin。被用户释放的 chunk 大于 max_fast（默认64bytes，是fast bins中chunk的最大大小，32位），或者 fast bins 中的空闲 chunk 合并后，会将chunk放入unsorted bin。分配时在fast bin中找不到，再到unsorted bin中找，还找不到的话会将unsorted bin的chunk放入bins，再在bins中找。unsorted bin可以看做是bins的缓冲区。，采用的遍历顺序是 FIFO，即插入的时候插入到 unsorted bin 的头部，取出的时候从链表尾获取。
    * 数组中的第2个到第63个是small bins，同一bin中chunk大小相同，相邻bin中chunk大小相差2\*SIZE_SZ，最小chunk size为4\*SIZE_SZ。最后释放的 chunk 被链接到链表的头部，而申请 chunk 是从链表尾部开始。
    * 数组中的第64个到第126个是为large bins,每个bin中chunk按大小排序。large bins分配时可以不精准匹配大小，但是fast bins和small bins需要精准匹配大小。
    * fast bins(fastbinsY)为了解决程序对较小内存的频繁需求，提高内存分配效率。fast bins中的chunk P标志位一直为1。不大于max_fast的chunk申请和释放时先在fast bins中进行。fast bins为数组，数组元素为单向链表，插入的时候插入到 fast bin 的头部，遵循LIFO（后进先出）。共有7个链表，对应small bins的前7个链表。
    * top chunk。arena的最顶部(即arean最高内存地址处，因为内存是按地址从低向高进行分配的)的空闲区域称之为top chunk。该chunk并不属于任何bin，而是在系统当前的所有free chunk(无论那种bin)都无法满足用户请求的内存大小的时候，将此chunk当做一个应急消防员，分配给用户使用。如果top chunk的大小比用户请求的大小要大的话，就将该top chunk分作两部分：1.用户请求的chunk；2.剩余的部分成为新的top chunk。否则，就需要扩展heap或分配新的heap了——在main arena中通过sbrk扩展heap，而在thread arena中通过mmap分配新的sub-heap。
    * mmaped chunk，不属于任何bin，需分配的chunk很大时，直接mmap将页映射至进程空间，free时直接将内存归还操作系统。
    * last remainder chunk。chunk拆分
  * 申请内存时
    * 尝试寻找空闲arean并获取arean的锁，否则新建non main arena。但是arean数量有限制。
    * 第一次分配前，对于主分配区，heap大小为0，brk=start_brk
      * 请求空间大小小于mmap分配阈值，就初始化heap，heap分配给用户。
      * 请求空间大小大于mmap分配阈值，直接使用mmap函数分配内存，heap未初始化。
    * 将用户申请的内存大小转化为实际需要分配的chunk大小，一般要对齐，还需要考虑chunk结构中prev_size区域。
    * 如果待分配chunk大小<max_fast，在fast bin中寻找，找到则分配结束。
    * 如果待分配chunk大小在small bins中，在对应大小的small bin中尾部取一个大小恰好相等的chunk，分配结束。
    * 到了这一步，说明需要分配大内存或者small bins中没有合适的，先遍历fast bins，将相邻的chunk合并，并链接到unsorted bin，然后遍历unsorted bin，有合适的（ unsorted bin只有一个chunk，并且这个chunk在上次分配时被使用过，并且所需分配的chunk大小属于small bins，并且chunk的大小大于等于需要分配的大小）就分配，否则将unsorted bin中的chunk放入small bins和large bins中。
    * 到了这一步，说明需要分配大内存或者unsorted bin和small bins中没有合适的，此时fast bins和unsorted bin已经清空。从large bins中按照“smallest-first best-fit”原则，找一个合适的chunk分割。
    * 以上都不满足，就操作top chunk分配，如果满足分配就分割top chunk。
    * top chunk也不满足，判断待分配chunk大小是否>=mmap分配阈值，是的话直接调用mmap分配空间（mmaped chunk）。否则主分配区调用sbrk()增大top chunk的大小，非主分配区调用mmap分配新的sub-heap，增大top chunk的大小,并在top chunk中分配。
  * 释放内存时
    * 首先获取arean的锁
    * 判断指针是否为0，是的话直接return
    * 判断chunk是否为mmaped chunk，是的话调用munmap释放，解除空间映射，return。
    * 判断chunk的位置和大小，如果大小小于max_fast，且不和top chunk相邻，则放到fast bins中，不修改P状态位，**也不和相邻chunk合并**，return。
    * 判断前后相邻chunk是否空闲，空闲则合并，并放到unsorted bin。判断合并后的chunk大小是否大于FASTBIN_CONSOLIDATION_THRESHOLD，是的话触发fast bins的合并操作malloc_consolidate：遍历fast bins中的chunk，并与相邻的空闲chunk进行合并，合并后的chunk放到unsorted bin中，fast bins将变为空。
      * 如果后相邻的chunk是top chunk，就和top chunk合并。
    * 最后判断top chunk大小是否大于mmap收缩阈值，是的话就收缩，return。
    * todo:头部信息如何更新？
* todo：各个bins大小，mmap分配空间大小，chunksize，用户使用size，等等
* todo：部分函数源码
* todo：不同版本变更
* todo:large bins

### Windows
---
## 栈
### 基本知识

### 漏洞利用

1. #### 溢出

2. #### ROP
* 面向返回的编程 oriented return program
* 使用工具 ROPgadget 查找
* 栈帧形成过程中，会将依次将参数、返回地址、esp等压栈。
* 示例：rop_chain = paddings+addr1+addr2+addr3+...
* 注意构造rop链时，返回地址应该是函数起始地址，而不是call函数的地址。因为call指令会将下一条指令压栈，破坏rop链



## 堆

### 基本知识

### 漏洞利用
1. 堆溢出 overwrite、覆写其他chunk信息
2. off by one 单字节缓冲区溢出
  * 这种漏洞的产生往往与边界验证不严和字符串操作有关，当然也不排除写入的 size 正好就只多了一个字节的情况。其中边界验证不严通常包括：1.使用循环语句向堆块中写入数据时，循环的次数设置错误（这在 C 语言初学者中很常见）导致多写入了一个字节；2.字符串操作不合适，strlen、strcpy一起使用。
    * 溢出字节为可控制任意字节
    * 溢出字节为Null字节，将下一个物理相邻的chunk的size位的P标志位清零，这样会认为前块为free块，可以使用ulink或伪造prev_size字段
  * 以下内容参考CTF竞赛权威指南：
    * 扩大被释放块，
    * 扩大使用块
    * 收缩被释放块
    * house of einherjar
3. chunk extend
  * ptmalloc中获取当前chunk大小、是否在使用，上一个chunk地址、大小，下一个chunk地址等，都是根据当前chunk head的地址、size、prev_size来进行计算。
  * 作用：控制chunk内容，利用chunk中的字符串、函数指针进行信息泄露或者执行流控制；实现chunk overlapping，控制fd、bk指针，实现其他攻击。

4. unlink 
* 目的是将空闲chunk从双向链表中取出，如free时将物理相邻的前后两个chunk合并，会将其中一个空闲chunk unlink。  
  前向后的概念如下：将previous free chunk（内存低地址）合并到当前free chunk，叫做向后合并；将next free chunk（内存高地址）合并到当前free chunk，叫做向前合并。
  ```c
  //small bins unlink
  FD=p->fd;  //定义FD
  BK=p->bk;  //定义BK
  FD->bk=BK; //修改双向链表
  BK->fd=FD; //修改双向链表
  ```
* 没有任何验证和保护时，攻击如下：
  ```c
  //通过overflow等将chunk P的fd、bk指针分别修改为target addr -12、expect value。
  FD=P->fd;  //=target addr -12;
  BK=P->bk;  //=expect value;
  FD->bk = BK;  //即 *(target addr-12+12)=BK=expect value
  //+12是bk相对于chunk p指针的偏移。这时就修改目标地址处（指针、GOT表项）的值为指定值或shellcode起始地址。
  BK->fd = FD;  //即 *(expect value +8) = FD = target addr-12
  //破坏了expect value +8处4个字节的值，如果expect value是shellcode，则需要跳过前12个字节。
  ```
* 新版本添加如下保护措施：
  ```c
  //P为要释放的chunk，判断P前后chunk的指针是否指向P
  if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                   \
    malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
  ```
  攻击如下：参考how_to_heap的unsafe_unlink。
  ```c
  global int *chunk0 = malloc(0x80);  //声明全局变量，chunk0存储在bss段
  int *chunk1 = malloc(0x80);         //申请两个small chunk
  //在chunk0中伪造一个free fake chunk，其中chunk0->fd=FD=&chunk0-3*size,chunk0->bk=BK=&chunk0-2*size，满足FD->bk=BK->fd=chunk0.
  //借助堆溢出等修改chunk1的prev_size和prev_inuse为fake chunk的信息。
  //释放chunk1，chunk1和fake chunk合并，fake chunk unlink,FD->bk=BK,BK->fd=FD等价于chunk0=&chunk0-3*size.
  //令chunk0[3] = target addr，即*(chunk0+3*size)=*(&chunk0)=target addr，相当于修改chunk0指针为target addr。
  //这时修改*chunk0的值或者chunk0[0]的值，就会修改target addr的值。
  ```
5. use after free
* 被释放后没有置null的指针称为悬挂指针(dangling pointer)
* 此时还可以对指针进行操作，就是use after free

6. fastbin attack


7. 








## 格式化字符串漏洞
* 格式化字符串
  * %d 十进制整数
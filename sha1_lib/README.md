基于c++实现的SHA1算法库  

## 使用说明

基于`cmake`编译，切换到`build`目录，执行脚本`./run.sh`即可在`lib`目录生成静态库`libsha1.a`

使用时只需要引入对应的头文件，然后就可以调用`SHA1`函数了。  
```cpp
#include "sha1.h"

unsigned char m[56] = "123";
unsigned int c[5] = { 0 };
SHA1(m,c);
for (int j = 0; j <= 4; j++) printf("%08X", c[j]);
```

## 测试
切换到`test`目录下，执行`make`命令生成`demo`的可执行程序
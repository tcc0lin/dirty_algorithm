基于c++实现的MD5算法库  

## 使用说明

基于`cmake`编译，切换到`build`目录，执行脚本`./run.sh`即可在`lib`目录生成静态库`libmd5.a`

使用时只需要引入对应的头文件，然后就可以调用`md5`函数了。  
```cpp
#include "md5.h"

md5(string)
```

## 测试
切换到`test`目录下，执行`make`命令生成`demo`的可执行程序

```bash
> echo -n "tcc0lin" | md5   
edf2ef5bfb48ca2b5f0d69a9bd47ac53
> ./demo "tcc0lin"   
md5 of 'tcc0lin': edf2ef5bfb48ca2b5f0d69a9bd47ac53
```
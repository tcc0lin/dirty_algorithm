基于c++实现的base64算法库  

## 使用说明

基于`cmake`编译，切换到`build`目录，执行脚本`./run.sh`即可在`lib`目录生成静态库`libbase64.a`

使用时只需要引入对应的头文件，然后就可以调用`base64`函数了。  
```cpp
#include "base64.h"

base64_encode(string)
```

## 测试
切换到`test`目录下，执行`make`命令生成`demo`的可执行程序

```bash
> ./demo encode lin
base64_encode of 'lin': bGlu
> ./demo decode bGlu
base64_decode of 'bGlu': lin
```
### 一、前置知识点
总体上来说，SHA1算法和MD5算法很类似，包括初始化变量以及算法流程等等，可以说SHA1是升级版本的MD5，不同的是，SHA1返回的信息长度是160位，因此相较于MD5算法来说会更加安全一些（不过也仅仅是一些而已）
### 二、算法流程
>引用：根据上面所说，MD5算法的输入是任意长度的信息，长度可以是0，也可以不是8的倍数，针对任意长度的输入，就需要通过下面的五个步骤来计算出它的MD5值
#### 1 补位
输入可以是不定长的信息，但是实际上转化到算法逻辑中时又需要根据定长的信息来计算，因此，首先需要做的就是补位操作，方法如下：
将二进制数据对512进行取模，如果有余数不等于448，则将余数补足到448的长度，补足的规则是先补1，后面全补0，相当于N*512+448的长度，N为一个非负整数（也包括0）

例如
```
# 以长度20解释
1001001001   #长度为10
10010010011000000000   #先补1后补0
```
#### 2 记录信息长度
上一步将最后的余数补充到448，距离512还相差64，这64位二进制就是用来记录信息的长度的，当然，如果信息长度超过64位，则取低64位。经过以上这两步的处理，整个输入信息的长度已经被扩充成N\*512+448+64=(N+1)\*512，即长度恰好是512的整数倍。这样做的原因是为满足后面处理中对信息长度的要求
#### 3 初始化变量
这一步引入SHA1算法中第一个关键点---初始常量（可以叫幻数、魔数或者IV），这些参数以小端字节序来表示，会参与到后续的计算，也会直接影响最终的计算结果。
```
word A: 01 23 45 67
word B: 89 ab cd ef
word C: fe dc ba 98
word D: 76 54 32 10
```
每一个变量给出的数值是高字节存于内存低地址，低字节存于内存高地址，即小端字节序。在程序中变量A、B、C、D的值分别为0x67452301，0xEFCDAB89，0x98BADCFE，0x10325476
#### 4 处理分组数据
在前两步我们将数据处理成了N*512的分组形式，下面再对每个分组进行二次分组成16份，也就是16\*32=512，每个子分组是32bit的数据

每个分组的计算流程都是一样的，简单来说如下：默认初始变量有a、b、c、d四个变量，首先以第三步的四个变量分别对其赋值，也就是
```
A = a
B = b
C = c
D = d
```
之后开始四轮的循环计算，每轮有16次操作，分别对应一个非线性函数以及子分组、常量，每次操作都会计算出a、b、c、d其中一个变量的新值作替换，这样经过四轮计算之后，a、b、c、d的值也就更新了一遍，后续的其他分组也是如此操作

下面具体讲下其中的逻辑：

首先是MD5算法中第二个关键点---非线性函数，分别是
```c
F(X,Y,Z) = XY v not(X) Z
G(X,Y,Z) = XZ v Y not(Z)
H(X,Y,Z) = X xor Y xor Z
I(X,Y,Z) = Y xor (X v not(Z))

// c++实现 F, G, H and I are basic MD5 functions.
inline MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
    return (x & y) | (~x & z);
}

inline MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
    return (x & z) | (y & ~z);
}

inline MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
    return x ^ y ^ z;
}

inline MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
    return y ^ (x | ~z);
}
```
每轮中都会使用其中一个函数来进行计算，因此函数的逻辑也直接决定最终的结果，具体使用到的地方如下
```c
// rotate_left rotates x left n bits.
inline MD5::uint4 MD5::rotate_left(uint4 x, int n) {
    return (x << n) | (x >> (32 - n));
}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline void MD5::FF(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + F(b, c, d) + x + ac, s) + b;
}

inline void MD5::GG(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + G(b, c, d) + x + ac, s) + b;
}

inline void MD5::HH(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + H(b, c, d) + x + ac, s) + b;
}

inline void MD5::II(uint4 &a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + I(b, c, d) + x + ac, s) + b;
}
```
四个函数格式相似，不同的只是引用到刚才所说的非线性函数

讲到主逻辑之前还需要提到MD5算法中第三个关键点---T常量表

它的计算方式也比较简单，之前说到计算会有4\*16=64次，因此也就需要64个常量，公式如
```
4294967296*abs(sin(i)) 
```
其中i是取值从1到64，而4294967296=2的32次方，最后计算可得出T常量表如
```c
unsigned int T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
```
还有第四个关键点---转换常量
```c
unsigned int S1[4] = {7, 12, 17, 22};
unsigned int S2[4] = {5, 9,  14, 20};
unsigned int S3[4] = {4, 11, 16, 23};
unsigned int S4[4] = {6, 10, 15, 21};
```
参与到非线性函数中循环左移的操作
主逻辑
```c
/* Round 1 */
FF(a, b, c, d, x[0], S1[0], T[0]); /* 1 */
FF(d, a, b, c, x[1], S1[1], T[1]); /* 2 */
FF(c, d, a, b, x[2], S1[2], T[2]); /* 3 */
FF(b, c, d, a, x[3], S1[3], T[3]); /* 4 */
FF(a, b, c, d, x[4], S1[0], T[4]); /* 5 */
FF(d, a, b, c, x[5], S1[1], T[5]); /* 6 */
FF(c, d, a, b, x[6], S1[2], T[6]); /* 7 */
FF(b, c, d, a, x[7], S1[3], T[7]); /* 8 */
FF(a, b, c, d, x[8], S1[0], T[8]); /* 9 */
FF(d, a, b, c, x[9], S1[1], T[9]); /* 10 */
FF(c, d, a, b, x[10], S1[2], T[10]); /* 11 */
FF(b, c, d, a, x[11], S1[3], T[11]); /* 12 */
FF(a, b, c, d, x[12], S1[0], T[12]); /* 13 */
FF(d, a, b, c, x[13], S1[1], T[13]); /* 14 */
FF(c, d, a, b, x[14], S1[2], T[14]); /* 15 */
FF(b, c, d, a, x[15], S1[3], T[15]); /* 16 */

/* Round 2 */
GG(a, b, c, d, x[1], S2[0], T[16]); /* 17 */
GG(d, a, b, c, x[6], S2[1], T[17]); /* 18 */
GG(c, d, a, b, x[11], S2[2], T[18]); /* 19 */
GG(b, c, d, a, x[0], S2[3], T[19]); /* 20 */
GG(a, b, c, d, x[5], S2[0], T[20]); /* 21 */
GG(d, a, b, c, x[10], S2[1], T[21]); /* 22 */
GG(c, d, a, b, x[15], S2[2], T[22]); /* 23 */
GG(b, c, d, a, x[4], S2[3], T[23]); /* 24 */
GG(a, b, c, d, x[9], S2[0], T[24]); /* 25 */
GG(d, a, b, c, x[14], S2[1], T[25]); /* 26 */
GG(c, d, a, b, x[3], S2[2], T[26]); /* 27 */
GG(b, c, d, a, x[8], S2[3], T[27]); /* 28 */
GG(a, b, c, d, x[13], S2[0], T[28]); /* 29 */
GG(d, a, b, c, x[2], S2[1], T[29]); /* 30 */
GG(c, d, a, b, x[7], S2[2], T[30]); /* 31 */
GG(b, c, d, a, x[12], S2[3], T[31]); /* 32 */

/* Round 3 */
HH(a, b, c, d, x[5], S3[0], T[32]); /* 33 */
HH(d, a, b, c, x[8], S3[1], T[33]); /* 34 */
HH(c, d, a, b, x[11], S3[2], T[34]); /* 35 */
HH(b, c, d, a, x[14], S3[3], T[35]); /* 36 */
HH(a, b, c, d, x[1], S3[0], T[36]); /* 37 */
HH(d, a, b, c, x[4], S3[1], T[37]); /* 38 */
HH(c, d, a, b, x[7], S3[2], T[38]); /* 39 */
HH(b, c, d, a, x[10], S3[3], T[39]); /* 40 */
HH(a, b, c, d, x[13], S3[0], T[40]); /* 41 */
HH(d, a, b, c, x[0], S3[1], T[41]); /* 42 */
HH(c, d, a, b, x[3], S3[2], T[42]); /* 43 */
HH(b, c, d, a, x[6], S3[3], T[43]); /* 44 */
HH(a, b, c, d, x[9], S3[0], T[44]); /* 45 */
HH(d, a, b, c, x[12], S3[1], T[45]); /* 46 */
HH(c, d, a, b, x[15], S3[2], T[46]); /* 47 */
HH(b, c, d, a, x[2], S3[3], T[47]); /* 48 */

/* Round 4 */
II(a, b, c, d, x[0], S4[0], T[48]); /* 49 */
II(d, a, b, c, x[7], S4[1], T[49]); /* 50 */
II(c, d, a, b, x[14], S4[2], T[50]); /* 51 */
II(b, c, d, a, x[5], S4[3], T[51]); /* 52 */
II(a, b, c, d, x[12], S4[0], T[52]); /* 53 */
II(d, a, b, c, x[3], S4[1], T[53]); /* 54 */
II(c, d, a, b, x[10], S4[2], T[54]); /* 55 */
II(b, c, d, a, x[1], S4[3], T[55]); /* 56 */
II(a, b, c, d, x[8], S4[0], T[56]); /* 57 */
II(d, a, b, c, x[15], S4[1], T[57]); /* 58 */
II(c, d, a, b, x[6], S4[2], T[58]); /* 59 */
II(b, c, d, a, x[13], S4[3], T[59]); /* 60 */
II(a, b, c, d, x[4], S4[0], T[60]); /* 61 */
II(d, a, b, c, x[11], S4[1], T[61]); /* 62 */
II(c, d, a, b, x[2], S4[2], T[62]); /* 63 */
II(b, c, d, a, x[9], S4[3], T[63]); /* 64 */
```
最终只需要将得到的a、b、c、d重新赋值再作为初始变量传递给下一分组计算即可
#### 5 输出结果
在经过分组计算后能够得到A、B、C、D，从低位字节A开始，高位字节D结束

### 总结
综合上面所讲到的SHA1算法原理，可以看出SHA1还是比较简单易懂的，与最终结果相关的正如上面所讲到的有四个关键点，理解它们的含义以及作用在后续我们对SHA1算法进行魔改的时候是很有帮助的

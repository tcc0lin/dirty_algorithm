# dirty_algorithm
>该项目的主旨是对移动安全领域常见算法的学习以及魔改方式、逆向分析方式的探究

- 一、算法学习
  - 编码格式
    - [从RFC4648中理解Base64算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC4648%E4%B8%AD%E7%90%86%E8%A7%A3Base64%E7%AE%97%E6%B3%95.md)
      - c++实现参考base64_lib 
  
  - 校验码
    - [理解CRC32算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E7%90%86%E8%A7%A3CRC32%E7%AE%97%E6%B3%95.md)
      - c++实现参考crc32_lib

  - 哈希加密
    - [从RFC1321中理解MD5算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC1321%E4%B8%AD%E7%90%86%E8%A7%A3MD5%E7%AE%97%E6%B3%95.md)
      - c++实现参考md5_lib
  
    - [从RFC3174中理解SHA1算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC3174%E4%B8%AD%E7%90%86%E8%A7%A3SHA1%E7%AE%97%E6%B3%95.md)
      - c++实现参考sha1_lib 

    - [从RFC6234中理解SHA2-256算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC6234%E4%B8%AD%E7%90%86%E8%A7%A3SHA2-256%E7%AE%97%E6%B3%95.md)
      - c++实现参考sha256_lib  
  - 对称加密
    - 分组加密
      - [从FIPS 46-3中理解DES算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8EFIPS%2046-3%E4%B8%AD%E7%90%86%E8%A7%A3DES%E7%AE%97%E6%B3%95.md)
        - c++实现参考des_lib
      
      - [从RFC2040中理解RC5算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC2040%E4%B8%AD%E7%90%86%E8%A7%A3RC5%E7%AE%97%E6%B3%95.md)
        - c++实现参考rc5_lib
    - 流加密
      - [从RFC6229中理解RC4算法](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E4%BB%8ERFC6229%E4%B8%AD%E7%90%86%E8%A7%A3RC4%E7%AE%97%E6%B3%95.md)
        - c++实现参考rc4_lib    
 
- 二、魔改思路
  - [探讨关于Base64算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8EBase64%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md)
  - [探讨关于MD5算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8EMD5%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md)
  -  [探讨关于SHA1算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8ESHA1%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md)

  -  [探讨关于SHA256算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8ESHA256%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md)
  
  -  [探讨关于RC4算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8ERC4%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md) 

  -  [探讨关于CRC32算法的魔改方式](https://github.com/tcc0lin/dirty_algorithm/blob/main/documents/%E6%8E%A2%E8%AE%A8%E5%85%B3%E4%BA%8ECRC32%E7%AE%97%E6%B3%95%E7%9A%84%E9%AD%94%E6%94%B9%E6%96%B9%E5%BC%8F.md) 

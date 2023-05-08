/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)

 based on:

 md5.h and md5.c
 reference implemantion of RFC 1321

 Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 rights reserved.

 License to copy and use this software is granted provided that it
 is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 Algorithm" in all material mentioning or referencing this software
 or this function.

 License is also granted to make and use derivative works provided
 that such works are identified as "derived from the RSA Data
 Security, Inc. MD5 Message-Digest Algorithm" in all material
 mentioning or referencing the derived work.

 RSA Data Security, Inc. makes no representations concerning either
 the merchantability of this software or the suitability of this
 software for any particular purpose. It is provided "as is"
 without express or implied warranty of any kind.

 These notices must be retained in any copies of any part of this
 documentation and/or software.

 */

/* interface header */
#include "md5.h"

/* system implementation headers */
#include <cstdio>

///////////////////////////////////////////////

// F, G, H and I are basic MD5 functions.
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

//////////////////////////////////////////////

// default ctor, just initailize
MD5::MD5() {
    init();
}

//////////////////////////////////////////////

// nifty shortcut ctor, compute MD5 for string and finalize it right away
MD5::MD5(const std::string &text) {
    init();
    update(text.c_str(), text.length());
    finalize();
}

//////////////////////////////

void MD5::init() {
    finalized = false;

    count[0] = 0;
    count[1] = 0;
}

//////////////////////////////

// decodes input (unsigned char) into output (uint4). Assumes len is a multiple of 4.
void MD5::decode(uint4 output[], const uint1 input[], size_type len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4) input[j]) | (((uint4) input[j + 1]) << 8) | (((uint4) input[j + 2]) << 16)
                | (((uint4) input[j + 3]) << 24);
}

//////////////////////////////

// encodes input (uint4) into output (unsigned char). Assumes len is
// a multiple of 4.
void MD5::encode(uint1 output[], const uint4 input[], size_type len) {
    for (size_type i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j + 1] = (input[i] >> 8) & 0xff;
        output[j + 2] = (input[i] >> 16) & 0xff;
        output[j + 3] = (input[i] >> 24) & 0xff;
    }
}

//////////////////////////////

// apply MD5 algo on a block
void MD5::transform(const uint1 block[blocksize]) {
    uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    decode(x, block, blocksize);

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

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Zeroize sensitive information.
    memset(x, 0, sizeof x);
}

//////////////////////////////

// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void MD5::update(const unsigned char input[], size_type length) {
    // compute number of bytes mod 64
    size_type index = count[0] / 8 % blocksize;

    // Update number of bits
    if ((count[0] += (length << 3)) < (length << 3)) {
        count[1]++;
    }

    count[1] += (length >> 29);

    // number of bytes we need to fill in buffer
    size_type firstpart = 64 - index;

    size_type i;

    // transform as many times as possible.
    if (length >= firstpart) {
        // fill buffer first, transform
        memcpy(&buffer[index], input, firstpart);
        transform(buffer);

        // transform chunks of blocksize (64 bytes)
        for (i = firstpart; i + blocksize <= length; i += blocksize) {
            transform(&input[i]);
        }

        index = 0;
    } else
        i = 0;

    // buffer remaining input
    memcpy(&buffer[index], &input[i], length - i);
}

//////////////////////////////

// for convenience provide a verson with signed char
void MD5::update(const char input[], size_type length) {
    update((const unsigned char*) input, length);
}

//////////////////////////////

// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
MD5& MD5::finalize() {
    static unsigned char padding[64] = { 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0 };

    if (!finalized) {
        // Save number of bits
        unsigned char bits[8];
        encode(bits, count, 8);

        // pad out to 56 mod 64.
        size_type index = count[0] / 8 % 64;
        size_type padLen = (index < 56) ? (56 - index) : (120 - index);
        update(padding, padLen);

        // Append length (before padding)
        update(bits, 8);

        // Store state in digest
        encode(digest, state, 16);

        // Zeroize sensitive information.
        memset(buffer, 0, sizeof buffer);
        memset(count, 0, sizeof count);

        finalized = true;
    }

    return *this;
}

//////////////////////////////

// return hex representation of digest as string
std::string MD5::hexdigest() const {
    if (!finalized) {
        return "";
    }

    char buf[33];
    for (int i = 0; i < 16; i++) {
        snprintf(buf + i * 2, sizeof(buf) - i * 2, "%02x", digest[i]);
    }

    return std::string(buf);
}

//////////////////////////////

std::ostream& operator<<(std::ostream& out, MD5 md5) {
    return out << md5.hexdigest();
}

//////////////////////////////

std::string md5(const std::string str) {
    MD5 md5 = MD5(str);
    return md5.hexdigest();
}

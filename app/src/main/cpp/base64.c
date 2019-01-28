/**
* 文件描述: base64编码解码的具体实现
* 作者: Created by 向定权 on 2018/5/5
* 版本号: v1.0    
* 组织名称: swifts.com.cn
* 包名: ${PACKAGE_NAME}
* 项目名称: SwiftsAES
* 版权申明: 暂无
*/
#include "base64.h"
/*****************************************************************************/
/*                         函数实现                                           */
/*****************************************************************************/

/**
 * base64编码
 * @param src 源
 * @param len 长度
 * @return 编码后的结果
 */
char *b64_encode(const unsigned char *src, size_t len) {
    int i = 0;
    int j = 0;
    char *enc = NULL;
    size_t size = 0;
    unsigned char buf[4];
    unsigned char tmp[3];

    // 分配内存
    enc = (char *) malloc(0);
    if (NULL == enc) {
        return NULL;
    }
    // 循环解析直到结束
    while (len--) {
        // 一次读三个字节到tmp中
        tmp[i++] = *(src++);
        // 编码并写入到buf中
        if (3 == i) {
            buf[0] = (tmp[0] & 0xfc) >> 2;
            buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
            buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
            buf[3] = tmp[2] & 0x3f;

            //在enc中申请四个字节的空间 然后根据索引表翻译编码后的buf的每个字节并且写入
            enc = (char *) realloc(enc, size + 4);
            for (i = 0; i < 4; ++i) {
                enc[size++] = b64_table[buf[i]];
            }
            // 重置索引
            i = 0;
        }
    }

    // 如果有剩余 也就是 0<i<3
    if (i > 0) {
        //补齐tmp剩余部分为`\0' 也就是每个位都填充0
        for (j = i; j < 3; ++j) {
            tmp[j] = '\0';
        }

        // 同样编码
        buf[0] = (tmp[0] & 0xfc) >> 2;
        buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
        buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
        buf[3] = tmp[2] & 0x3f;

        // 写人
        for (j = 0; (j < i + 1); ++j) {
            enc = (char *) realloc(enc, size + 1);
            enc[size++] = b64_table[buf[j]];
        }

        //然后在多余的地方补'='
        while ((i++ < 3)) {
            enc = (char *) realloc(enc, size + 1);
            enc[size++] = '=';
        }
    }
    // 保证有足够的空间添加字符串的结束符
    enc = (char *) realloc(enc, size + 1);
    enc[size] = '\0';
    return enc;
}
/**
 * base64解码
 * @param src 待解码的base64字符
 * @param len 长度
 * @param decsize 结果的长度
 * @return 结果
 */
unsigned char *b64_decode_ex(const char *src, size_t len, size_t *decsize) {
    int i = 0;
    int j = 0;
    int l = 0;
    size_t size = 0;
    unsigned char *dec = NULL;
    unsigned char buf[3];
    unsigned char tmp[4];

    // 分配内存
    dec = (unsigned char *) malloc(0);
    if (NULL == dec) {
        return NULL;
    }

    // 循环解析直到结束
    while (len--) {
        //如果到了'='或者不是base64字符 中断循环
        if ('=' == src[j]) {
            break;
        }
        if (!(isalnum(src[j]) || '-' == src[j] || '_' == src[j])) {
            break;
        }
        // 一次读四个字符到tmp中
        tmp[i++] = src[j++];

        // 当i=4的时候开始解码
        if (4 == i) {
            // 根据索引表翻译tmp
            for (i = 0; i < 4; ++i) {
                //在索引表中进行查找
                for (l = 0; l < 64; ++l) {
                    if (tmp[i] == b64_table[l]) {
                        tmp[i] = l;
                        break;
                    }
                }
            }
            // 解码
            buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
            buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
            buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];

            //结果写入
            dec = (unsigned char *) realloc(dec, size + 3);
            for (i = 0; i < 3; ++i) {
                dec[size++] = buf[i];
                //打印每个字节的ascii码
            }
            // 重置索引
            i = 0;
        }

    }

    // 处理剩余部分
    if (i > 0) {
        // 填充剩余部分为 `\0'
        for (j = i; j < 4; ++j) {
            tmp[j] = '\0';
        }
        // 根据索引表解码
        for (j = 0; j < 4; ++j) {
            for (l = 0; l < 64; ++l) {
                if (tmp[j] == b64_table[l]) {
                    tmp[j] = l;
                    break;
                }
            }
        }
        //解码
        buf[0] = (tmp[0] << 2) + ((tmp[1] & 0x30) >> 4);
        buf[1] = ((tmp[1] & 0xf) << 4) + ((tmp[2] & 0x3c) >> 2);
        buf[2] = ((tmp[2] & 0x3) << 6) + tmp[3];
        // 写入剩余部分
        dec = (unsigned char *) realloc(dec, size + (i - 1));
        for (j = 0; (j < i - 1); ++j) {
            dec[size++] = buf[j];

        }
    }
    dec = (unsigned char *) realloc(dec, size + 1);
    dec[size] = '\0';
    if (decsize != NULL){
        *decsize = size;
    }
    return dec;
}



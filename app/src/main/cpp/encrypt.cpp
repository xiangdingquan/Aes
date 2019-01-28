#include <jni.h>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include "base64.h"
#include "aes.h"
/*****************************************************************************/
/*                         base64                                            */
/*****************************************************************************/
/**
 * 编码
 */
extern "C"
JNIEXPORT jstring JNICALL
Java_org_xdq_aes_util_AES4CUtil_string2Base64(JNIEnv *env, jclass type,
                                                            jbyteArray buf_) {
    char *str = NULL;
    jsize alen = env->GetArrayLength(buf_);
    jbyte *ba = env->GetByteArrayElements(buf_, 0);
    str = (char *) malloc(alen + 1);
    memcpy(str, ba, alen);
    str[alen] = '\0';
    env->ReleaseByteArrayElements(buf_, ba, 0);
    char *res = b64_encode((unsigned char *) str, alen);
    // 结果转换为utf-8格式字符串
    return env->NewStringUTF(res);
}
/**
 * 解码 返回对应的一个byte数组
 */
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_org_xdq_aes_util_AES4CUtil_base642Byte(JNIEnv *env, jclass type,
                                                          jstring out_str) {
    const char *str = env->GetStringUTFChars(out_str, 0);
    size_t size = (size_t) env->GetStringUTFLength(out_str);//152
    size_t decsize = 0;
    char *result = (char *) b64_decode_ex(str, size, &decsize);
    env->ReleaseStringUTFChars(out_str, str);
    jbyteArray jbArr = env->NewByteArray(decsize);
    env->SetByteArrayRegion(jbArr, 0, decsize, (jbyte *) result);
    return jbArr;
}
/*****************************************************************************/
/*                         base64                                            */
/*****************************************************************************/

/*****************************************************************************/
/*                         AES                                               */
/*****************************************************************************/
//CBC模式初始化向量
static const uint8_t AES_IV[] = "KXTUDEdBs9zGlvy7";
static uint8_t AES_KEY[] = "abcdefgabcdefg12";
extern "C"
JNIEXPORT jstring JNICALL
Java_org_xdq_aes_util_AES4CUtil_encrypt(JNIEnv *env, jclass type, jstring src_) {
    const char *str = (char *) env->GetStringUTFChars(src_, 0);
    char *result = AES_ECB_PKCS7_Encrypt(str, AES_KEY);//AES ECB PKCS7Padding加密
    env->ReleaseStringUTFChars(src_, str);
    //char *result = AES_CBC_PKCS7_Encrypt(str, AES_KEY, AES_IV);//AES CBC PKCS7Padding加密
    return env->NewStringUTF(result);
}
extern "C"
JNIEXPORT jstring JNICALL
Java_org_xdq_aes_util_AES4CUtil_decrypt(JNIEnv *env, jclass type, jstring encrypted_) {
    const char *str = (char *) env->GetStringUTFChars(encrypted_, 0);
    const char *result = AES_ECB_PKCS7_Decrypt(str, AES_KEY);//AES ECB PKCS7Padding解密
    env->ReleaseStringUTFChars(encrypted_, str);
    //char *result = AES_CBC_PKCS7_Decrypt(str, AES_KEY, AES_IV);//AES CBC PKCS7Padding解密
    return env->NewStringUTF(result);
}
/*****************************************************************************/
/*                         AES                                               */
/*****************************************************************************/

/*****************************************************************************/
/*                         密钥 get set                                      */
/****************************************************************************/
/**
 * 重新设置密钥 key
 * @param key java层传输进来的key
 */
void setKey(unsigned char *_key, size_t size) {
    for (int i = 0; i < size; i++) {//元素复制
        if (i > sizeof(AES_KEY) / sizeof(AES_KEY[0]) - 1)
            break;
        AES_KEY[i] = *_key;
        _key++;
    }
    for (int i = size; i < 16; i++) {//补齐key
        AES_KEY[i] = 0x30;
    }
    AES_KEY[16] = '\0';//结束符
}
/**
 * 给java层返回密钥
 */
extern "C"
JNIEXPORT jstring JNICALL
Java_org_xdq_aes_util_AES4CUtil_getAESKey(JNIEnv *env, jclass type) {
    return env->NewStringUTF((const char *) AES_KEY);
}
/**
 * java层接口设置密钥
 */
extern "C"
JNIEXPORT void JNICALL
Java_org_xdq_aes_util_AES4CUtil_setAESKey(JNIEnv *env, jclass type, jstring key_) {
    unsigned char *_key = (unsigned char *) env->GetStringUTFChars(key_, 0);
    //获取key的长度
    size_t size = (size_t) env->GetStringUTFLength(key_);
    setKey(_key, size);
    env->ReleaseStringUTFChars(key_, (char *) _key);
}
/*****************************************************************************/
/*                         密钥 get set                                      */
/****************************************************************************/
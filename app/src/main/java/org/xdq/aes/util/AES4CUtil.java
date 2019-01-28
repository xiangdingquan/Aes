package org.xdq.aes.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 文件描述: 调用native层实现 base64 和 EAS
 * 作者: Created by 向定权 on 2019/1/28
 * 版本号：v1.0
 * 组织名称: wimetro.com
 * 包名：org.xdq.aes.util
 * 项目名称：Aes
 * 版权申明：暂无
 */
public class AES4CUtil {

    static {
        System.loadLibrary("encrypt");
    }

    /**
     * base64编码
     * @param buf 待编码字节
     * @return 结果
     */
    public static native String string2Base64(byte[] buf) throws UnsupportedEncodingException;

    /**
     * base64解码
     * @param hexString 待解码字符串
     * @return 结果
     */
    public static native byte[] base642Byte(String hexString);

    /**
     * AES加密
     * @param src 待加密字符串
     * @return 结果
     */
    public static native String encrypt(String src) throws UnsupportedEncodingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;

    /**
     * AES解密
     * @param encrypted 待解密串
     * @return 结果
     */
    public static native String decrypt(String encrypted) throws IOException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException;

    /**
     * 获取native 层密钥
     * @return 密钥
     */
    public static native String getAESKey();

    /**
     * 设置native层密钥
     * @param key 密钥
     */
    public static native void setAESKey(String key);
}

package org.xdq.aes.util;

import android.util.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @version V1.0
 * @desc AES 加密工具类
 */
public class AESUtil {

    private static final String PASSWORD = "abcdefgabcdefg12";
    private final static String HEX = "0123456789ABCDEF";
    private static final int KEY_LENGTH = 16;
    private static final String DEFAULT_V = "0";
    private static final String CHARSET_NAME = "utf-8";
    private static final String ALGORITHM = "AES";
    private static final String CIPHER = "AES/ECB/PKCS7Padding";

    /**
     * 加密
     *
     * @param src 加密文本
     * @return
     * @throws Exception
     */
    public static String encrypt(String src) throws UnsupportedEncodingException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] rawKey = toMakekey(PASSWORD, KEY_LENGTH, DEFAULT_V).getBytes();// key.getBytes();
        byte[] result = encrypt(rawKey, src.getBytes(CHARSET_NAME));
        return StringToBase64(result);
    }


    /**
     * 解密
     *
     * @param encrypted 待揭秘文本
     * @return
     * @throws Exception
     */
    public static String decrypt(String encrypted) throws IOException,
            IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] rawKey = toMakekey(PASSWORD, KEY_LENGTH, DEFAULT_V).getBytes();// key.getBytes();
        byte[] enc = Base64ToByte(encrypted);
        byte[] result = decrypt(rawKey, enc);
        return new String(result, CHARSET_NAME);
    }

    /**
     * 密钥key ,默认补的数字，补全16位数，以保证安全补全至少16位长度,android和ios对接通过
     *
     * @param str
     * @param strLength
     * @param val
     * @return
     */
    private static String toMakekey(String str, int strLength, String val) {

        int strLen = str.length();
        if (strLen < strLength) {
            while (strLen < strLength) {
                StringBuffer buffer = new StringBuffer();
                buffer.append(str).append(val);
                str = buffer.toString();
                strLen = str.length();
            }
        }
        return str;
    }

    /**
     * 真正的加密过程
     * 1.通过密钥得到一个密钥专用的对象SecretKeySpec
     * 2.Cipher 加密算法，加密模式和填充方式三部分或指定加密算 (可以只用写算法然后用默认的其他方式)Cipher.getInstance("AES");
     *
     * @param key
     * @param src
     * @return
     * @throws Exception
     */
    private static byte[] encrypt(byte[] key, byte[] src) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(src);
        return encrypted;
    }

    /**
     * 真正的解密过程
     *
     * @param key
     * @param encrypted
     * @return
     * @throws Exception
     */
    private static byte[] decrypt(byte[] key, byte[] encrypted) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    public static byte[] Base64ToByte(String hexString) {
        return Base64.decode(hexString, Base64.URL_SAFE);
    }

    public static String StringToBase64(byte[] buf) throws UnsupportedEncodingException {
        return new String(Base64.encode(buf, Base64.URL_SAFE), CHARSET_NAME).replaceAll("\n", "");
    }
}
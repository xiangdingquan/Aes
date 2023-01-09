package org.xdq.aes;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import org.xdq.aes.util.AES4CUtil;
import org.xdq.aes.util.AESUtil;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends Activity {


    public static final String MSG = "this is test message !!!";
    private TextView mTVBase64Java;
    private TextView mTVBase64Jni;
    private EditText mSrc;
    private TextView mTVAESJava;
    private TextView mTVAESJni;
    private EditText mKey;
    private EditText mShowKey;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initViews();
        initListeners();
    }

    private void initViews() {
        mSrc = findViewById(R.id.et_src);
        mSrc.setText(MSG);//设置默认值
        mTVBase64Java = findViewById(R.id.tv_base64_java);
        mTVBase64Jni = findViewById(R.id.tv_base64_jni);
        mTVAESJava = findViewById(R.id.tv_aes_java);
        mTVAESJni = findViewById(R.id.tv_aes_jni);
        mKey = findViewById(R.id.et_key);
        mShowKey = findViewById(R.id.show_key);
    }

    private void initListeners() {
        //java版本base64编码
        findViewById(R.id.bt_base64_encode_java).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVBase64Java.setText(AESUtil.StringToBase64(mSrc.getText().toString().trim().getBytes()));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });
        //java版本base64解码
        findViewById(R.id.bt_base64_decode_java).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVBase64Java.setText(new String(AESUtil.Base64ToByte(AESUtil.StringToBase64(mSrc.getText().toString().trim().getBytes())), "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });
        //jni版本base64编码
        findViewById(R.id.bt_base64_encode_jni).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVBase64Jni.setText(AES4CUtil.string2Base64(mSrc.getText().toString().trim().getBytes()));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });
        //jni版本base64解码
        findViewById(R.id.bt_base64_decode_jni).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVBase64Jni.setText(new String(AES4CUtil.base642Byte(AES4CUtil.string2Base64(mSrc.getText().toString().trim().getBytes()))));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }
        });
        //java版本AES加密
        findViewById(R.id.bt_java_encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVAESJava.setText(AESUtil.encrypt(mSrc.getText().toString().trim()));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
            }
        });
        //java版本AES解密
        findViewById(R.id.bt_java_decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVAESJava.setText(AESUtil.decrypt(AESUtil.encrypt(mSrc.getText().toString().trim())));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        //jni版本AES加密
        findViewById(R.id.bt_jni_encrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVAESJni.setText(AES4CUtil.encrypt(mSrc.getText().toString().trim()));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
            }
        });
        //jni版本AES解密
        findViewById(R.id.bt_jni_decrypt).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    mTVAESJni.setText(AES4CUtil.decrypt(AES4CUtil.encrypt(mSrc.getText().toString().trim())));
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
            }
        });

        //设置密钥
        findViewById(R.id.bt_set_key).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                AES4CUtil.setAESKey(mKey.getText().toString().trim());
            }
        });
        //获取native层密钥
        findViewById(R.id.bt_get_key).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                mShowKey.setText(AES4CUtil.getAESKey());
            }
        });

    }
}

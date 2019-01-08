package com.boy.learning;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.boy.learning.aes.AesUtils;

public class MainActivity extends AppCompatActivity {
    private static String TAG = "tag";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        //ase加密算法适配9.0
        aes();
    }

    /**
     * ase加密算法适配9.0
     */
    private void aes() {
        String encryStr = AesUtils.encrypt("12345678", "走向全栈工程师");
        Log.d(TAG, "走向全栈工程师加密:" + encryStr);
        String decryStr = AesUtils.decrypt("12345678", encryStr);
        Log.d(TAG, encryStr + "解密:" + decryStr);
    }
}

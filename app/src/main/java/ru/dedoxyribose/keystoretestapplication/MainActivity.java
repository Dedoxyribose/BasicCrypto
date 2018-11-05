package ru.dedoxyribose.keystoretestapplication;

import android.content.SharedPreferences;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "TAG";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        SharedPreferences sharedPreferences = getSharedPreferences("o1", MODE_PRIVATE);

        BasicCrypto basicCrypto = new BasicCrypto(this);

        basicCrypto.init();


        //----

        /*String str = "alala"+Math.random()*100;
        byte [] encrypted = basicCrypto.encrypt(str);


        SharedPreferences.Editor ed = sharedPreferences.edit();
        ed.putString("code", Base64.encodeToString(encrypted, Base64.DEFAULT));
        ed.commit();

        Toast.makeText(this, "encrypted: "+str, Toast.LENGTH_SHORT).show();*/

        //----

        byte[] array = Base64.decode(sharedPreferences.getString("code", null), Base64.DEFAULT);

        String decrypted = basicCrypto.decrypt(array);

        Toast.makeText(this, "decrypted: "+decrypted, Toast.LENGTH_SHORT).show();



    }
}

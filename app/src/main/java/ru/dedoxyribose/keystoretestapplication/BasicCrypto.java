package ru.dedoxyribose.keystoretestapplication;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import static android.content.ContentValues.TAG;

/**
 * Created by Ryan on 26.04.2017.
 */

public class BasicCrypto {

    private Context mContext;

    private PrivateKey mPrivateKey;
    private PublicKey mPublicKey;

    private static final String KEY_ALIAS="a187590";

    private boolean mInitialized = false;

    public BasicCrypto(@NonNull Context context) {
        this.mContext = context;
    }

    public boolean init() {

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            int nBefore = keyStore.size();

            // Create the keys if necessary
            if (!keyStore.containsAlias(KEY_ALIAS)) {

                Calendar notBefore = Calendar.getInstance();
                Calendar notAfter = Calendar.getInstance();
                notAfter.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                        .setAlias(KEY_ALIAS)
                        //.setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
                        //.setKeySize(2048)
                        .setSubject(new X500Principal("CN=test"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(notBefore.getTime())
                        .setEndDate(notAfter.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();

            }
            int nAfter = keyStore.size();
            Log.v(TAG, "Before = " + nBefore + " After = " + nAfter);

            // Retrieve the keys
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(KEY_ALIAS, null);
            mPrivateKey =  privateKeyEntry.getPrivateKey();
            mPublicKey = privateKeyEntry.getCertificate().getPublicKey();



        } catch (NoSuchAlgorithmException | UnsupportedOperationException| UnrecoverableEntryException | IOException | CertificateException | InvalidAlgorithmParameterException | KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        } catch (NoSuchProviderException e) {
            Log.e(TAG, Log.getStackTraceString(e));
            return false;
        }


        mInitialized = true;
        return true;

    }

    public byte[] encrypt(String text) {

        if (!mInitialized) throw new IllegalStateException("not initialized");

        try {
            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            inCipher.init(Cipher.ENCRYPT_MODE, mPublicKey);
            return inCipher.doFinal(text.getBytes("UTF-16"));
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | UnsupportedEncodingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

        return null;
    }


    public String decrypt(byte [] arr) {

        if (!mInitialized) throw new IllegalStateException("not initialized");

        try {
            Cipher outCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            outCipher.init(Cipher.DECRYPT_MODE, mPrivateKey);
            return new String(outCipher.doFinal(arr), "UTF-16");
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /*public void test1() {

        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            String alias = "key5";

            int nBefore = keyStore.size();

            // Create the keys if necessary
            if (!keyStore.containsAlias(alias)) {

                Calendar notBefore = Calendar.getInstance();
                Calendar notAfter = Calendar.getInstance();
                notAfter.add(Calendar.YEAR, 1);
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(mContext)
                        .setAlias(alias)
                        //.setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
                        //.setKeySize(2048)
                        .setSubject(new X500Principal("CN=test"))
                        .setSerialNumber(BigInteger.ONE)
                        .setStartDate(notBefore.getTime())
                        .setEndDate(notAfter.getTime())
                        .build();
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                KeyPair keyPair = generator.generateKeyPair();

                Log.v(TAG, "Bef 1111");

            }
            int nAfter = keyStore.size();
            Log.v(TAG, "Before = " + nBefore + " After = " + nAfter);

            // Retrieve the keys
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            PrivateKey privateKey = (PrivateKey) privateKeyEntry.getPrivateKey();
            PublicKey publicKey = (PublicKey) privateKeyEntry.getCertificate().getPublicKey();

            Log.v(TAG, "private key = " + privateKey.toString());
            Log.v(TAG, "public key = " + publicKey.toString());

            // Encrypt the text
            String plainText = "This text is supposed to be a secret!";
            String dataDirectory = mContext.getApplicationInfo().dataDir;
            String filesDirectory = mContext.getFilesDir().getAbsolutePath();
            String encryptedDataFilePath = filesDirectory + File.separator + "keep_yer_secrets_here";

            Log.v(TAG, "plainText = " + plainText);
            Log.v(TAG, "dataDirectory = " + dataDirectory);
            Log.v(TAG, "filesDirectory = " + filesDirectory);
            Log.v(TAG, "encryptedDataFilePath = " + encryptedDataFilePath);

            Cipher inCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            Cipher outCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            outCipher.init(Cipher.DECRYPT_MODE, privateKey);


                byte[] encodedBytes = inCipher.doFinal(plainText.getBytes("UTF-16"));
                String encryptedBase64Encoded = new String(encodedBytes, "UTF-16");

                Log.d(TAG, "str.len="+encryptedBase64Encoded.length());
                Log.d(TAG, "encodedBytes.length="+encodedBytes.length);
                Log.d(TAG, "2.length="+encryptedBase64Encoded.getBytes("UTF-16").length);

                byte[] decodedBytes = outCipher.doFinal(encodedBytes);
                String decryptedBase64Encoded = new String(decodedBytes, "UTF-16");

                Toast.makeText(mContext, encryptedBase64Encoded, Toast.LENGTH_SHORT).show();
                Toast.makeText(mContext, decryptedBase64Encoded, Toast.LENGTH_SHORT).show();





        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (NoSuchProviderException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (InvalidAlgorithmParameterException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (KeyStoreException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (CertificateException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (IOException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (UnrecoverableEntryException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (NoSuchPaddingException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (InvalidKeyException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (UnsupportedOperationException e) {
            Log.e(TAG, Log.getStackTraceString(e));
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }*/


}

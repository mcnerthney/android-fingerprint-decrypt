/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.softllc.android.fingerprintdialog;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;


import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.inject.Inject;

/**
 * Main entry point for the sample, showing a backpack and "Purchase" button.
 */
public class MainActivity extends Activity {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";

    /** Alias for our key in the Android Key Store */
    private static final String KEY_NAME = "com.softllc.password.key";
    private static final String KEY_PASSWORD = "EncryptedPassword";
    private static final String KEY_PASSWORD_IV = "EncryptedPasswordIV";

    @Inject KeyguardManager mKeyguardManager;
    @Inject FingerprintManager mFingerprintManager;
    @Inject FingerprintAuthenticationDialogFragment mFragment;
    @Inject KeyStore mKeyStore;
    @Inject KeyGenerator mKeyGenerator;
    @Inject Cipher mEncryptCipher;
    @Inject Cipher mDecryptCipher;
    @Inject SharedPreferences mSharedPreferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ((InjectedApplication) getApplication()).inject(this);

        setContentView(R.layout.activity_main);
        Button purchaseButton = (Button) findViewById(R.id.purchase_button);
        if (!mKeyguardManager.isKeyguardSecure()) {
            // Show a message that the user hasn't set up a fingerprint or lock screen.
            Toast.makeText(this,
                    "Secure lock screen hasn't set up.\n"
                            + "Go to 'Settings -> Security -> Fingerprint' to set up a fingerprint",
                    Toast.LENGTH_LONG).show();
            purchaseButton.setEnabled(false);
            return;
        }

        //noinspection ResourceType
        if (!mFingerprintManager.hasEnrolledFingerprints()) {
            purchaseButton.setEnabled(false);
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }


        purchaseButton.setEnabled(true);
        purchaseButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                findViewById(R.id.confirmation_message).setVisibility(View.GONE);
                findViewById(R.id.encrypted_message).setVisibility(View.GONE);

                if ( initEncryptCipher() ) {
                    mFragment.setEncryptCipher(mEncryptCipher);

                    if (mSharedPreferences.getString(KEY_PASSWORD, "") != "") {
                        if (initDecryptCipher()) {

                            // Show the fingerprint dialog to unlock the password
                            mFragment.setDecryptCipher(mDecryptCipher);

                            mFragment.setStage(FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT_DECRYPT);
                            mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
                            return;
                        }
                    }
                }

                mFragment.setStage(FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
                mFragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);

            }
        });
    }

     private boolean initEncryptCipher() {

        mEncryptCipher = getCipher(Cipher.ENCRYPT_MODE);
         if ( mEncryptCipher == null ) {
             // try again after recreating the keystore
             createKey();
             mEncryptCipher = getCipher(Cipher.ENCRYPT_MODE);
         }
        return ( mEncryptCipher != null) ;

    }

    public boolean initDecryptCipher() {
        mDecryptCipher = getCipher(Cipher.DECRYPT_MODE);
        return ( mDecryptCipher != null) ;
    }

    public void onPurchased(String password, boolean bDecrypt, boolean bEncrypt) {
        showConfirmation(password + (bDecrypt ? " (fingerprint decrypt)":"") + (bEncrypt ? " (fingerprint encrypt)":""));
    }

    // Show confirmation, - show the plain text password
    private void showConfirmation(String password) {

        findViewById(R.id.confirmation_message).setVisibility(View.VISIBLE);
        if (password != null) {
            TextView v = (TextView) findViewById(R.id.encrypted_message);
            v.setVisibility(View.VISIBLE);
            v.setText(password);
        }
    }

    /**
     * Tries to encrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    public boolean tryEncrypt(String secert) {
        try {

            byte[] encrypted = mEncryptCipher.doFinal(secert.getBytes());

            IvParameterSpec ivParams = mEncryptCipher.getParameters().getParameterSpec(IvParameterSpec.class);
            String iv = Base64.encodeToString(ivParams.getIV(), Base64.DEFAULT);

            SharedPreferences.Editor editor = mSharedPreferences.edit();
            editor.putString(KEY_PASSWORD, Base64.encodeToString(encrypted, Base64.DEFAULT));
            editor.putString(KEY_PASSWORD_IV, iv);
            editor.commit();
            return true;



        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Toast.makeText(this, "Failed to encrypt the data with the generated key. "
                    + "Retry the purchase", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to encrypt the data with the generated key." + e.getMessage());
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Tries to decrypt some data with the generated key in {@link #createKey} which is
     * only works if the user has just authenticated via fingerprint.
     */
    public String tryDecrypt() {
        try {

            byte[] encodedData = Base64.decode(mSharedPreferences.getString(KEY_PASSWORD, ""), Base64.DEFAULT);
            byte[] decodedData = mDecryptCipher.doFinal(encodedData);
            return new String(decodedData);

        } catch (BadPaddingException | IllegalBlockSizeException e) {
            Toast.makeText(this, "Failed to decrypt the data with the generated key. "
                    + "Retry the purchase", Toast.LENGTH_LONG).show();
            Log.e(TAG, "Failed to decrypt the data with the generated key." + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    private SecretKey getKey() {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey)mKeyStore.getKey(KEY_NAME, null);
            if ( key != null) return key;
            return createKey();

        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    private SecretKey createKey() {
        try {

            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            // Require the user to authenticate with a fingerprint to authorize every use
                            // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            return mKeyGenerator.generateKey();

        }
        catch(Exception e) {

        }
        return null;
    }



    public Cipher getCipher(int mode) {
        Cipher cipher;

        try {
            mKeyStore.load(null);
            byte[] iv;
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            IvParameterSpec ivParams;
            if(mode == Cipher.ENCRYPT_MODE) {
                cipher.init(mode, getKey());

            }
            else {
                SecretKey key = (SecretKey)mKeyStore.getKey(KEY_NAME, null);
                iv = Base64.decode(mSharedPreferences.getString(KEY_PASSWORD_IV, ""), Base64.DEFAULT);
                ivParams = new IvParameterSpec(iv);
                cipher.init(mode, key, ivParams);
            }
            return cipher;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}

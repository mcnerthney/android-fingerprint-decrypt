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
import android.app.DialogFragment;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import javax.crypto.Cipher;
import javax.inject.Inject;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to password
 * authentication if fingerprint is not available.
 */
public class FingerprintAuthenticationDialogFragment extends DialogFragment
        implements TextView.OnEditorActionListener, FingerprintUiHelper.Callback {

    private View mView;
    private Button mCancelButton;
    private Button mSecondDialogButton;
    private View mFingerprintEncrypt;
    private View mFingerprintDecrypt;
    private View mBackupContent;
    private EditText mPassword;
    private CheckBox mUseFingerprintFutureCheckBox;
    private TextView mPasswordDescriptionTextView;
    private TextView mNewFingerprintEnrolledTextView;

    private Stage mStage = Stage.FINGERPRINT_DECRYPT;

    private Cipher mEncryptCipher;
    private Cipher mDecryptCipher;
    private FingerprintUiHelper mFingerprintUiHelper;
    private MainActivity mActivity;

    @Inject FingerprintUiHelper.FingerprintUiHelperBuilder mFingerprintUiHelperBuilder;
    @Inject InputMethodManager mInputMethodManager;
    @Inject SharedPreferences mSharedPreferences;

    @Inject
    public FingerprintAuthenticationDialogFragment() {}

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
            Bundle savedInstanceState) {
        getDialog().setTitle(getString(R.string.sign_in));
        View v = mView = inflater.inflate(R.layout.fingerprint_dialog_container, container, false);
        mCancelButton = (Button) mView.findViewById(R.id.cancel_button);
        mCancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                dismiss();

                if ( mStage == Stage.FINGERPRINT_ENCRYPT ) {
                    // purchase without saving the password
                    mActivity.onPurchased(mPassword.getText().toString(), false, false);
                }
            }
        });

        mSecondDialogButton = (Button) mView.findViewById(R.id.second_dialog_button);
        mSecondDialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                switch (mStage) {
                    case FINGERPRINT_DECRYPT:
                        enterPassword();
                        break;
                    case PASSWORD:
                        verifyPassword();
                        break;
                }
            }
        });
        mFingerprintEncrypt = v.findViewById(R.id.fingerprint_encrypt_container);
        mFingerprintDecrypt = v.findViewById(R.id.fingerprint_decrypt_container);
        mBackupContent = v.findViewById(R.id.backup_container);
        mPassword = (EditText) v.findViewById(R.id.password);
        mPassword.setOnEditorActionListener(this);
        mPasswordDescriptionTextView = (TextView) v.findViewById(R.id.password_description);
        mUseFingerprintFutureCheckBox = (CheckBox)
                v.findViewById(R.id.use_fingerprint_in_future_check);
        mNewFingerprintEnrolledTextView = (TextView)
                v.findViewById(R.id.new_fingerprint_enrolled_description);

        updateStage();

        // If fingerprint authentication is not available, switch immediately to the backup
        // (password) screen.
        mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                (ImageView) mView.findViewById(R.id.fingerprint_icon_decrypt),
                (TextView) mView.findViewById(R.id.fingerprint_status_decrypt), this);

        if (!mFingerprintUiHelper.isFingerprintAuthAvailable()) {
            enterPassword();
        }
        return v;
    }

    @Override
    public void onResume() {
        super.onResume();
        mFingerprintUiHelper.stopListening();
        if (mStage == Stage.FINGERPRINT_ENCRYPT ) {
            mFingerprintUiHelper.startListening(new FingerprintManager.CryptoObject(mEncryptCipher));
        }
        if ( mStage == Stage.FINGERPRINT_DECRYPT ) {
            mFingerprintUiHelper.startListening(new FingerprintManager.CryptoObject(mDecryptCipher));
        }
    }
    public void setStage(Stage stage) {
        mStage = stage;
    }

    @Override
    public void onPause() {
        super.onPause();
        mFingerprintUiHelper.stopListening();
    }

    @Override
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        mActivity = (MainActivity) activity;
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setDecryptCipher(Cipher cipher) {
        mDecryptCipher = cipher;
    }

    /**
     * Sets the crypto object to be passed in when authenticating with fingerprint.
     */
    public void setEncryptCipher(Cipher cipher) {
        mEncryptCipher = cipher;
    }
    /**
     * Switches to backup (password) screen. This either can happen when fingerprint is not
     * available or the user chooses to use the password authentication method by pressing the
     * button. This can also happen when the user had too many fingerprint attempts.
     */
    private void enterPassword() {
        mStage = Stage.PASSWORD;
        updateStage();
        mPassword.requestFocus();

        // Show the keyboard.
        mPassword.postDelayed(mShowKeyboardRunnable, 500);

        // Fingerprint is not used anymore. Stop listening for it.
        mFingerprintUiHelper.stopListening();
    }

    /**
     * Checks whether the current entered password is correct, and dismisses the the dialog and
     * let's the activity know about the result.
     */
    private void verifyPassword() {
        if (!checkPassword(mPassword.getText().toString())) {
            return;
        }
        if (mStage == Stage.PASSWORD) {
            mStage = Stage.FINGERPRINT_ENCRYPT;
            updateStage();
            mFingerprintUiHelper.stopListening();
            mFingerprintUiHelper.startListening(new FingerprintManager.CryptoObject(mEncryptCipher));
            return;
        }

        //mPassword.setText("");
        mActivity.onPurchased(mPassword.getText().toString(), false, false);
        dismiss();
    }

    /**
     * @return true if {@code password} is correct, false otherwise
     */
    private boolean checkPassword(String password) {
        // Assume the password is always correct.
        // In the real world situation, the password needs to be verified in the server side.
        return true;
    }

    private final Runnable mShowKeyboardRunnable = new Runnable() {
        @Override
        public void run() {
            mInputMethodManager.showSoftInput(mPassword, 0);
        }
    };

    private void updateStage() {
        switch (mStage) {
            case FINGERPRINT_DECRYPT:
                mCancelButton.setText(R.string.cancel);
                mSecondDialogButton.setText(R.string.use_password);
                mFingerprintDecrypt.setVisibility(View.VISIBLE);
                mFingerprintEncrypt.setVisibility(View.GONE);
                mBackupContent.setVisibility(View.GONE);
                mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                        (ImageView) mView.findViewById(R.id.fingerprint_icon_decrypt),
                        (TextView) mView.findViewById(R.id.fingerprint_status_decrypt), this);
                break;
            case FINGERPRINT_ENCRYPT:
                mCancelButton.setText(R.string.cancel);
                mSecondDialogButton.setVisibility(View.GONE);
                mFingerprintEncrypt.setVisibility(View.VISIBLE);
                mFingerprintDecrypt.setVisibility(View.GONE);
                mBackupContent.setVisibility(View.GONE);
                mFingerprintUiHelper = mFingerprintUiHelperBuilder.build(
                        (ImageView) mView.findViewById(R.id.fingerprint_icon),
                        (TextView) mView.findViewById(R.id.fingerprint_status), this);
                break;

            case PASSWORD:
                mCancelButton.setText(R.string.cancel);
                mSecondDialogButton.setText(R.string.ok);
                mFingerprintEncrypt.setVisibility(View.GONE);
                mFingerprintDecrypt.setVisibility(View.GONE);
                mBackupContent.setVisibility(View.VISIBLE);
                break;
        }
    }

    @Override
    public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
        if (actionId == EditorInfo.IME_ACTION_GO) {
            verifyPassword();
            return true;
        }
        return false;
    }

    @Override
    public void onAuthenticated(Cipher cipher) {
        // Callback from FingerprintUiHelper. Let the activity know that authentication was
        // successful.

        boolean bEncrypt = false;
        String password = mPassword.getText().toString();
        if ( mStage == Stage.FINGERPRINT_ENCRYPT ) {

            //encrypt the password, so they don't have to reenter it.
            bEncrypt = mActivity.tryEncrypt(mPassword.getText().toString());

        }
        if ( mStage == Stage.FINGERPRINT_DECRYPT) {
            password = mActivity.tryDecrypt();
        }

        mActivity.onPurchased(password, mStage == Stage.FINGERPRINT_DECRYPT, bEncrypt );

        mPassword.setText("");
        dismiss();
    }

    @Override
    public void onError() {

        enterPassword();
    }

    /**
     * Enumeration to indicate which authentication method the user is trying to authenticate with.
     */
    public enum Stage {

        FINGERPRINT_ENCRYPT,
        FINGERPRINT_DECRYPT,
        PASSWORD
    }
}

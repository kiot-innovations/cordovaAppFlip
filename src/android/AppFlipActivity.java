package com.appflip.plugin;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.nfc.NdefMessage;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Toast;

import androidx.annotation.Nullable;

import com.chariotsolutions.nfc.plugin.NfcPlugin;

import org.json.JSONException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Map;


public class AppFlipActivity extends Activity {

    private static String TAG = "AppFlipLogs";
    private String clientId, scopes, redirectUri;
    private static final String EXTRA_APP_FLIP_CLIENT_ID = "CLIENT_ID";
    private static final String EXTRA_APP_FLIP_SCOPES = "SCOPE";
    private static final String EXTRA_APP_FLIP_REDIRECT_URI = "REDIRECT_URI";
    private static final String SIGNATURE_DIGEST_ALGORITHM = "SHA-256";
    static Intent result = new Intent();
    private String callingAppPackageName = "com.google.android.googlequicksearchbox";
    private String callingAppFingerprint = "F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83";

    private static final int MAINACTIVITY_RESULT_INTENT = 105;

    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setWindowParams();
        try {
            Intent intent = getIntent();
            final Context context = getApplicationContext();
            ComponentName callingActivity = getCallingActivity();

            if (!validateCallingApp(callingActivity)) {
                Toast.makeText(context, "Sender cert or name mismatch!", Toast.LENGTH_LONG).show();
                Log.e(TAG, "Intent sender certificate or package ID mismatch!");
                return;
            }
            if(intent.hasExtra(EXTRA_APP_FLIP_CLIENT_ID)){
                clientId = intent.getExtras().getString(EXTRA_APP_FLIP_CLIENT_ID);
                scopes = intent.getExtras().getString(EXTRA_APP_FLIP_SCOPES);
                redirectUri = intent.getExtras().getString(EXTRA_APP_FLIP_REDIRECT_URI);
            } else {
                Log.d(TAG, "couldn't find extra " + EXTRA_APP_FLIP_CLIENT_ID);
                Toast.makeText(context, "Did not received clientID", Toast.LENGTH_SHORT).show();
                return;
            }
            this.sendPushPayload(clientId);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        PackageManager pm = getPackageManager();
        Intent launchIntent = pm.getLaunchIntentForPackage(getApplicationContext().getPackageName());
        startActivityForResult(launchIntent, MAINACTIVITY_RESULT_INTENT);

    }

    public void setWindowParams() {
        WindowManager.LayoutParams wlp = getWindow().getAttributes();
        wlp.width = 0;
        wlp.height = 0;
        wlp.dimAmount = 0;
        wlp.flags = WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS |
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL;
        getWindow().setAttributes(wlp);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if(requestCode == MAINACTIVITY_RESULT_INTENT){
            setResult(resultCode,data);
            finish();
        }
    }

    public void getAuthCode(Intent returnIntent) {
        result = returnIntent;
       setResult(Activity.RESULT_OK, result);
    }

    private boolean validateCallingApp(ComponentName callingActivity) {
        if (callingActivity != null) {
            String packageName = callingActivity.getPackageName();
            if (callingAppPackageName.equalsIgnoreCase(packageName)) {
                try {
                    String fingerPrint = getCertificateFingerprint(getApplicationContext(), packageName);
                    return callingAppFingerprint.equalsIgnoreCase(fingerPrint);
                } catch (PackageManager.NameNotFoundException e) {
                    Log.e(TAG, "No such app is installed", e);
                }
            }
        }
        return false;
    }

    @Nullable
    private String getCertificateFingerprint(Context context, String packageName)
            throws PackageManager.NameNotFoundException {
        PackageManager pm = context.getPackageManager();
        PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
        Signature[] signatures = packageInfo.signatures;
        InputStream input = new ByteArrayInputStream(signatures[0].toByteArray());
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(input);
            MessageDigest md = MessageDigest.getInstance(SIGNATURE_DIGEST_ALGORITHM);
            byte[] publicKey = md.digest(certificate.getEncoded());
            return byte2HexFormatted(publicKey);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            Log.e(TAG, "Failed to process the certificate", e);
        }
        return null;
    }

    private String byte2HexFormatted(byte[] byteArray) {
        Formatter formatter = new Formatter();
        for (int i = 0; i < byteArray.length - 1; i++) {
            formatter.format("%02x:", byteArray[i]);
        }
        formatter.format("%02x", byteArray[byteArray.length - 1]);
        return formatter.toString().toUpperCase();
    }

    private void sendPushPayload(String clientId) throws JSONException {
        Log.d(TAG, "==> USER entered appflip");
        AppFlip.setInitialPushPayload(clientId);
    }
}

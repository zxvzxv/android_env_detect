package com.envdetect;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.envdetect.detector.EnvDetector;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_PERMISSIONS = 1001;

    private static final String[] REQUIRED_PERMISSIONS;

    static {
        List<String> perms = new ArrayList<>();
        perms.add(Manifest.permission.READ_PHONE_STATE);
        perms.add(Manifest.permission.ACCESS_WIFI_STATE);
        perms.add(Manifest.permission.ACCESS_NETWORK_STATE);
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.R) {
            perms.add(Manifest.permission.BLUETOOTH);
        }
        REQUIRED_PERMISSIONS = perms.toArray(new String[0]);
    }

    private TextView tvResult;
    private Button btnPermission;
    private Button btnDetect;
    private Button btnCopy;
    private String resultJson = "";
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvResult = findViewById(R.id.tv_result);
        btnPermission = findViewById(R.id.btn_permission);
        btnDetect = findViewById(R.id.btn_detect);
        btnCopy = findViewById(R.id.btn_copy);

        btnPermission.setOnClickListener(v -> requestAllPermissions());
        btnDetect.setOnClickListener(v -> startDetection());
        btnCopy.setOnClickListener(v -> copyToClipboard());

        updatePermissionButton();
    }

    private void requestAllPermissions() {
        List<String> needed = new ArrayList<>();
        for (String perm : REQUIRED_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, perm)
                    != PackageManager.PERMISSION_GRANTED) {
                needed.add(perm);
            }
        }
        if (needed.isEmpty()) {
            Toast.makeText(this, R.string.permission_granted, Toast.LENGTH_SHORT).show();
            return;
        }
        ActivityCompat.requestPermissions(this,
                needed.toArray(new String[0]), REQUEST_PERMISSIONS);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
            @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode != REQUEST_PERMISSIONS) return;

        boolean allGranted = true;
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        Toast.makeText(this,
                allGranted ? R.string.permission_granted : R.string.permission_partial,
                Toast.LENGTH_SHORT).show();
        updatePermissionButton();
    }

    private void updatePermissionButton() {
        boolean allGranted = true;
        for (String perm : REQUIRED_PERMISSIONS) {
            if (ContextCompat.checkSelfPermission(this, perm)
                    != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        if (allGranted) {
            btnPermission.setText("✓ 权限已获取");
            btnPermission.setEnabled(false);
            btnPermission.setAlpha(0.6f);
        }
    }

    private void startDetection() {
        btnDetect.setEnabled(false);
        btnCopy.setEnabled(false);
        tvResult.setText(R.string.detecting);

        executor.execute(() -> {
            final String json = EnvDetector.detect(MainActivity.this);
            mainHandler.post(() -> {
                resultJson = json;
                tvResult.setText(json);
                btnDetect.setEnabled(true);
                btnCopy.setEnabled(true);
            });
        });
    }

    private void copyToClipboard() {
        if (resultJson.isEmpty()) return;
        ClipboardManager clipboard = (ClipboardManager)
                getSystemService(CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText("env_detect_result", resultJson);
            clipboard.setPrimaryClip(clip);
            Toast.makeText(this, R.string.copy_success, Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}

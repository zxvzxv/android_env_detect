package com.envdetect;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.envdetect.detector.EnvDetector;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private TextView tvResult;
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
        btnDetect = findViewById(R.id.btn_detect);
        btnCopy = findViewById(R.id.btn_copy);

        btnDetect.setOnClickListener(v -> startDetection());
        btnCopy.setOnClickListener(v -> copyToClipboard());
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

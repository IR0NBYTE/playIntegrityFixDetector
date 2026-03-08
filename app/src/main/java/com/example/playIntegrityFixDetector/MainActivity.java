package com.example.playIntegrityFixDetector;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.annotation.NonNull;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;

import com.example.playIntegrityFixDetector.databinding.ActivityMainBinding;
import com.scottyab.rootbeer.RootBeer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final int RESULT_DEBUG_DETECTED = -1;
    private static final int RESULT_TAMPERING_DETECTED = 1;
    private static final int RESULT_CLEAN = 0;

    private static boolean nativeLibLoaded = false;

    static {
        try {
            System.loadLibrary("playIntegrityFixDetector");
            nativeLibLoaded = true;
        } catch (UnsatisfiedLinkError ignored) {
        }
    }

    private ActivityMainBinding binding;
    private RootBeer rootChecker;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!nativeLibLoaded) {
            showErrorAndExit("Native security module failed to load");
            return;
        }

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        rootChecker = new RootBeer(this);

        if (performInitialSecurityCheck()) {
            setupDetectionButton();
        }
    }

    private boolean performInitialSecurityCheck() {
        if (rootChecker.isRooted()) {
            showSecurityAlert(
                "Root Detected",
                "This device has been rooted. The app cannot verify integrity on compromised systems."
            );
            return false;
        }
        return true;
    }

    private void setupDetectionButton() {
        Button detectBtn = binding.button2;
        if (detectBtn == null) return;

        detectBtn.setOnClickListener(v -> {
            detectBtn.setEnabled(false);
            detectBtn.setText("Checking...");
            runIntegrityCheck(detectBtn);
        });
    }

    private void runIntegrityCheck(Button detectBtn) {
        executor.execute(() -> {
            int result = isIntegrityTampered();

            mainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;

                detectBtn.setEnabled(true);
                detectBtn.setText("Detect PlayIntegrityFix");

                switch (result) {
                    case RESULT_DEBUG_DETECTED:
                        showSecurityAlert(
                            "Debug Tools Detected",
                            "Runtime instrumentation detected. This may indicate tampering attempts."
                        );
                        break;

                    case RESULT_TAMPERING_DETECTED:
                        showSecurityAlert(
                            "Integrity Violation",
                            "System modifications detected that bypass integrity checks."
                        );
                        break;

                    case RESULT_CLEAN:
                        showSuccessDialog();
                        break;

                    default:
                        showErrorAndExit("Unexpected integrity check result");
                }
            });
        });
    }

    private void showSecurityAlert(@NonNull String title, @NonNull String message) {
        if (isFinishing() || isDestroyed()) return;

        new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("Exit", (dialog, which) -> finish())
                .show();
    }

    private void showSuccessDialog() {
        if (isFinishing() || isDestroyed()) return;

        new AlertDialog.Builder(this)
                .setTitle("Integrity Verified")
                .setMessage("No integrity violations detected.")
                .setPositiveButton("OK", null)
                .show();
    }

    private void showErrorAndExit(@NonNull String message) {
        if (isFinishing() || isDestroyed()) return;

        new AlertDialog.Builder(this)
                .setTitle("Error")
                .setMessage(message)
                .setCancelable(false)
                .setPositiveButton("Exit", (dialog, which) -> finish())
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdownNow();
        binding = null;
        rootChecker = null;
    }

    public native int isIntegrityTampered();
}

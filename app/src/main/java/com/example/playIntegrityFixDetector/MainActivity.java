package com.example.playIntegrityFixDetector;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import com.example.playIntegrityFixDetector.databinding.ActivityMainBinding;
import com.scottyab.rootbeer.RootBeer;

public class MainActivity extends AppCompatActivity {


    static {
        System.loadLibrary("playIntegrityFixDetector");
    }
    private ActivityMainBinding binding;

    private void showDebugToolsDetectedDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Security Warning")
                .setMessage("This app cannot run along debugging tools !")
                .setCancelable(false)
                .setPositiveButton("OK", (dialog, which) -> {
                    dialog.dismiss();
                    finishAffinity();
                })
                .show();
    }
    private void showRootDetectedDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Security Warning")
                .setMessage("This app cannot run on rooted devices for security reasons.")
                .setCancelable(false)
                .setPositiveButton("OK", (dialog, which) -> {
                    dialog.dismiss();
                    finishAffinity();
                })
                .show();
    }

    private void showPIFDetectedDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Security Warning")
                .setMessage("Play integrity fix is detected !")
                .setCancelable(false)
                .setPositiveButton("OK", (dialog, which) -> {
                    dialog.dismiss();
                    finishAffinity();
                })
                .show();
    }
    private void showNormalFlowDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Integrity Passed")
                .setMessage("Play integrity fix on this device not detected !")
                .setPositiveButton("OK", null)
                .show();
    }
    private void checkRootStatus() {
        RootBeer rootBeer = new RootBeer(this);
        if (rootBeer.isRooted())
            showRootDetectedDialog();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        checkRootStatus();
        Button detectBtn = findViewById(R.id.button2);
        detectBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) {
                if (isIntegrityTampered() == -1)
                    showDebugToolsDetectedDialog();
                else if (isIntegrityTampered() == 1)
                    showPIFDetectedDialog();
                else
                    showNormalFlowDialog();
            }
        });
    }



    public native int isIntegrityTampered();
}
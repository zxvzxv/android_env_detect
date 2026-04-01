package com.envdetect.detector;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothAdapter;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.hardware.camera2.CameraManager;
import android.os.BatteryManager;
import android.os.Build;
import android.telephony.TelephonyManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class EmulatorDetector {

    private static final String[] EMULATOR_FILES = {
            // QEMU / Goldfish / Android Emulator
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/dev/goldfish_pipe",
            "/sys/qemu_trace",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/system/bin/qemu-props",
            "/sys/devices/virtual/misc/goldfish_pipe",
            "/sys/module/goldfish_audio",
            "/sys/module/goldfish_battery",
            "/sys/module/kvm_intel/",
            "/sys/module/kvm_amd/",
            "/init.android_x86_64.rc",
            "/init.android_x86.rc",
            "/init.androidVM_x86.rc",
            "/init.intel.rc",
            "/init.vbox2345_x86.rc",
            // Genymotion
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/system/bin/androVM-prop",
            "/system/bin/androVM-vbox-sf",
            "/system/bin/androVM_setprop",
            "/system/bin/get_androVM_host",
            "/system/etc/init.androVM.sh",
            "/system/etc/init.buildroid.sh",
            // LDPlayer (雷电)
            "/system/bin/ldinit",
            "/system/bin/ldmountsf",
            "/system/lib/libldutils.so",
            // MicroVirt (逍遥)
            "/system/bin/microvirt-prop",
            "/system/bin/microvirtd",
            "/data/data/com.microvirt.market",
            "/data/data/com.microvirt.toolst",
            "/dev/nemuguest",
            "/system/lib/libnemuVMprop.so",
            // Nox (夜神)
            "/system/bin/nox-prop",
            "/system/lib/libnoxspeedup.so",
            "/data/property/persist.nox.simulator_version",
            "/data/misc/profiles/ref/com.bignox.google.installer",
            "/data/misc/profiles/ref/com.bignox.app.store.hd",
            // TTVM (天天)
            "/system/bin/ttVM-prop",
            // Droid4X (海马玩)
            "/system/lib/libdroid4x.so",
            "/system/bin/droid4x-prop",
            // Duos
            "/system/bin/duosconfig",
            // MEMU / MUMU (网易 MuMu)
            "/system/etc/mumu-configs/device-prop-configs/mumu.config",
            "/data/data/com.mumu.launcher",
            "/data/data/com.mumu.store",
            "/data/data/com.netease.mumu.cloner",
            "/system/etc/xxzs_prop.sh",
            // BlueStacks
            "/boot/bstsetup.env",
            "/boot/bstmods",
            "/system/xbin/bstk",
            "/system/bin/bstshutdown",
            "/data/bluestacks.prop",
            "/data/data/com.bluestacks.appmart",
            "/data/data/com.bluestacks.home",
            "/sys/module/bstinput",
            "/sys/class/misc/bstXqpb",
            "/data/data/com.anrovmconfig",
            // VirtualBox
            "/dev/vboxguest",
            "/dev/vboxuser",
            "/sys/bus/pci/drivers/vboxguest",
            "/sys/class/bdi/vboxsf-c",
            "/sys/class/misc/vboxguest",
            "/sys/class/misc/vboxuser",
            "/sys/devices/virtual/bdi/vboxsf-c",
            "/sys/devices/virtual/misc/vboxguest",
            "/sys/devices/virtual/misc/vboxuser",
            "/sys/module/vboxguest",
            "/sys/module/vboxsf",
            "/sys/module/vboxvideo",
            "/system/bin/mount.vboxsf",
            "/system/xbin/mount.vboxsf",
            "/system/lib/vboxguest.ko",
            "/system/lib/vboxsf.ko",
            "/system/lib/vboxvideo.ko",
            "/data/youwave_id",
            // PhoenixOS (凤凰)
            "/system/phoenixos",
            "/xbin/phoenix_compat",
            // Dundi (独蜂)
            "/init.dundi.rc",
            "/system/etc/init.dundi.sh",
            "/data/data/com.ddmnq.dundidevhelper",
            // Andy
            "/init.andy.cloud.rc",
            // XiaoPi / XCPlayer / LYBox
            "/system/bin/xiaopiVM-prop",
            "/system/bin/XCPlayer-prop",
            "/system/lib/liblybox_prop.so",
            // Tencent (腾讯手游助手)
            "/system/bin/tencent_virtual_input",
            "/vendor/bin/init.tencent.sh",
            // Windroye (文卓爷)
            "/system/bin/windroyed",
    };

    private static final String[] EMULATOR_MOUNT_INDICATORS = {
            "/mnt/shared/Sharefolder",
            "/tiantian.conf",
            "/data/share1",
            "/hardware_device.conf",
            "/mnt/shared/products",
            "/mumu_hardware.conf",
            "/Andy.conf",
            "/mnt/windows/BstSharedFolder",
            "/bst.conf",
            "/mnt/shared/Applications",
            "/ld.conf",
    };

    private static final String[] EMULATOR_KEYWORDS = {
            "generic", "unknown", "google_sdk", "emulator",
            "android sdk built for x86", "goldfish", "ranchu",
            "sdk_gphone", "vbox", "virtualbox", "genymotion",
            "nox", "bluestacks", "memu", "mumu", "ldplayer",
            "andy", "droid4x", "tiantian", "windroye", "xiaoyao",
            "duos", "ttvm", "bignox", "hd-player", "microvirt",
            "ami_gphone"
    };

    private static final String[][] SUSPICIOUS_PROPS = {
            {"ro.kernel.qemu", "1"},
            {"ro.hardware.audio.primary", "goldfish"},
            {"ro.hardware", "goldfish"},
            {"ro.hardware", "ranchu"},
            {"init.svc.qemu-props", null},
            {"qemu.sf.lcd_density", null},
            {"qemu.hw.mainkeys", null},
            {"ro.boot.qemu", "1"},
            {"ro.product.device", "generic"},
            {"ro.product.model", "sdk"},
            {"ro.secure", "0"},
            {"ro.boot.hardware", "goldfish"},
            {"ro.boot.hardware", "ranchu"},
            {"gsm.version.ril-impl", "android memu"},
            {"init.svc.vbox86-setup", null},
            {"init.svc.noxd", null},
            {"init.svc.ttVM_x86-setup", null},
    };

    public static JSONObject detect(Context context) {
        JSONObject result = new JSONObject();
        try {
            JSONObject suspiciousBuild = checkBuildFields();
            result.put("suspicious_build_fields", suspiciousBuild);
            result.put("build_fingerprint_suspicious", suspiciousBuild.length() > 0);

            List<String> emulatorFiles = checkEmulatorFiles();
            result.put("emulator_files_found", new JSONArray(emulatorFiles));

            List<String> mountIndicators = checkMountIndicators();
            result.put("emulator_mount_indicators", new JSONArray(mountIndicators));

            JSONObject suspiciousProps = checkSuspiciousProps();
            result.put("suspicious_props", suspiciousProps);

            collectTelephonyInfo(context, result);
            collectSensorInfo(context, result);
            collectBatteryInfo(context, result);

            result.put("supported_abis", new JSONArray(Arrays.asList(Build.SUPPORTED_ABIS)));
            result.put("has_bluetooth", checkBluetooth());
            result.put("camera_count", getCameraCount(context));
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static JSONObject checkBuildFields() {
        JSONObject suspicious = new JSONObject();
        try {
            matchField(suspicious, "FINGERPRINT", Build.FINGERPRINT);
            matchField(suspicious, "MODEL", Build.MODEL);
            matchField(suspicious, "MANUFACTURER", Build.MANUFACTURER);
            matchField(suspicious, "BRAND", Build.BRAND);
            matchField(suspicious, "DEVICE", Build.DEVICE);
            matchField(suspicious, "PRODUCT", Build.PRODUCT);
            matchField(suspicious, "HARDWARE", Build.HARDWARE);
            matchField(suspicious, "BOARD", Build.BOARD);
        } catch (Exception ignored) {
        }
        return suspicious;
    }

    private static void matchField(JSONObject result, String fieldName, String value) throws Exception {
        if (value == null) return;
        String lower = value.toLowerCase();
        for (String keyword : EMULATOR_KEYWORDS) {
            if (lower.contains(keyword)) {
                result.put(fieldName, value);
                return;
            }
        }
    }

    private static List<String> checkEmulatorFiles() {
        List<String> found = new ArrayList<>();
        for (String path : EMULATOR_FILES) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static List<String> checkMountIndicators() {
        List<String> found = new ArrayList<>();
        for (String path : EMULATOR_MOUNT_INDICATORS) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static JSONObject checkSuspiciousProps() {
        JSONObject result = new JSONObject();
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            Method get = clazz.getMethod("get", String.class, String.class);
            for (String[] prop : SUSPICIOUS_PROPS) {
                try {
                    String value = (String) get.invoke(null, prop[0], "");
                    if (value != null && !value.isEmpty()) {
                        if (prop[1] == null || value.equals(prop[1])) {
                            result.put(prop[0], value);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return result;
    }

    @SuppressLint({"HardwareIds", "MissingPermission"})
    private static void collectTelephonyInfo(Context context, JSONObject result) {
        try {
            TelephonyManager tm = (TelephonyManager)
                    context.getSystemService(Context.TELEPHONY_SERVICE);
            if (tm == null) return;

            String imei = "";
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    imei = tm.getImei();
                } else {
                    imei = tm.getDeviceId();
                }
            } catch (Exception ignored) {
            }
            result.put("imei", imei != null ? imei : "");

            String phoneNumber = "";
            try {
                phoneNumber = tm.getLine1Number();
            } catch (Exception ignored) {
            }
            result.put("phone_number", phoneNumber != null ? phoneNumber : "");

            result.put("network_operator_name",
                    tm.getNetworkOperatorName() != null ? tm.getNetworkOperatorName() : "");
            result.put("sim_operator_name",
                    tm.getSimOperatorName() != null ? tm.getSimOperatorName() : "");
        } catch (Exception e) {
            try {
                result.put("imei", "");
                result.put("phone_number", "");
            } catch (Exception ignored) {
            }
        }
    }

    private static void collectSensorInfo(Context context, JSONObject result) {
        try {
            SensorManager sm = (SensorManager)
                    context.getSystemService(Context.SENSOR_SERVICE);
            if (sm == null) return;

            List<Sensor> sensors = sm.getSensorList(Sensor.TYPE_ALL);
            result.put("sensors_count", sensors.size());
            result.put("has_accelerometer",
                    sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER) != null);
            result.put("has_gyroscope",
                    sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE) != null);
            result.put("has_magnetic_field",
                    sm.getDefaultSensor(Sensor.TYPE_MAGNETIC_FIELD) != null);
            result.put("has_light_sensor",
                    sm.getDefaultSensor(Sensor.TYPE_LIGHT) != null);
            result.put("has_proximity",
                    sm.getDefaultSensor(Sensor.TYPE_PROXIMITY) != null);
        } catch (Exception e) {
            try {
                result.put("sensors_count", -1);
            } catch (Exception ignored) {
            }
        }
    }

    private static void collectBatteryInfo(Context context, JSONObject result) {
        try {
            IntentFilter filter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, filter);
            if (batteryStatus != null) {
                int temperature = batteryStatus.getIntExtra(
                        BatteryManager.EXTRA_TEMPERATURE, -1);
                int voltage = batteryStatus.getIntExtra(
                        BatteryManager.EXTRA_VOLTAGE, -1);
                int status = batteryStatus.getIntExtra(
                        BatteryManager.EXTRA_STATUS, -1);
                result.put("battery_temperature", temperature / 10.0);
                result.put("battery_voltage", voltage);
                result.put("battery_status", status);
            }
        } catch (Exception ignored) {
        }
    }

    @SuppressLint("MissingPermission")
    private static boolean checkBluetooth() {
        try {
            BluetoothAdapter adapter = BluetoothAdapter.getDefaultAdapter();
            return adapter != null;
        } catch (Exception e) {
            return false;
        }
    }

    private static int getCameraCount(Context context) {
        try {
            CameraManager manager = (CameraManager)
                    context.getSystemService(Context.CAMERA_SERVICE);
            if (manager != null) {
                return manager.getCameraIdList().length;
            }
        } catch (Exception ignored) {
        }
        return -1;
    }
}

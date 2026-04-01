package com.envdetect.detector;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.DisplayMetrics;
import android.view.WindowManager;

import org.json.JSONObject;

import java.io.File;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;

public class SystemPropCollector {

    private static final String[] SYSTEM_PROPS = {
            "ro.build.display.id",
            "ro.build.version.incremental",
            "ro.build.version.sdk",
            "ro.build.version.release",
            "ro.build.version.security_patch",
            "ro.build.type",
            "ro.build.user",
            "ro.build.host",
            "ro.build.tags",
            "ro.build.flavor",
            "ro.product.model",
            "ro.product.brand",
            "ro.product.name",
            "ro.product.device",
            "ro.product.board",
            "ro.product.cpu.abi",
            "ro.product.cpu.abilist",
            "ro.product.manufacturer",
            "ro.product.locale",
            "ro.product.first_api_level",
            "ro.hardware",
            "ro.hardware.chipname",
            "ro.boot.hardware",
            "ro.boot.serialno",
            "ro.serialno",
            "ro.bootimage.build.fingerprint",
            "ro.kernel.qemu",
            "ro.kernel.androidboot.hardware",
            "ro.debuggable",
            "ro.secure",
            "ro.adb.secure",
            "ro.zygote",
            "persist.sys.usb.config",
            "persist.sys.dalvik.vm.lib.2",
            "persist.sys.timezone",
            "persist.sys.language",
            "gsm.sim.operator.alpha",
            "gsm.operator.alpha",
            "gsm.version.baseband",
            "gsm.version.ril-impl",
            "net.gprs.local-ip",
            "wifi.interface",
            "ro.crypto.state",
            "ro.boot.vbmeta.device_state",
            "sys.oem_unlock_allowed",
            "dalvik.vm.heapsize",
            "dalvik.vm.heapmaxfree",
            "dalvik.vm.isa.arm.variant",
            "dalvik.vm.isa.arm64.variant"
    };

    public static JSONObject collect(Context context) {
        JSONObject result = new JSONObject();
        try {
            result.put("build", collectBuildInfo());
            result.put("props", collectSystemProps());
            result.put("device_id", collectDeviceIds(context));
            result.put("network", collectNetworkInfo(context));
            result.put("screen", collectScreenInfo(context));
            result.put("memory", collectMemoryInfo(context));
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static JSONObject collectBuildInfo() {
        JSONObject build = new JSONObject();
        try {
            build.put("board", Build.BOARD);
            build.put("bootloader", Build.BOOTLOADER);
            build.put("brand", Build.BRAND);
            build.put("device", Build.DEVICE);
            build.put("display", Build.DISPLAY);
            build.put("fingerprint", Build.FINGERPRINT);
            build.put("hardware", Build.HARDWARE);
            build.put("host", Build.HOST);
            build.put("id", Build.ID);
            build.put("manufacturer", Build.MANUFACTURER);
            build.put("model", Build.MODEL);
            build.put("product", Build.PRODUCT);
            build.put("tags", Build.TAGS);
            build.put("time", Build.TIME);
            build.put("type", Build.TYPE);
            build.put("user", Build.USER);
            build.put("radio_version", Build.getRadioVersion());
            build.put("sdk_int", Build.VERSION.SDK_INT);
            build.put("release", Build.VERSION.RELEASE);
            build.put("incremental", Build.VERSION.INCREMENTAL);
            build.put("codename", Build.VERSION.CODENAME);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                build.put("security_patch", Build.VERSION.SECURITY_PATCH);
                build.put("base_os", Build.VERSION.BASE_OS);
                build.put("preview_sdk_int", Build.VERSION.PREVIEW_SDK_INT);
            }
            build.put("supported_abis", String.join(",", Build.SUPPORTED_ABIS));
            build.put("serial", getSerial());
        } catch (Exception ignored) {
        }
        return build;
    }

    @SuppressLint("HardwareIds")
    private static String getSerial() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                return Build.getSerial();
            } else {
                return Build.SERIAL;
            }
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static JSONObject collectSystemProps() {
        JSONObject props = new JSONObject();
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            Method get = clazz.getMethod("get", String.class, String.class);
            for (String key : SYSTEM_PROPS) {
                try {
                    String value = (String) get.invoke(null, key, "");
                    if (value != null && !value.isEmpty()) {
                        props.put(key, value);
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return props;
    }

    @SuppressLint("HardwareIds")
    private static JSONObject collectDeviceIds(Context context) {
        JSONObject ids = new JSONObject();
        try {
            String androidId = Settings.Secure.getString(
                    context.getContentResolver(), Settings.Secure.ANDROID_ID);
            ids.put("android_id", androidId != null ? androidId : "");
            ids.put("serial", getSerial());

            try {
                TelephonyManager tm = (TelephonyManager)
                        context.getSystemService(Context.TELEPHONY_SERVICE);
                if (tm != null) {
                    String imei;
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        imei = tm.getImei();
                    } else {
                        imei = tm.getDeviceId();
                    }
                    ids.put("imei", imei != null ? imei : "");
                }
            } catch (SecurityException e) {
                ids.put("imei", "no_permission");
            } catch (Exception e) {
                ids.put("imei", "error");
            }
        } catch (Exception ignored) {
        }
        return ids;
    }

    @SuppressLint({"HardwareIds", "MissingPermission"})
    private static JSONObject collectNetworkInfo(Context context) {
        JSONObject network = new JSONObject();
        try {
            try {
                WifiManager wm = (WifiManager) context.getApplicationContext()
                        .getSystemService(Context.WIFI_SERVICE);
                if (wm != null) {
                    WifiInfo wifiInfo = wm.getConnectionInfo();
                    if (wifiInfo != null) {
                        network.put("wifi_mac", wifiInfo.getMacAddress());
                        network.put("wifi_ssid", wifiInfo.getSSID());
                        network.put("wifi_bssid", wifiInfo.getBSSID());
                    }
                }
            } catch (Exception ignored) {
            }

            try {
                List<NetworkInterface> interfaces =
                        Collections.list(NetworkInterface.getNetworkInterfaces());
                for (NetworkInterface ni : interfaces) {
                    List<InetAddress> addresses =
                            Collections.list(ni.getInetAddresses());
                    for (InetAddress addr : addresses) {
                        if (!addr.isLoopbackAddress()
                                && addr.getHostAddress().indexOf(':') < 0) {
                            network.put("ip_address", addr.getHostAddress());
                        }
                    }
                }
            } catch (Exception ignored) {
            }

            try {
                TelephonyManager tm = (TelephonyManager)
                        context.getSystemService(Context.TELEPHONY_SERVICE);
                if (tm != null) {
                    network.put("operator", tm.getNetworkOperatorName());
                    network.put("sim_operator", tm.getSimOperatorName());
                    network.put("network_country", tm.getNetworkCountryIso());
                    network.put("sim_country", tm.getSimCountryIso());
                }
            } catch (Exception ignored) {
            }

            try {
                ConnectivityManager cm = (ConnectivityManager)
                        context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    @SuppressWarnings("deprecation")
                    NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
                    if (activeNetwork != null) {
                        network.put("network_type", activeNetwork.getTypeName());
                        network.put("network_subtype", activeNetwork.getSubtypeName());
                        network.put("network_connected", activeNetwork.isConnected());
                    }
                }
            } catch (Exception ignored) {
            }
        } catch (Exception ignored) {
        }
        return network;
    }

    @SuppressWarnings("deprecation")
    private static JSONObject collectScreenInfo(Context context) {
        JSONObject screen = new JSONObject();
        try {
            WindowManager wm = (WindowManager)
                    context.getSystemService(Context.WINDOW_SERVICE);
            if (wm != null) {
                DisplayMetrics dm = new DisplayMetrics();
                wm.getDefaultDisplay().getMetrics(dm);
                screen.put("width", dm.widthPixels);
                screen.put("height", dm.heightPixels);
                screen.put("dpi", dm.densityDpi);
                screen.put("density", dm.density);
                screen.put("scaled_density", dm.scaledDensity);
                screen.put("xdpi", dm.xdpi);
                screen.put("ydpi", dm.ydpi);
            }
        } catch (Exception ignored) {
        }
        return screen;
    }

    private static JSONObject collectMemoryInfo(Context context) {
        JSONObject memory = new JSONObject();
        try {
            ActivityManager am = (ActivityManager)
                    context.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo memInfo = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(memInfo);
                memory.put("total_ram_mb", memInfo.totalMem / (1024 * 1024));
                memory.put("available_ram_mb", memInfo.availMem / (1024 * 1024));
                memory.put("low_memory", memInfo.lowMemory);
                memory.put("threshold_mb", memInfo.threshold / (1024 * 1024));
            }

            StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
            memory.put("total_storage_mb", statFs.getTotalBytes() / (1024 * 1024));
            memory.put("available_storage_mb",
                    statFs.getAvailableBytes() / (1024 * 1024));

            File externalDir = Environment.getExternalStorageDirectory();
            if (externalDir != null && externalDir.exists()) {
                StatFs extStatFs = new StatFs(externalDir.getPath());
                memory.put("external_total_mb",
                        extStatFs.getTotalBytes() / (1024 * 1024));
                memory.put("external_available_mb",
                        extStatFs.getAvailableBytes() / (1024 * 1024));
            }
        } catch (Exception ignored) {
        }
        return memory;
    }
}

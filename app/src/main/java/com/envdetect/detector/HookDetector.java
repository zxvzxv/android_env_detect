package com.envdetect.detector;

import android.content.Context;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class HookDetector {

    private static final String[] XPOSED_PACKAGES = {
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager",
            "com.solohsu.android.edxp.manager",
            "io.va.exposed",
            "io.va.exposed64",
            "com.android.vendinern"
    };

    private static final String[] XPOSED_FILES = {
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so",
            "/system/xposed.prop",
            "/data/misc/riru/modules/lsposed",
            "/data/adb/lspd",
            "/data/adb/modules/riru_lsposed",
            "/data/adb/modules/zygisk_lsposed",
            "/data/misc/riru/modules/edxposed"
    };

    private static final String[] FRIDA_FILES = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent.so",
            "/data/local/tmp/frida-gadget.so",
            "/data/local/tmp/frida-server-arm",
            "/data/local/tmp/frida-server-arm64",
    };

    private static final int[] FRIDA_PORTS = {27042, 27043};

    private static final String[] SUSPICIOUS_LIB_KEYWORDS = {
            "xposed", "frida", "substrate", "cydia",
            "hook", "inject", "hide", "magisk",
            "riru", "lsposed", "edxposed", "epic"
    };

    public static JSONObject detect(Context context) {
        JSONObject result = new JSONObject();
        try {
            List<String> xposedPkgs = checkXposedPackages(context);
            result.put("xposed_installed", !xposedPkgs.isEmpty());
            result.put("xposed_packages", new JSONArray(xposedPkgs));

            List<String> xposedFiles = checkXposedFiles();
            result.put("xposed_files_found", new JSONArray(xposedFiles));

            result.put("xposed_in_stack", checkXposedInStack());
            result.put("xposed_class_loadable", checkXposedClassLoadable());

            List<Integer> fridaPorts = checkFridaPorts();
            result.put("frida_port_open", !fridaPorts.isEmpty());
            result.put("frida_open_ports", new JSONArray(fridaPorts));

            result.put("frida_in_maps", checkFridaInMaps());
            result.put("frida_process_found", checkFridaProcess());

            List<String> fridaFiles = checkFridaFiles();
            result.put("frida_files_found", new JSONArray(fridaFiles));

            result.put("substrate_installed", checkSubstrate(context));

            List<String> suspiciousLibs = collectSuspiciousNativeLibs();
            result.put("suspicious_native_libs", new JSONArray(suspiciousLibs));
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static List<String> checkXposedPackages(Context context) {
        List<String> found = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        for (String pkg : XPOSED_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return found;
    }

    private static List<String> checkXposedFiles() {
        List<String> found = new ArrayList<>();
        for (String path : XPOSED_FILES) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static boolean checkXposedInStack() {
        try {
            StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
            for (StackTraceElement element : stackTrace) {
                String cls = element.getClassName();
                if (cls.contains("de.robv.android.xposed")
                        || cls.contains("EdHooker")
                        || cls.contains("LSPosed")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static boolean checkXposedClassLoadable() {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static List<Integer> checkFridaPorts() {
        List<Integer> openPorts = new ArrayList<>();
        for (int port : FRIDA_PORTS) {
            Socket socket = null;
            try {
                socket = new Socket();
                socket.connect(new InetSocketAddress("127.0.0.1", port), 300);
                openPorts.add(port);
            } catch (Exception ignored) {
            } finally {
                try {
                    if (socket != null) socket.close();
                } catch (Exception ignored) {
                }
            }
        }
        return openPorts;
    }

    private static boolean checkFridaInMaps() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gadget")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        } finally {
            try {
                if (reader != null) reader.close();
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    private static boolean checkFridaProcess() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"ps", "-A"});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gum-js-loop")) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (Exception ignored) {
        } finally {
            if (process != null) process.destroy();
        }
        return false;
    }

    private static List<String> checkFridaFiles() {
        List<String> found = new ArrayList<>();
        for (String path : FRIDA_FILES) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static boolean checkSubstrate(Context context) {
        try {
            context.getPackageManager().getPackageInfo("com.saurik.substrate", 0);
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
        }
        try {
            return new File("/system/lib/libsubstrate.so").exists()
                    || new File("/system/lib/libsubstrate-dvm.so").exists()
                    || new File("/system/lib64/libsubstrate.so").exists();
        } catch (Exception ignored) {
        }
        return false;
    }

    private static List<String> collectSuspiciousNativeLibs() {
        Set<String> suspicious = new HashSet<>();
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.contains(".so")) continue;
                String lower = line.toLowerCase();
                for (String keyword : SUSPICIOUS_LIB_KEYWORDS) {
                    if (lower.contains(keyword)) {
                        String[] parts = line.split("\\s+");
                        if (parts.length > 5) {
                            suspicious.add(parts[parts.length - 1]);
                        }
                        break;
                    }
                }
            }
        } catch (Exception ignored) {
        } finally {
            try {
                if (reader != null) reader.close();
            } catch (Exception ignored) {
            }
        }
        return new ArrayList<>(suspicious);
    }
}

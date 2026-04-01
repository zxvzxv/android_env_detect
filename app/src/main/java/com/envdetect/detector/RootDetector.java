package com.envdetect.detector;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class RootDetector {

    private static final String[] SU_PATHS = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su",
            "/system/bin/.ext/su",
            "/system/bin/.hid/su",
            "/system/bin/cph_su",
            "/system/bin/failsafe/su",
            "/system/usr/we-need-root/su",
            "/system/sd/xbin/su",
            "/system/xbin/mu",
            "/system/xbin/mu_bak",
            "/system/xbin/bstk/su",
            "/system/xbin/sugote",
            "/system/xbin/sugote-mksh",
            "/system/xbin/supolicy",
            "/system/xbin/daemonsu",
            "/system_ext/bin/su",
            "/vendor/bin/su",
            "/vendor/xbin/su",
            "/odm/bin/su",
            "/product/bin/su",
            "/su/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/data/su",
            "/dev/su",
            "/cache/su",
            "/sbin/.mianju",
            "/sbin/nvsu",
            "/apex/com.android.runtime/bin/su",
            "/apex/com.android.art/bin/su",
            "/magisk/.core/bin/su"
    };

    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.kingo.root.KingoRoot",
            "com.smedialink.oneclean",
            "com.zhiqupk.root.global",
            "com.alephzain.framaroot",
            "com.formyhm.hideroot",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.amphoras.hidemyroot",
            "com.saurik.substrate",
            "de.robv.android.xposed.installer"
    };

    private static final String[] ROOT_FILES = {
            "/system/app/Superuser.apk",
            "/system/app/SuperUser/SuperUser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/SuperSU",
            "/system/app/superuser.apk",
            "/system/app/KingUser.apk",
            "/system/.supersu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/etc/.has_su_daemon",
            "/system/etc/.installed_su_daemon",
            "/system/addon.d/99-magisk.sh",
            "/data/data/com.topjohnwu.magisk",
            "/dev/com.koushikdutta.superuser.daemon/"
    };

    private static final String[] MAGISK_FILES = {
            "/data/adb/magisk",
            "/data/magisk",
            "/data/magisk.apk",
            "/cache/magisk.log",
            "/cache/.disable_magisk",
            "/dev/magisk/img",
            "/sbin/.magisk",
            "/system/etc/init/magisk",
            "/system/etc/init/magisk.rc"
    };

    public static JSONObject detect(Context context) {
        JSONObject result = new JSONObject();
        try {
            List<String> suPaths = checkSuBinary();
            result.put("su_binary_found", !suPaths.isEmpty());
            result.put("su_binary_paths", new JSONArray(suPaths));

            List<String> rootApps = checkRootApps(context);
            result.put("root_apps_found", new JSONArray(rootApps));

            List<String> rootFiles = checkRootFiles();
            result.put("root_files_found", new JSONArray(rootFiles));

            List<String> magiskFiles = checkMagiskFiles();
            result.put("magisk_files_found", new JSONArray(magiskFiles));

            result.put("test_keys", checkTestKeys());
            result.put("system_rw", checkSystemRW());
            result.put("su_executable", checkSuExecutable());
            result.put("selinux_permissive", checkSELinuxPermissive());
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static List<String> checkSuBinary() {
        List<String> found = new ArrayList<>();
        for (String path : SU_PATHS) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        try {
            String pathEnv = System.getenv("PATH");
            if (pathEnv != null) {
                for (String dir : pathEnv.split(":")) {
                    File suFile = new File(dir, "su");
                    String absPath = suFile.getAbsolutePath();
                    if (suFile.exists() && !found.contains(absPath)) {
                        found.add(absPath);
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return found;
    }

    private static List<String> checkRootApps(Context context) {
        List<String> found = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        for (String pkg : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return found;
    }

    private static List<String> checkRootFiles() {
        List<String> found = new ArrayList<>();
        for (String path : ROOT_FILES) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static List<String> checkMagiskFiles() {
        List<String> found = new ArrayList<>();
        for (String path : MAGISK_FILES) {
            try {
                if (new File(path).exists()) {
                    found.add(path);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static boolean checkTestKeys() {
        try {
            String tags = Build.TAGS;
            return tags != null && tags.contains("test-keys");
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean checkSystemRW() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/mounts"));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 4 && parts[1].equals("/system")) {
                    return parts[3].contains("rw");
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

    private static boolean checkSuExecutable() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            reader.close();
            return line != null && line.trim().length() > 0;
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static boolean checkSELinuxPermissive() {
        BufferedReader reader = null;
        try {
            File selinux = new File("/sys/fs/selinux/enforce");
            if (selinux.exists()) {
                reader = new BufferedReader(new FileReader(selinux));
                String line = reader.readLine();
                return "0".equals(line != null ? line.trim() : "");
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
}

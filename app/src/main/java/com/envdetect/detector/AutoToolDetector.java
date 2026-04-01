package com.envdetect.detector;

import android.content.Context;
import android.content.pm.PackageManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects screenshot capture tools, auto-click / automation frameworks,
 * and remote-control software that are commonly used for fraud or scripted operations.
 */
public class AutoToolDetector {

    private static final String TMP_DIR = "/data/local/tmp/";

    private static final String[] SUSPICIOUS_TMP_FILES = {
            "minicap.so",
            "minicap",
            "minitouch",
            "mini",
            "mini/minicap",
            "oat/arm64/scrcpy-server.odex",
            "vysor.pwd",
            "mobile_info.properties",
            "tc/mobileagent",
            "tc/input3.sh",
            "tc/mainputjar7",
            "com.cyjh.mobileanjian.id",
            "com.cyjh.mobileanjianen.id",
            "juejinAzykb/",
            "juejinAzykb/TouchService.jar",
            "mqc-scrcpy.jar",
            "uiautomator-stub.jar",
            "cloudtestig/cloudscreen",
            "cloudtesting/touchserver",
            "txysvr.apk",
            "yijianwanservice.apk",
            "screen-shread10x64.so",
            "screen-shread5x32.so",
            "maxpresent.jar",
            "libtxysvr.so",
    };

    private static final String[] AUTO_TOOL_PACKAGES = {
            // Auto-click / macro tools
            "com.cygery.repetitouch.pro",
            "com.cyjh.mobileanjian",
            "com.cyjh.mobileanjian.vip",
            "com.touchsprite.android",
            "com.cjzs123.zhushou",
            "com.touchspriteent.android",
            "com.zidongdianji",
            "com.zdanjian.zdanjian",
            "com.zdnewproject",
            "com.ifengwoo.zyjdkj",
            "com.angel.nrzs",
            "com.shumai.shudaxia",
            "fun.tooling.clicker.cn",
            "com.dianjiqi",
            "com.miaodong.autoactionssss",
            "com.mxz.wxautojiafujinderen",
            "com.touchelf.app",
            "com.adinall.autoclick",
            "com.i_cool.auto_clicker",
            "com.kongshan.aidianji",
            "com.xptech.catclicker",
            "com.tingniu.autoclick",
            "com.yicu.yichujifa",
            "com.smallyin.autoclick",
            "com.ksxkq.autoclick",
            "com.x2.clicker",
            "com.scott.autoclickhelper",
            "com.auyou.auyouwzs",
            // Scripting / automation frameworks
            "org.autojs.autojspro",
            "org.autojs.autojs",
            "com.stardust.scriptdroid",
            // UIAutomator / remote control
            "com.github.uiautomator",
            "com.github.uiautomator2",
            "com.sigma_rt.totalcontrol",
            "com.genymobile.scrcpy",
    };

    public static JSONObject detect(Context context) {
        JSONObject result = new JSONObject();
        try {
            List<String> tmpFiles = checkSuspiciousTmpFiles();
            result.put("suspicious_tmp_files", new JSONArray(tmpFiles));

            List<String> autoToolApps = checkAutoToolApps(context);
            result.put("auto_tool_apps", new JSONArray(autoToolApps));
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static List<String> checkSuspiciousTmpFiles() {
        List<String> found = new ArrayList<>();
        for (String name : SUSPICIOUS_TMP_FILES) {
            try {
                File f = new File(TMP_DIR, name);
                if (f.exists()) {
                    found.add(name);
                }
            } catch (Exception ignored) {
            }
        }
        return found;
    }

    private static List<String> checkAutoToolApps(Context context) {
        List<String> found = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        for (String pkg : AUTO_TOOL_PACKAGES) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return found;
    }
}

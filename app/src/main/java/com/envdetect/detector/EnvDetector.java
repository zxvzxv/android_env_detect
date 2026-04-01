package com.envdetect.detector;

import android.content.Context;

import org.json.JSONObject;

/**
 * Unified entry point for environment detection.
 * <p>
 * Usage:
 * <pre>
 *   String json = EnvDetector.detect(context);
 *   // or
 *   JSONObject obj = EnvDetector.detectAsJson(context);
 * </pre>
 */
public class EnvDetector {

    private static final String SDK_VERSION = "1.0.0";

    /**
     * Run all detectors and return a pretty-printed JSON string.
     */
    public static String detect(Context context) {
        try {
            return detectAsJson(context).toString(2);
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }

    /**
     * Run all detectors and return a JSONObject for programmatic access.
     */
    public static JSONObject detectAsJson(Context context) {
        JSONObject result = new JSONObject();
        try {
            result.put("timestamp", System.currentTimeMillis());
            result.put("sdk_version", SDK_VERSION);

            try {
                result.put("root", RootDetector.detect(context));
            } catch (Exception e) {
                result.put("root", errorJson("RootDetector", e));
            }

            try {
                result.put("emulator", EmulatorDetector.detect(context));
            } catch (Exception e) {
                result.put("emulator", errorJson("EmulatorDetector", e));
            }

            try {
                result.put("hook", HookDetector.detect(context));
            } catch (Exception e) {
                result.put("hook", errorJson("HookDetector", e));
            }

            try {
                result.put("auto_tool", AutoToolDetector.detect(context));
            } catch (Exception e) {
                result.put("auto_tool", errorJson("AutoToolDetector", e));
            }

            try {
                result.put("system_props", SystemPropCollector.collect(context));
            } catch (Exception e) {
                result.put("system_props", errorJson("SystemPropCollector", e));
            }
        } catch (Exception e) {
            try {
                result.put("error", e.getMessage());
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    private static JSONObject errorJson(String module, Exception e) {
        JSONObject err = new JSONObject();
        try {
            err.put("module", module);
            err.put("error", e.getMessage());
        } catch (Exception ignored) {
        }
        return err;
    }
}

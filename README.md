

## 说明

[![Android CI](https://github.com/zxvzxv/android_env_detect/actions/workflows/android.yml/badge.svg)](https://github.com/zxvzxv/android_env_detect/actions/workflows/android.yml)

### 编译
先安装好java、android sdk、gradle环境
```
gradle assembleDebug
```

下面是AI生成的说明

------------------------------

# EnvDetect - Android 异常环境检测工具

用于安卓端风控场景的环境特征数据采集工具。**只采集原始特征数据，不做判定/评分**，判定逻辑交由服务端完成。

## 检测模块

| 模块 | 类名 | 说明 |
|------|------|------|
| Root 检测 | `RootDetector` | 35+ su 路径、Root 管理应用、特征文件、Magisk 文件、Build Tags、系统分区读写、su 可执行性、SELinux 状态 |
| 模拟器检测 | `EmulatorDetector` | Build 指纹、90+ 设备特征文件（覆盖雷电/夜神/MuMu/BlueStacks/Genymotion 等）、挂载点检测、系统属性、电话/IMEI、传感器、电池、CPU 架构、蓝牙/摄像头 |
| Hook 检测 | `HookDetector` | Xposed（包名/文件/调用栈/类加载）、Frida（端口/maps/进程/文件）、Substrate、可疑 native 库 |
| 自动化工具检测 | `AutoToolDetector` | /data/local/tmp 截图/投屏工具文件（minicap/scrcpy/vysor 等）、35+ 模拟点击/自动化应用（按键精灵/AutoJS/触动精灵等） |
| 系统属性 | `SystemPropCollector` | Build 信息、50+ 系统属性、设备标识、网络信息、屏幕参数、内存/存储 |

## 快速集成

### 核心 API

```java
// 获取格式化 JSON 字符串
String json = EnvDetector.detect(context);

// 获取 JSONObject（方便程序内使用）
JSONObject data = EnvDetector.detectAsJson(context);
```

### 权限说明

```xml
<!-- 必需：Frida 端口检测 -->
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />

<!-- 可选：WiFi 信息采集 -->
<uses-permission android:name="android.permission.ACCESS_WIFI_STATE" />

<!-- 可选：IMEI 采集（需运行时权限） -->
<uses-permission android:name="android.permission.READ_PHONE_STATE" />

<!-- 可选：蓝牙检测 -->
<uses-permission android:name="android.permission.BLUETOOTH" />
```

## 输出 JSON 结构

```json
{
  "timestamp": 1711900800000,
  "sdk_version": "1.0.0",
  "root": {
    "su_binary_found": false,
    "su_binary_paths": [],
    "root_apps_found": [],
    "root_files_found": [],
    "test_keys": false,
    "system_rw": false,
    "su_executable": false,
    "selinux_permissive": false
  },
  "emulator": {
    "build_fingerprint_suspicious": false,
    "suspicious_build_fields": {},
    "emulator_files_found": [],
    "suspicious_props": {},
    "imei": "...",
    "phone_number": "",
    "sensors_count": 20,
    "has_accelerometer": true,
    "has_gyroscope": true,
    "battery_temperature": 25.0,
    "supported_abis": ["arm64-v8a", "armeabi-v7a"],
    "has_bluetooth": true,
    "camera_count": 2
  },
  "hook": {
    "xposed_installed": false,
    "xposed_packages": [],
    "xposed_files_found": [],
    "xposed_in_stack": false,
    "xposed_class_loadable": false,
    "frida_port_open": false,
    "frida_in_maps": false,
    "frida_process_found": false,
    "frida_files_found": [],
    "substrate_installed": false,
    "suspicious_native_libs": []
  },
  "auto_tool": {
    "suspicious_tmp_files": [],
    "auto_tool_apps": []
  },
  "system_props": {
    "build": { "...": "..." },
    "props": { "...": "..." },
    "device_id": { "...": "..." },
    "network": { "...": "..." },
    "screen": { "...": "..." },
    "memory": { "...": "..." }
  }
}
```

## 构建

### 环境要求

- Android Studio Arctic Fox 或更高版本
- JDK 11+
- Android SDK 34

### 构建步骤

```bash
# 在 Android Studio 中打开项目目录即可自动配置

# 或使用命令行（需先生成 Gradle Wrapper）
gradle wrapper
./gradlew assembleDebug
```

## 项目结构

```
app/src/main/java/com/envdetect/
├── MainActivity.java              # 演示界面
└── detector/
    ├── EnvDetector.java           # 统一入口 API
    ├── RootDetector.java          # Root 环境检测
    ├── EmulatorDetector.java      # 模拟器/虚拟机检测
    ├── HookDetector.java          # Hook 框架检测
    ├── AutoToolDetector.java      # 截图/模拟点击工具检测
    └── SystemPropCollector.java   # 系统属性采集
```

## 设计原则

- **只采集不判定**：所有模块只输出原始特征值，不包含风险评分或结论
- **容错隔离**：每个检测项独立 try-catch，单项失败不影响其他项
- **异步执行**：检测操作在子线程运行，避免 ANR
- **零依赖**：仅使用 Android SDK 内置 API，无第三方依赖
- **兼容性**：minSdk 21，覆盖 Android 5.0 及以上

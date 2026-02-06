package io.github.sms1sis.oxidoh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            val autoStart = prefs.getBoolean("auto_start", false)
            
            if (autoStart) {
                val serviceIntent = Intent(context, ProxyService::class.java).apply {
                    putExtra("resolverUrl", prefs.getString("resolver_url", "https://odoh.cloudflare-dns.com/dns-query"))
                    putExtra("listenPort", prefs.getString("listen_port", "5053")?.toIntOrNull() ?: 5053)
                    putExtra("bootstrapDns", prefs.getString("bootstrap_dns", "1.1.1.1"))
                    putExtra("heartbeatEnabled", prefs.getBoolean("heartbeat_enabled", true))
                    putExtra("heartbeatDomain", prefs.getString("heartbeat_domain", "google.com"))
                    putExtra("heartbeatInterval", prefs.getString("heartbeat_interval", "10")?.toLongOrNull() ?: 10L)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(serviceIntent)
                } else {
                    context.startService(serviceIntent)
                }
            }
        }
    }
}

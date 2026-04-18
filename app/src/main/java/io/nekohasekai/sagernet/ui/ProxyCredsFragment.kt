package io.nekohasekai.sagernet.ui

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.widget.Toolbar
import com.google.android.material.button.MaterialButton
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.ktx.snackbar
import io.nekohasekai.sagernet.util.ProxyAuth

class ProxyCredsFragment : ToolbarFragment(R.layout.layout_proxy_creds) {

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        toolbar.title = "Local Proxy Access"
        render(view)
    }

    private fun render(view: View) {
        val text = view.findViewById<TextView>(R.id.proxy_creds_text)
        val copySocks = view.findViewById<MaterialButton>(R.id.proxy_creds_copy_socks)
        val copyClash = view.findViewById<MaterialButton>(R.id.proxy_creds_copy_clash)
        val refresh = view.findViewById<MaterialButton>(R.id.proxy_creds_refresh)

        val creds = ProxyAuth.current()
        val port = ProxyAuth.port()
        val clashSecret = ProxyAuth.clashSecret()

        if (creds == null || port == 0) {
            text.text = "VPN is not active.\n\nStart the VPN to generate credentials."
            copySocks.isEnabled = false
            copyClash.isEnabled = false
        } else {
            val (user, pass) = creds
            val url = "socks5://$user:$pass@127.0.0.1:$port"
            val clashLine = if (clashSecret != null) {
                "\nClash secret\n  $clashSecret\n" +
                "  (yacd UI: http://127.0.0.1:9090/ui/)\n"
            } else {
                "\nClash API: disabled\n"
            }

            text.text = buildString {
                append("Address      127.0.0.1\n")
                append("Port         $port\n")
                append("Username     $user\n")
                append("Password     $pass\n")
                append("\n")
                append("SOCKS5 URL\n")
                append("  $url\n")
                append(clashLine)
            }

            copySocks.isEnabled = true
            copySocks.setOnClickListener {
                if (SagerNet.trySetPrimaryClip(url)) {
                    snackbar("Copied SOCKS5 URL").show()
                }
            }

            copyClash.isEnabled = clashSecret != null
            if (clashSecret != null) {
                copyClash.setOnClickListener {
                    if (SagerNet.trySetPrimaryClip(clashSecret)) {
                        snackbar("Copied Clash secret").show()
                    }
                }
            }
        }

        refresh.setOnClickListener { render(view) }
    }
}

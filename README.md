# Firewall Auto-Whitelist for Loon

A Loon plugin that keeps your device's exit IP on a firewall whitelist: po0's, or your own server's. A clean rebuild of the Loon part of [po0fw](https://github.com/reallinzc/po0fw).

| File | What it is |
|---|---|
| `fw-whitelist-po0.plugin` | The plugin, preset for po0's API. Ready to install |
| `fw-whitelist.plugin` | The same plugin for your own server |
| `fw-whitelist.js` | The script both plugins run. Loon downloads it from this repo |

## Install for po0

In Loon, go to **Configuration → Plugins → +** and paste this URL:

```
https://raw.githubusercontent.com/Dokoyamo-Lisa/loon-fw-whitelist/main/fw-whitelist-po0.plugin
```

Or open this link in Safari on your iPhone, which hands the plugin to Loon (GitHub won't make `loon://` links clickable):

```
loon://import?plugin=https%3A%2F%2Fraw.githubusercontent.com%2FDokoyamo-Lisa%2Floon-fw-whitelist%2Fmain%2Ffw-whitelist-po0.plugin
```

Then:

1. Open the plugin's settings and paste your `pgnfw_` token(s) into **po0 tokens**. For several machines, separate them with commas. To pin one to a slot so it's never evicted, add `@N` after it, e.g. `pgnfw_xxx@0`.
2. Run **po0-fw-manual** from Loon's script list. You'll get a notification like:

   ```
   [manual] 1/1 listed · exit 1.2.3.0/24
   #1 OK — listed 2/5
       1.2.3.0/24  <- you
       5.6.7.0/24
   ```

3. Compare it with the whitelist in po0's console.

What this README says about how po0 behaves server-side comes from po0fw's comments, not from po0's documentation.

## Install for your own server

Your server needs to implement the contract below. Then either:

- Install `https://raw.githubusercontent.com/Dokoyamo-Lisa/loon-fw-whitelist/main/fw-whitelist.plugin`, set **API base URL** in its settings, and also add a rule of your own to send your API host DIRECT. A plugin installed from a URL can't be edited, and its built-in rule only covers `fw.example.com`.
- Or fork this repo, replace `fw.example.com` in `fw-whitelist.plugin` with your host, and install your fork's raw URL.

## How the client works

1. **Triggers.** Loon has no "proxy switched on" trigger, so the script uses three:
   - **network-changed** (`-event` tag): Wi-Fi/cellular switches. Waits 3s for the new network, then sends the request.
   - **cron every 15s** (`-cron` tag, `"*/15 * * * * *"`, seconds first). Most ticks exit without sending anything. A tick sends a request when:
     - **Reconnect:** the gap since the previous tick is more than 3× the usual gap (at least 45s). Ticks stop while Loon or the proxy is off, so the first tick after you switch it back on sends a request within about 15s.
     - **Refresh:** the last request was a minute ago, which re-adds you if you were evicted.
     - A tick skips if a run is still retrying, so ticks never cut short the 3 attempts.
   - **generic** (`-manual` tag): you tap it. It sends at once, with no wait.
   - The script tells these apart by tag, which Loon gives it as `$script.name`.
   - If your Loon rejects the 6-field cron, use `cron "* * * * *"`. Reconnect detection adapts to 1-minute ticks, but a reconnect then takes up to a minute to notice.
   - Before Loon 3.5.1 (983), Loon ran only the **first** `network-changed` script in your config. In 983 and later, every enabled one runs.
   - **Units:** the script works in milliseconds everywhere, including Loon's `$httpClient` `timeout` option. Passing `10` there means 10 ms, which caused the earlier `NSURLErrorDomain Code=-1001` timeouts. Only the plugin's `timeout=60` is in seconds.
2. **One call per token:** `POST <api>/api/firewall/<token>/add` with an empty body. The server reads your IP from the connection itself.
3. **DIRECT rule.** Without it, Loon might send the request through your proxy, and the server would whitelist the proxy's exit IP.
4. **Check the reply.** You count as whitelisted if `currentIp` matches a `whitelist` entry, exactly or within the same /24.
5. **Notifications** (the **Notify** setting):
   - `once` (default): the first success on each network, then quiet. It notifies again after a network change, a reconnect, or a change in your exit IP (even without a network event). While failing, it notifies when the result changes, and once more when it recovers.
   - `changes`: when a token's exit IP or OK/FAIL result changes.
   - `always`: after every run that sent a request, about once a minute.
   - Whatever the setting, these always notify: manual runs, and any run where a token still gets a network error after all 3 attempts (`FAILED after retries`).
   - The subtitle starts with why the run happened: `[network]`, `[reconnect]`, `[refresh]` or `[manual]`. Every run that sends a request is also logged to Loon's script log.

## Server contract (what you need to implement)

### `POST /api/firewall/{token}/add[?slot=N]`

- **Auth:** the token in the path. Return 401/404 for an unknown token.
- **Client IP:** the TCP source address. Behind a reverse proxy, use `X-Forwarded-For` / `X-Real-IP`, but only when the request comes from your own proxy.
- **Normalize** the IP to its /24 (`1.2.3.77` → `1.2.3.0/24`). For IPv6, a /64 is the usual equivalent.

**Write rules, no slot:**
- Already listed → only refresh `updated_at`. This repeat call must not use up a new entry.
- Not listed, list not full → insert with `slot = null`.
- Not listed, list full → delete the unpinned entry with the oldest `updated_at`, then insert. If every entry is pinned, reject (e.g. 409).

**Write rules, `?slot=N`:**
- Your IP already in slot N → refresh `updated_at`.
- Slot N holds another IP → replace it.
- Your IP is listed without a slot → move it to slot N.
- Your IP already holds a different slot → **403**.

**Response, 200:**

```json
{
  "enabled": true,
  "limit": 5,
  "currentIp": "1.2.3.0/24",
  "whitelist": [
    { "ip": "1.2.3.0/24", "slot": null },
    { "ip": "5.6.7.0/24", "slot": 0 }
  ]
}
```

**Applying the list:** after each change, sync the list to the real firewall. For example, with an nftables set and the rule `ip saddr @fw_allow tcp dport <port> accept`, add and remove `/24` elements as the list changes.

## Security notes

- The token is the only credential. Make tokens long and random, use HTTPS only, and rate-limit the endpoint.
- A /24 on a cellular network also covers other customers of that carrier. If you need it tighter, whitelist exact IPs; the script already handles both.
- Nothing can remove an entry except eviction. Give yourself a way to delete entries on the server side as well.

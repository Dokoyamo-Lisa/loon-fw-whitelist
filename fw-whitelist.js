/*
 * fw-whitelist.js — Loon script: keep this device's exit IP on a firewall whitelist.
 *
 * For each configured token it calls:
 *
 *     POST <api>/api/firewall/<token>/add[?slot=N]
 *
 * The server whitelists the request's *source address* (nothing is sent in
 * the body), so the request must leave the device DIRECT, not through a
 * proxy; the plugin's [Rule] section takes care of that.
 *
 * Expected response (see README.md for the full contract):
 *   { "enabled": true, "limit": 5, "currentIp": "1.2.3.0/24",
 *     "whitelist": [ { "ip": "1.2.3.0/24", "slot": null }, ... ] }
 *
 * Triggers (told apart by the plugin tag, which Loon exposes as $script.name):
 *   network  — network-changed. Waits 3s for the network, then POSTs.
 *   manual   — the generic script the user taps. POSTs at once.
 *   tick     — cron every 15s. Usually exits without any request. It POSTs
 *              when (a) ticks stopped for a while, meaning Loon / the proxy
 *              was off and was just switched back on ("reconnect"), or
 *              (b) the last POST is REFRESH_MS old.
 *   Loon has no "proxy switched on" trigger, so (a) is how a reconnect gets
 *   whitelisted within one tick.
 *
 * Arguments (from the plugin's [Argument] section):
 *   api    — base URL of your server, e.g. https://fw.example.com
 *   tokens — one or more tokens separated by , | ; or whitespace.
 *            Append @N to pin that token's entry to slot N: abc123@0
 *   notify — "once" (default): one success notification per network. Then
 *            silent until the network changes, the proxy reconnects, or the
 *            exit IP changes. Failures still notify (see below).
 *            "changes": only when a token's exit IP or OK/FAIL changes.
 *            "always": after every run that sent a request.
 * Regardless of notify: manual runs, and runs where a token still had a
 * network error after all 3 attempts, always notify.
 */

/*
 * Units: every time value in this script is in MILLISECONDS, like
 * Date.now(), setTimeout() and Loon's $httpClient `timeout` option
 * (whose default is 5000). Only the plugin's `timeout=60` on each script
 * line is in SECONDS: it is how long Loon lets one run last before
 * killing it.
 */
var SECOND_MS = 1000;

// Per-request limit for $httpClient (milliseconds, NOT seconds).
var TIMEOUT_MS = 10 * SECOND_MS;
// network-changed fires the moment the interface switches, before the new
// network has a route and DNS; wait this long first.
var SETTLE_MS = 3 * SECOND_MS;
// On a network error, retry after each of these delays. Worst case:
// 3s settle + 3 attempts x 10s timeout + 3s + 6s = 42s, under the plugin's
// timeout=60 (seconds).
var RETRY_DELAYS_MS = [3 * SECOND_MS, 6 * SECOND_MS];
// While connected, re-POST this often so evicted entries come back.
var REFRESH_MS = 60 * SECOND_MS;
// A tick is "due" for refresh this much early, so a tick that lands
// slightly before REFRESH_MS doesn't push the request to the next tick.
var REFRESH_SLACK_MS = 5 * SECOND_MS;
// A tick counts as a reconnect when the gap since the previous tick is more
// than 3x the usual gap, and at least this long.
var MIN_RECONNECT_GAP_MS = 45 * SECOND_MS;
// Cap on the remembered "usual" tick gap, so one long outage doesn't hide
// the next reconnect.
var MAX_TICK_GAP_MS = 5 * 60 * SECOND_MS;
// A POST run older than this is assumed dead: Loon kills runs after the
// plugin's timeout=60 (seconds), so 70s is safely past that.
var INFLIGHT_STALE_MS = 70 * SECOND_MS;

var K = {
  state: "fwwl_state_", // + token index: "ip|ok" from the last run
  runId: "fwwl_run_id", // newest automatic POST run; older ones stop
  inflight: "fwwl_inflight", // start of the running POST run (Date.now() ms), or ""
  lastPost: "fwwl_last_post", // end of the last finished POST run (Date.now() ms)
  lastTick: "fwwl_last_tick", // previous cron tick (Date.now() ms)
  tickGap: "fwwl_tick_gap", // usual gap between ticks (ms)
  notified: "fwwl_notified", // exit IPs already announced this network; "" = not yet
};

/* ---------- storage ---------- */

function get(key) {
  return $persistentStore.read(key);
}
function set(key, value) {
  $persistentStore.write(String(value), key);
}
function getNum(key) {
  var n = parseInt(get(key), 10);
  return isNaN(n) ? null : n;
}

/* ---------- arguments ---------- */

// Loon passes $argument as an object when the plugin uses argument=[{a},{b}],
// and as a "k=v&k=v" or JSON string in other setups. Accept all three.
function readArgs() {
  var raw = typeof $argument === "undefined" || $argument === null ? {} : $argument;
  if (typeof raw === "object") return raw;

  var s = String(raw).trim().replace(/^["']|["']$/g, "");
  if (s.charAt(0) === "{") {
    try {
      return JSON.parse(s);
    } catch (e) {}
  }
  var out = {};
  s.split("&").forEach(function (pair) {
    var i = pair.indexOf("=");
    if (i > 0) out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  });
  return out;
}

// "abc@0, def" -> [{token:"abc", slot:0}, {token:"def", slot:null}]
function parseTokens(str) {
  return String(str || "")
    .split(/[,|;\s]+/)
    .filter(Boolean)
    .map(function (s) {
      var at = s.indexOf("@");
      if (at === -1) return { token: s, slot: null };
      var n = parseInt(s.slice(at + 1), 10);
      return { token: s.slice(0, at), slot: isNaN(n) ? null : n };
    });
}

/* ---------- helpers ---------- */

// True when a and b are the same IP, or when either is an x.x.x.0/24 entry
// and both fall inside the same /24.
function sameC24(a, b) {
  if (!a || !b) return false;
  a = String(a);
  b = String(b);
  if (a === b) return true;
  if (a.slice(-3) !== "/24" && b.slice(-3) !== "/24") return false;
  var pa = a.replace("/24", "").split(".");
  var pb = b.replace("/24", "").split(".");
  return pa.length === 4 && pb.length === 4 && pa.slice(0, 3).join(".") === pb.slice(0, 3).join(".");
}

function sleep(ms) {
  return new Promise(function (resolve) {
    setTimeout(resolve, ms);
  });
}

// Loon documents $script.name as the script's name or tag. The plugin's tags
// end in -event, -cron and -manual. $script.type is checked too in case a
// Loon version provides it.
function detectTrigger() {
  try {
    var s = typeof $script === "object" && $script ? $script : {};
    var label = (String(s.name || "") + " " + String(s.tag || "")).toLowerCase();
    var type = String(s.type || "").toLowerCase();
    if (type === "generic" || /manual/.test(label)) return "manual";
    if (type === "network-changed" || /event|network/.test(label)) return "network";
  } catch (e) {}
  return "tick";
}

// Every automatic POST run stamps a unique id. A newer one overwrites it,
// and the older run stops instead of sending a stale POST or overwriting
// newer results. Manual runs use runId = null and are never cancelled.
function isSuperseded(runId) {
  return runId !== null && get(K.runId) !== runId;
}

function post(url) {
  return new Promise(function (resolve) {
    $httpClient.post(
      {
        url: url,
        headers: { "Content-Type": "application/json" },
        body: "",
        timeout: TIMEOUT_MS,
        // Send DIRECT whatever the rules say, so the server sees this
        // device's real exit IP (the plugin's [Rule] is a second guard).
        node: "DIRECT",
      },
      function (err, resp, body) {
        if (err) resolve({ error: String(err) });
        else resolve({ status: resp && (resp.status || resp.statusCode), body: body });
      }
    );
  });
}

/* ---------- one token ---------- */

// POST, retrying only on network errors. An HTTP reply (even 403/500) is a
// real answer from the server and is returned as-is. Stops early if a newer
// run has started.
function postWithRetry(url, runId) {
  var attempt = 0;
  function tryOnce() {
    return post(url).then(function (r) {
      if (!r.error || attempt >= RETRY_DELAYS_MS.length) return r;
      var wait = RETRY_DELAYS_MS[attempt++];
      console.log("network error (" + r.error + "), retry " + attempt + " in " + wait + "ms");
      return sleep(wait).then(function () {
        return isSuperseded(runId) ? { superseded: true } : tryOnce();
      });
    });
  }
  return tryOnce();
}

function whitelist(api, item, runId) {
  var url = api + "/api/firewall/" + encodeURIComponent(item.token) + "/add";
  if (item.slot !== null) url += "?slot=" + item.slot;

  return postWithRetry(url, runId).then(function (r) {
    if (r.superseded) return { superseded: true };
    // Still a network error after every retry: flag it so it always notifies.
    if (r.error) {
      return {
        ok: false,
        exhausted: true,
        msg: "failed after " + (RETRY_DELAYS_MS.length + 1) + " attempts: " + r.error,
      };
    }

    var data = null;
    try {
      data = JSON.parse(r.body);
    } catch (e) {}

    if (r.status === 403) return { ok: false, msg: "slot conflict: this IP already holds another slot" };
    if (r.status !== 200 || !data) {
      return { ok: false, msg: "HTTP " + r.status + ": " + String(r.body).slice(0, 80) };
    }
    if (data.enabled === false) return { ok: false, ip: data.currentIp, msg: "firewall disabled" };

    // Entries may be {ip, slot} objects or plain strings.
    var entries = (data.whitelist || []).map(function (e) {
      return typeof e === "object" ? e : { ip: e, slot: null };
    });
    var listed = entries.some(function (e) {
      return sameC24(e.ip, data.currentIp);
    });

    return {
      ok: listed,
      ip: data.currentIp,
      msg: (listed ? "listed " : "NOT listed ") + entries.length + "/" + data.limit,
      entries: entries,
    };
  });
}

/* ---------- deciding whether to run ---------- */

// Called on every cron tick. Records the tick and reports whether the gap
// since the previous one means Loon was off (a reconnect).
function checkTick(now) {
  var last = getNum(K.lastTick);
  var usual = getNum(K.tickGap) || REFRESH_MS;
  set(K.lastTick, now);
  if (last === null) return true; // first tick ever
  var gap = now - last;
  // Remember the latest gap as "usual", capped so one long outage
  // doesn't hide the next one.
  set(K.tickGap, Math.min(gap, MAX_TICK_GAP_MS));
  return gap > Math.max(MIN_RECONNECT_GAP_MS, 3 * usual);
}

// Returns why this run should send requests, or null to exit quietly.
function reasonToRun(trigger, now) {
  if (trigger === "manual") return "manual";
  if (trigger === "network") return "network";

  if (checkTick(now)) return "reconnect";
  var started = getNum(K.inflight);
  if (started !== null && now - started < INFLIGHT_STALE_MS) return null; // a run is working
  var lastPost = getNum(K.lastPost);
  if (lastPost === null || now - lastPost >= REFRESH_MS - REFRESH_SLACK_MS) return "refresh";
  return null;
}

/* ---------- notifications ---------- */

function shouldNotify(mode, reason, summary) {
  // Bookkeeping for "once" first, whatever the outcome: a success records
  // which exit IPs were announced; a failure clears it, so the recovery is
  // announced too.
  var firstSuccess = false;
  if (summary.allOk) {
    firstSuccess = get(K.notified) !== summary.ipKey;
    set(K.notified, summary.ipKey);
  } else {
    set(K.notified, "");
  }

  if (reason === "manual" || summary.exhausted || mode === "always") return true;
  if (mode === "changes") return summary.changed;
  // "once": the first success on each network, and failures when they change.
  return summary.allOk ? firstSuccess : summary.changed;
}

/* ---------- main ---------- */

function main() {
  var args = readArgs();
  var api = String(args.api || "").replace(/\/+$/, "");
  var tokens = parseTokens(args.tokens);
  var mode = String(args.notify || "once").toLowerCase();

  if (!/^https?:\/\//.test(api) || tokens.length === 0) {
    $notification.post("Firewall whitelist", "Not configured", "Set api and tokens in the plugin's arguments.");
    return $done();
  }

  var now = Date.now();
  var trigger = detectTrigger();
  var reason = reasonToRun(trigger, now);
  if (!reason) return $done(); // routine tick: nothing to do

  // A new network or a reconnect starts a new "once" round.
  if (reason === "network" || reason === "reconnect") set(K.notified, "");

  var runId = null;
  if (reason !== "manual") {
    runId = now + "-" + Math.random().toString(36).slice(2, 8);
    set(K.runId, runId);
    set(K.inflight, now);
  }
  console.log("fw-whitelist: run (" + reason + ")");

  function finish() {
    if (runId !== null && !isSuperseded(runId)) set(K.inflight, "");
    $done();
  }

  sleep(reason === "network" ? SETTLE_MS : 0)
    .then(function () {
      if (isSuperseded(runId)) return null;
      return Promise.all(
        tokens.map(function (t) {
          return whitelist(api, t, runId);
        })
      );
    })
    .then(function (results) {
      // A newer run took over: leave state and notifications to it.
      if (
        !results ||
        isSuperseded(runId) ||
        results.some(function (r) {
          return r.superseded;
        })
      ) {
        console.log("fw-whitelist: superseded by a newer run, exiting");
        return $done();
      }
      set(K.lastPost, Date.now());

      var changed = false;
      var lines = results.map(function (r, i) {
        var state = (r.ip || "?") + "|" + (r.ok ? 1 : 0);
        if (get(K.state + i) !== state) {
          set(K.state + i, state);
          changed = true;
        }
        var pin = tokens[i].slot !== null ? " [slot " + tokens[i].slot + "]" : "";
        var line = "#" + (i + 1) + pin + " " + (r.ok ? "OK" : "FAIL") + " — " + r.msg;
        if (r.entries) {
          line += r.entries
            .map(function (e) {
              return (
                "\n    " + e.ip + (e.slot !== null && e.slot !== undefined ? " [slot " + e.slot + "]" : "") +
                (sameC24(e.ip, r.ip) ? "  <- you" : "")
              );
            })
            .join("");
        }
        return line;
      });

      var okCount = results.filter(function (r) {
        return r.ok;
      }).length;
      var ips = results.map(function (r) {
        return r.ip || "?";
      });
      var summary = {
        changed: changed,
        allOk: okCount === results.length,
        exhausted: results.some(function (r) {
          return r.exhausted;
        }),
        ipKey: ips.join(","),
      };
      var subtitle =
        "[" + reason + "] " +
        (summary.exhausted ? "FAILED after retries · " : "") +
        okCount + "/" + results.length + " listed · exit " + ips[0];
      var body = lines.join("\n");

      console.log(subtitle + "\n" + body);
      if (shouldNotify(mode, reason, summary)) $notification.post("Firewall whitelist", subtitle, body);
      finish();
    })
    .catch(function (e) {
      console.log("fw-whitelist crashed: " + e);
      finish();
    });
}

main();

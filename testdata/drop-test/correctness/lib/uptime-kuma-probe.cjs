// uptime-kuma socket.io probe — drives what only socket.io can (admin setup,
// login, monitor CRUD) so a drop-test can exercise a RUNNING monitor, not just
// the serving/auth stack. Run from a sidecar using the uptime-kuma image itself
// (node + socket.io-client baked in) sharing the target's netns; the script is
// bind-mounted, so NOTHING is written inside the target.
//
//   node uptime-kuma-probe.cjs <http|ping>
//
// Exit 0 = the monitor of that type reported an UP heartbeat (status 1).
const type = process.argv[2] || "http";
const { io } = require("socket.io-client");
const s = io("http://localhost:3001", { reconnection: false });
const emit = (ev, ...a) => new Promise((res, rej) => {
  const t = setTimeout(() => rej(new Error(ev + " timeout")), 15000);
  s.emit(ev, ...a, (r) => { clearTimeout(t); res(r); });
});
(async () => {
  await new Promise((res, rej) => { s.on("connect", res); s.on("connect_error", rej); });
  await emit("setup", "csdadmin", "CsdProbe-Pw-12345").catch(() => {}); // ok if already set up
  await emit("login", { username: "csdadmin", password: "CsdProbe-Pw-12345", token: "" });
  const base = { name: "csd-" + type, interval: 20, maxretries: 1, retryInterval: 20,
    conditions: [], notificationIDList: {}, accepted_statuscodes: ["200-299"], timeout: 10 };
  const mon = type === "ping"
    ? { ...base, type: "ping", hostname: "127.0.0.1", packetSize: 56 }
    : { ...base, type: "http", url: "http://localhost:3001/api/entry-page", method: "GET" };
  const r = await emit("add", mon);
  if (!r || !r.ok) { console.error("add failed:", JSON.stringify(r)); process.exit(1); }
  const id = r.monitorID;
  for (let i = 0; i < 20; i++) {
    const list = await emit("getMonitorBeats", id, 168).catch(() => null);
    const beats = list && Array.isArray(list.data) ? list.data : [];
    if (beats.length) {
      const last = beats[beats.length - 1];
      if (last.status === 1) { console.log(type + " monitor UP"); process.exit(0); }
      if (last.status === 0 && i > 4) console.error(type + " DOWN beat:", last.msg);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  console.error(type + " monitor never reported UP");
  process.exit(3);
})().catch((e) => { console.error("ERR", e.message); process.exit(2); });

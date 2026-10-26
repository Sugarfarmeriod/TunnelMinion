// 地图即工作台草图：全部是假数据，不发任何请求。CSP 只允许 self，所以不用内联样式和内联事件。
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const NS = "http://www.w3.org/2000/svg";
  const PX = 6;
  const sleep = (ms) => new Promise((r) => later(ms, r));
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  // 演示期间的定时器统一登记，"重新开始"时全部取消
  let timers = [];
  let epoch = 0;
  function later(ms, fn) { timers.push(setTimeout(fn, ms)); }

  /* ---------- 假数据 ---------- */
  // 这台电脑只知道自己到每台对端通不通，不知道对端之间怎么连、走哪种网络，所以画成星形
  const UP = "#b083f0";
  const NODES = [
    { id: "win", name: "这台电脑", os: "Windows", kind: "desktop", x: 240, y: 380, online: true, local: true },
    { id: "lap", name: "笔记本", os: "Windows", kind: "laptop", x: 250, y: 160, online: true, seen: "1 分钟前" },
    { id: "mac", name: "Mac mini", os: "macOS", kind: "mini", x: 690, y: 260, online: true, seen: "2 分钟前" },
    { id: "old", name: "旧笔记本", os: "Windows", kind: "laptop", x: 820, y: 460, online: false, last: "3 天前" },
  ];
  const LINKS = [["win", "lap"], ["win", "mac"], ["win", "old"]];
  const STATUS = { ok: "正常", down: "打不开", stopped: "已停止" };
  const ORDER = { down: 0, stopped: 1, ok: 2 };
  const KIND = { docker: "Docker", python: "Python", program: "程序" };

  function freshServices() {
    return [
      { id: "blog", node: "win", name: "博客预览", kind: "program", port: 4000, desc: "本地写作实时预览", status: "ok" },
      { id: "dash", node: "win", name: "数据看板", kind: "python", port: 8501, desc: "Streamlit 做的收支统计", status: "stopped" },
      { id: "penpot", node: "win", name: "Penpot", kind: "docker", port: 9001, desc: "设计稿", status: "ok" },
      { id: "jupyter", node: "lap", name: "Jupyter", kind: "python", port: 8888, desc: "实验笔记本", status: "ok" },
      { id: "photos", node: "mac", name: "相册", kind: "docker", port: 2342, desc: "家庭照片备份与浏览", status: "down" },
      { id: "qwen", node: "mac", name: "本地大模型 Qwen", kind: "program", port: 8082, desc: "兼容 OpenAI 接口", status: "ok" },
      { id: "dl", node: "mac", name: "下载管理", kind: "docker", port: 8080, desc: "qBittorrent 网页界面", status: "ok" },
      { id: "ha", node: "mac", name: "Home Assistant", kind: "docker", port: 8123, desc: "智能家居中控", status: "ok" },
      { id: "grafana", node: "mac", name: "Grafana", kind: "docker", port: 3000, desc: "监控图表", status: "ok" },
      { id: "gitea", node: "mac", name: "Gitea", kind: "docker", port: 3001, desc: "自建 Git 仓库", status: "ok" },
      { id: "jelly", node: "mac", name: "Jellyfin", kind: "docker", port: 8096, desc: "影音库", status: "ok" },
      { id: "kuma", node: "mac", name: "Uptime Kuma", kind: "docker", port: 3002, desc: "服务在线监控", status: "ok" },
      { id: "n8n", node: "mac", name: "n8n 自动化", kind: "docker", port: 5678, desc: "工作流自动化", status: "stopped" },
    ];
  }

  // 修法内容沿用 agent-fix.md 的五件事
  const REPAIRS = {
    dash: {
      node: "win", svc: "dash", thread: "t-dash",
      title: "数据看板已停止", short: "脚本 40 分钟前退出了。Agent 建议按原来的方式重新拉起。",
      what: "重新启动 Python 脚本 <b>dashboard.py</b>（用原来的 Python、原来的目录、原来的参数）",
      why: "它 40 分钟前退出了；端口 8501 现在没人在听；Agent 有它上次的启动记录。",
      impact: "脚本会在后台运行，不会回到原来那个终端窗口；输出写进 TunnelMinion 的日志。不改动任何文件。",
      verify: "启动后我会再打开一次数据看板首页。",
      fallback: "如果端口一直没起来，我会把这次拉起的进程停掉，回到“已停止”，告诉你日志要点。",
      cmd: "&lt;启动记录里的 Python&gt; dashboard.py --server.port 8501",
      steps: ["再核对一次：端口 8501 还空着，脚本没有自己起来", "正在按启动记录重新拉起", "正在确认：打开数据看板首页"],
      ok: "修好了。数据看板在运行，首页能正常打开（耗时 6 秒）。",
      badStep: "确认失败：脚本启动 3 秒后又退出了",
      bad: "没修好。脚本启动 3 秒后又退出了，日志里写着“找不到模块 pandas”。我已经停掉这次拉起的进程，回到“已停止”。可能原来是在另一个 Python 环境里运行的。",
      minutesLeft: 8,
    },
    photos: {
      node: "mac", svc: "photos", thread: null, remote: true,
      title: "相册打不开", short: "两个容器 13 分钟前都退出了。Mac mini 的 Agent 建议重启。",
      what: "重启 Docker 容器组 <b>photos</b>（2 个容器）",
      why: "两个容器 13 分钟前都退出了；端口 2342 现在没人在听；日志最后一行是“收到停止信号”。",
      impact: "重启大约需要半分钟，这期间相册打不开；正在上传的照片可能要重新传。不会删除任何照片或设置。",
      verify: "重启后 Mac mini 会再打开一次相册首页。",
      fallback: "Mac mini 会停下来，告诉你卡在哪，不会反复重启。",
      cmd: "docker start photos-app-1 photos-db-1",
      steps: ["把批准交给 Mac mini", "Mac mini 再核对一次：容器还是原来那两个", "Mac mini 正在重启容器", "Mac mini 正在确认：打开相册首页"],
      ok: "修好了。两个容器都在运行，相册首页能正常打开（耗时 21 秒）。记录保存在 Mac mini 上。",
      badStep: "确认失败：容器启动 5 秒后又退出了",
      bad: "没修好。容器一启动就退出，日志里写着“数据库文件被占用”。Mac mini 没有再重启。建议先看看是不是另一个程序也在用这个数据目录。",
      minutesLeft: 10,
    },
  };

  function freshHistory() {
    return [
      { id: "t-dash", title: "数据看板为什么打不开？", when: "40 分钟前", where: "这台电脑", msgs: [
        { role: "user", text: "数据看板为什么打不开？", ctx: { node: "win", svc: "dash" } },
        { role: "agent", who: "win", basis: "checked", text: "数据看板的脚本 dashboard.py 40 分钟前退出了，端口 8501 现在没人在听。我有它上次的启动记录，可以按原来的方式重新拉起。已经放到这台电脑头上的感叹号里，点它就能批准。",
          evidence: ["端口清单：8501 没有程序在听（刚刚）", "启动记录：入口 dashboard.py，上次在 8501 端口", "进程清单：没有 dashboard.py"], fix: "dash" },
      ] },
      { id: "t-jup", title: "Jupyter 的地址是多少？", when: "昨天", where: "笔记本", msgs: [
        { role: "user", text: "Jupyter 的地址是多少？" },
        { role: "agent", who: "win", basis: "checked", text: "Jupyter 在笔记本上，端口 8888，现在能正常打开。在地图上点“笔记本”就能看到“打开”按钮。", evidence: ["服务清单（笔记本，1 分钟前）"] },
      ] },
      { id: "t-mem", title: "Mac mini 上哪个容器最占内存？", when: "3 天前", where: "Mac mini", msgs: [
        { role: "user", text: "Mac mini 上哪个容器最占内存？" },
        { role: "agent", who: "mac", basis: "inferred", text: "容器里最占内存的是下载管理，约 1.4 GB；整台机器最占内存的是本地大模型 Qwen（不是容器），约 21 GB。", evidence: ["容器资源占用（Mac mini）", "进程资源占用（Mac mini）"] },
      ] },
    ];
  }

  let state;
  function freshState() {
    return {
      services: freshServices(),
      pending: { win: "dash" },       // 电脑 → 待批准的修复
      busyNode: {},                    // 电脑 → "thinking" | "working"
      selected: null, page: 0, pageSize: 6,
      history: freshHistory(),
      current: null,                   // 当前对话的 id
      tab: "now",
      unread: 0,
      ctx: null,                       // 抽屉输入框带着的上下文
      asking: false,
      modal: null,                     // { key, phase: "ask" | "run" | "done" }
    };
  }

  const node = (id) => NODES.find((n) => n.id === id);
  const svc = (id) => state.services.find((s) => s.id === id);
  const thread = (id) => state.history.find((t) => t.id === id);
  const opts = () => ({ fail: $("optFail").checked, noProxy: $("optNoProxy").checked });

  /* ---------- 像素小电脑（与 pixel.html 相同的精灵） ---------- */
  const SPRITES = {
    desktop: ["................", ".FFFFFFFFFFFFFF.", ".FSSSSSSSSSSSSF.", ".FSHHSSSSSSSSSF.", ".FSHSSSSSSSSSSF.", ".FSSSSSSSSSSSSF.", ".FSSSSSSSSSSSSF.",
      ".FSSSSSSSSSSSSF.", ".FSSSSSSSSSSSSF.", ".FFFFFFFFFFFFFF.", ".FFFFFFFFFFFFLF.", "......DDDD......", "......DDDD......", "...DDDDDDDDDD..."],
    laptop: ["................", "................", "..FFFFFFFFFFFF..", "..FSSSSSSSSSSF..", "..FSHHSSSSSSSF..", "..FSHSSSSSSSSF..", "..FSSSSSSSSSSF..",
      "..FSSSSSSSSSSF..", "..FSSSSSSSSSSF..", "..FFFFFFFFFFFF..", ".BBBBBBBBBBBBBB.", "BKKKKKKKKKKKKKKB", "BBBBBBBBBBBBBBBB", ".DDDDDDDDDDDDDD."],
    mini: ["................", "................", "................", "................", "................", "................", "..WWWWWWWWWWWW..",
      ".WBBBBBBBBBBBBW.", "WBBBBBBBBBBBBBBW", "WBBBBBBBBBBBBBBW", "DDDDDDDDDDDDDDDD", "DKKKKKKKKKKKKLKD", "DDDDDDDDDDDDDDDD", ".DDDDDDDDDDDDDD."],
  };
  const COLORS = { F: "#94b0c2", S: "#3b5dc9", H: "#73eff7", L: "#a7f070", D: "#566c86", B: "#94b0c2", K: "#333c57", W: "#f4f4f4" };

  function spriteSvg(kind, online) {
    let out = "";
    SPRITES[kind].forEach((row, r) => [...row].forEach((ch, c) => {
      if (ch === ".") return;
      let fill = COLORS[ch];
      if (!online && (ch === "S" || ch === "H")) fill = "#333c57";
      if (!online && ch === "L") fill = "#1a1c2c";
      out += `<rect x="${c * PX}" y="${r * PX}" width="${PX}" height="${PX}" fill="${fill}"${ch === "L" ? ` class="led${online ? " blink" : ""}"` : ""}/>`;
    }));
    if (online && kind !== "mini") out += `<rect class="blink" x="${4 * PX}" y="${7 * PX}" width="${PX}" height="${PX}" fill="#73eff7"/>`;
    return out;
  }
  function brackets() {
    const w = 16 * PX + 16, h = 14 * PX + 16, l = 14, t = 4, x0 = -8, y0 = -8;
    return [[x0, y0, l, t], [x0, y0, t, l], [x0 + w - l, y0, l, t], [x0 + w - t, y0, t, l],
      [x0, y0 + h - t, l, t], [x0, y0 + h - l, t, l], [x0 + w - l, y0 + h - t, l, t], [x0 + w - t, y0 + h - l, t, l]]
      .map(([x, y, ww, hh]) => `<rect x="${x}" y="${y}" width="${ww}" height="${hh}" fill="#ffcd75"/>`).join("");
  }
  // 红色感叹号：这台电脑上有一个待批准的修复
  const bangSvg = (id) => `<g class="bubble" data-bang="${id}" role="button" tabindex="0" aria-label="${esc(node(id).name)} 有一个待批准的修复">
    <rect x="30" y="-50" width="36" height="34" fill="#f4f4f4"/><rect x="26" y="-46" width="44" height="26" fill="#f4f4f4"/>
    <rect x="42" y="-16" width="8" height="6" fill="#f4f4f4"/><rect x="44" y="-10" width="4" height="4" fill="#f4f4f4"/>
    <rect x="45" y="-46" width="6" height="16" fill="#e05265"/><rect x="45" y="-27" width="6" height="5" fill="#e05265"/></g>`;
  // 思考气泡：这台电脑的 Agent 正在查
  const thinkSvg = () => `<g class="think"><rect x="24" y="-44" width="48" height="24" fill="#f4f4f4"/><rect x="20" y="-40" width="56" height="16" fill="#f4f4f4"/>
    <rect x="30" y="-20" width="6" height="6" fill="#f4f4f4"/>
    <rect class="d" x="32" y="-35" width="6" height="6" fill="#1a1c2c"/><rect class="d d2" x="45" y="-35" width="6" height="6" fill="#1a1c2c"/><rect class="d d3" x="58" y="-35" width="6" height="6" fill="#1a1c2c"/></g>`;

  function nodeSummary(n) {
    if (!n.online) return [`○ 离线 · 上次在线 ${n.last}`, "#566c86"];
    if (state.busyNode[n.id] === "thinking") return ["◌ 正在查……", "#ffcd75"];
    if (state.busyNode[n.id] === "working") return ["◌ 正在修……", "#ffcd75"];
    const list = state.services.filter((s) => s.node === n.id);
    if (state.pending[n.id]) return ["! 有 1 件事要你批准", "#e05265"];
    const down = list.filter((s) => s.status === "down").length;
    const stopped = list.filter((s) => s.status === "stopped").length;
    if (down) return [`● ${list.length} 个服务 · ${down} 个打不开`, "#e05265"];
    if (stopped) return [`● ${list.length} 个服务 · ${stopped} 个已停止`, "#94b0c2"];
    return [`● 在线 · ${list.length} 个服务`, "#a7f070"];
  }

  /* ---------- 拓扑 ---------- */
  const center = (n) => ({ x: n.x, y: n.y - 40 });
  function drawLinks() {
    $("links").innerHTML = LINKS.map(([a, b]) => {
      const A = node(a), B = node(b), pa = center(A), pb = center(B), up = A.online && B.online;
      return `<line class="link" data-a="${a}" data-b="${b}" x1="${pa.x}" y1="${pa.y}" x2="${pb.x}" y2="${pb.y}" stroke="${up ? UP : "#566c86"}" stroke-width="4"${up ? "" : ' stroke-dasharray="10 10"'}/>`;
    }).join("");
  }
  function drawNodes() {
    $("nodes").innerHTML = NODES.map((n) => {
      const [txt, col] = nodeSummary(n);
      const cls = ["node", n.online ? "" : "offline", state.selected === n.id ? "selected" : "",
        state.busyNode[n.id] === "thinking" ? "thinking" : "", state.busyNode[n.id] === "working" ? "working" : ""].join(" ");
      return `<g class="${cls}" data-id="${n.id}" transform="translate(${n.x},${n.y})" role="button" tabindex="0" aria-label="${esc(n.name)}，${esc(txt.slice(2))}">
        <rect x="${-6 * PX}" y="-6" width="${12 * PX}" height="${PX}" fill="#1a1c2c" opacity=".55"/>
        <g class="body"><g transform="translate(${-8 * PX},${-14 * PX - 6})">
          <g class="brackets">${brackets()}</g>
          <g class="sprite">${spriteSvg(n.kind, n.online)}</g>
          ${state.pending[n.id] && !state.busyNode[n.id] ? bangSvg(n.id) : ""}
          ${thinkSvg()}
        </g></g>
        <text class="label" y="30">${esc(n.name)}</text>
        <text class="status" y="52" fill="${col}">${esc(txt)}</text>
      </g>`;
    }).join("");
  }
  function hot(id, on) {
    document.querySelectorAll(".link").forEach((l) => { if (l.dataset.a === id || l.dataset.b === id) l.classList.toggle("hot", on); });
  }
  function updateSummary() {
    const on = NODES.filter((n) => n.online).length;
    const fixes = Object.keys(state.pending).length;
    $("summary").textContent = `${on} 台在线 · ${NODES.length - on} 台离线 · ${state.services.length} 个服务` + (fixes ? ` · ${fixes} 件事等你批准` : "");
  }
  function redrawMap() { drawNodes(); updateSummary(); if (state.selected) drawPop(); }

  /* ---------- 悬停提示 ---------- */
  let tipEl = null;
  function showTip(e, id) {
    if (state.selected) return hideTip();
    const n = node(id), st = $("stage").getBoundingClientRect();
    if (!tipEl) { tipEl = document.createElement("div"); tipEl.className = "tip"; $("stage").appendChild(tipEl); }
    tipEl.innerHTML = `<div class="st-gold">${esc(n.name)} · ${n.os}</div><div>${esc(nodeSummary(n)[0].slice(2))}</div><div class="muted">点一下查看</div>`;
    let left = e.clientX - st.left + 18, top = e.clientY - st.top + 18;
    if (left + tipEl.offsetWidth > st.width - 8) left = e.clientX - st.left - tipEl.offsetWidth - 18;
    if (top + tipEl.offsetHeight > st.height - 8) top = e.clientY - st.top - tipEl.offsetHeight - 18;
    tipEl.style.left = Math.max(4, left) + "px";
    tipEl.style.top = Math.max(4, top) + "px";
  }
  function hideTip() { if (tipEl) { tipEl.remove(); tipEl = null; } }

  /* ---------- 点电脑：旁边弹出服务框（分页，不长滚动） ---------- */
  function select(id) {
    hideTip();
    if (state.selected === id) return closePop();
    state.selected = id; state.page = 0; state.pageSize = 6;
    drawNodes(); drawPop();
    $("pop").focus();
  }
  function closePop() {
    const id = state.selected;
    state.selected = null; drawNodes(); drawPop();
    const el = document.querySelector(`.node[data-id="${id}"]`); if (el) el.focus();
  }

  function drawPop() {
    const p = $("pop");
    if (!state.selected) { p.hidden = true; $("poptail").hidden = true; return; }
    const n = node(state.selected);
    p.hidden = false; p.tabIndex = -1;
    if (!n.online) {
      p.innerHTML = `<div class="head"><h2 id="popTitle">${esc(n.name)}</h2><button class="x" type="button" data-act="close-pop" aria-label="关闭">×</button></div>
        <div class="meta">${n.os} · 离线（上次在线 ${n.last}）</div>
        <div class="muted">这台电脑现在不在线，它上面的服务暂时看不到，也不能把问题交给它。开机并启动 TunnelMinion 后会自动出现。</div>`;
      return placePop();
    }
    const list = state.services.filter((s) => s.node === n.id);
    const bad = list.filter((s) => s.status !== "ok").length;
    const rk = state.pending[n.id], r = rk && REPAIRS[rk];
    p.innerHTML = `<div class="head"><h2 id="popTitle">${esc(n.name)}</h2><button class="x" type="button" data-act="close-pop" aria-label="关闭">×</button></div>
      <div class="meta">${n.os} · ${list.length} 个服务${bad ? ` · <span class="st-down">${bad} 个不正常</span>` : ""}</div>
      ${r ? `<div class="warn"><div class="t">! ${esc(r.title)}</div><div>${esc(r.short)}</div>
        <div class="acts"><button class="btn go" type="button" data-act="fix" data-node="${n.id}">看看怎么修</button></div></div>` : ""}
      <div id="poplist"></div>
      <div class="foot">
        <button class="btn ask" type="button" data-act="ask-node" data-node="${n.id}">问问 ${esc(n.name)} 的 Agent</button>
        ${n.local ? "" : `<span class="src">清单由 ${esc(n.name)} 报来 · ${n.seen}</span>`}
      </div>
      <div class="morehint" id="morehint" hidden>▼ 下面还有</div>`;
    refreshList();
  }

  function refreshList() {
    drawList(); placePop();
    const p = $("pop");
    let guard = 6;
    // 放不下时减少每页条数，尽量不出现滚动
    while (window.innerWidth > 760 && state.pageSize > 3 && p.scrollHeight > p.clientHeight + 1 && guard--) {
      state.pageSize--; drawList(); placePop();
    }
    updateHint();
  }
  function drawList() {
    const el = $("poplist"); if (!el) return;
    const all = state.services.filter((s) => s.node === state.selected)
      .sort((a, b) => ORDER[a.status] - ORDER[b.status] || a.name.localeCompare(b.name, "zh"));
    const pages = Math.max(1, Math.ceil(all.length / state.pageSize));
    state.page = Math.min(Math.max(0, state.page), pages - 1);
    const shown = all.slice(state.page * state.pageSize, (state.page + 1) * state.pageSize);
    const pager = pages > 1 ? `<div class="pager">
        <button class="btn" type="button" data-act="page" data-d="-1" ${state.page === 0 ? "disabled" : ""} aria-label="上一页">◀</button>
        <span>第 ${state.page + 1} / ${pages} 页</span>
        <button class="btn" type="button" data-act="page" data-d="1" ${state.page === pages - 1 ? "disabled" : ""} aria-label="下一页">▶</button></div>` : "";
    el.innerHTML = pager + shown.map((s) => `<div class="svc">
        <span class="sq sq-${s.status}"></span>
        <span class="n">${esc(s.name)} <span class="st-${s.status}">${STATUS[s.status]}</span></span>
        <span class="acts">
          ${s.status === "ok" ? `<button class="btn small" type="button" data-act="open" data-svc="${s.id}">打开</button>` : ""}
          <button class="btn small ask" type="button" data-act="ask-svc" data-svc="${s.id}">问问</button>
        </span>
        <span class="d">${KIND[s.kind]} · 端口 ${s.port} · ${esc(s.desc)}</span>
      </div>`).join("");
  }
  function updateHint() {
    const p = $("pop"), h = $("morehint");
    if (h) h.hidden = p.scrollHeight - p.scrollTop - p.clientHeight <= 4;
  }
  function placePop() {
    const p = $("pop"), tail = $("poptail");
    if (p.hidden || window.innerWidth <= 760) { p.style.maxHeight = ""; tail.hidden = true; return; }
    const svg = $("map"), stage = $("stage"), n = node(state.selected), m = svg.getScreenCTM(), st = stage.getBoundingClientRect();
    const pt = svg.createSVGPoint(); pt.x = n.x; pt.y = n.y - 50;
    const a = pt.matrixTransform(m), ax = a.x - st.left, ay = a.y - st.top, half = 62 * m.a;
    const maxH = Math.max(stage.clientHeight - 16, 420);
    p.style.maxHeight = maxH + "px";
    const w = p.offsetWidth, h = Math.min(p.offsetHeight, maxH);
    let left = ax + half + 18, side = "right";
    if (left + w > stage.clientWidth - 8) { left = ax - half - 18 - w; side = "left"; }
    left = Math.max(8, left);
    const top = Math.min(Math.max(8, ay - 60), Math.max(8, stage.clientHeight - h - 8));
    p.style.left = left + "px"; p.style.top = top + "px";
    tail.hidden = false;
    tail.className = "poptail " + side;
    tail.style.left = (side === "right" ? left - 7 : left + w - 11) + "px";
    tail.style.top = (Math.min(Math.max(ay, top + 24), top + h - 24) - 9) + "px";
  }

  /* ---------- 右侧对话抽屉 ---------- */
  function openDrawer(tab) {
    if (tab) state.tab = tab;
    document.body.classList.add("drawer-open");
    $("drawer").setAttribute("aria-hidden", "false");
    $("chatBtn").setAttribute("aria-expanded", "true");
    if (state.tab === "now") state.unread = 0;
    drawDrawer();
    later(220, () => { if (state.selected) refreshList(); });
  }
  function closeDrawer() {
    document.body.classList.remove("drawer-open");
    $("drawer").setAttribute("aria-hidden", "true");
    $("chatBtn").setAttribute("aria-expanded", "false");
    $("chatBtn").focus();
    later(220, () => { if (state.selected) refreshList(); });
  }
  const drawerOpen = () => document.body.classList.contains("drawer-open");

  function basisTag(b) {
    return b === "inferred" ? `<span class="basis">推断 · 尚未逐条核对</span>` : "";
  }
  function ctxTag(ctx) {
    if (!ctx) return "";
    const n = node(ctx.node), s = ctx.svc && svc(ctx.svc);
    return `<span class="ctx">关于：${esc(n.name)}${s ? ` · ${esc(s.name)}（${KIND[s.kind]}）` : ""}</span>`;
  }
  function msgHtml(m) {
    if (m.role === "user") return `<div class="msg user">${ctxTag(m.ctx)}<div>${esc(m.text)}</div></div>`;
    if (m.role === "system") return `<div class="msg system">${esc(m.text)}</div>`;
    if (m.role === "progress") {
      return `<div class="msg progress"><div class="who">调查进度${m.done ? "（已完成）" : ""}</div><ol class="steps">${m.steps.map((s) =>
        `<li class="${s.st || ""}">${esc(s.t)}</li>`).join("")}</ol></div>`;
    }
    const n = node(m.who), remote = m.who !== "win";
    const fixOpen = m.fix && Object.values(state.pending).includes(m.fix);
    return `<div class="msg agent${remote ? " remote" : ""}">
      <div class="who">${esc(n.name)} 的 Agent${remote ? "（受这台电脑委派）" : ""} ${m.basis ? basisTag(m.basis) : ""}</div>
      <div>${esc(m.text)}</div>
      ${m.evidence && m.evidence.length ? `<details><summary>证据（${m.evidence.length} 项）</summary><ul>${m.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></details>` : ""}
      ${fixOpen ? `<div class="acts"><button class="btn go" type="button" data-act="fix" data-node="${REPAIRS[m.fix].node}">看看怎么修</button></div>` : ""}
    </div>`;
  }

  function drawDrawer() {
    $("tabNow").setAttribute("aria-selected", String(state.tab === "now"));
    $("tabHist").setAttribute("aria-selected", String(state.tab === "hist"));
    const t = state.current && thread(state.current);
    $("drawerTitle").textContent = state.tab === "hist" ? "以往对话" : (t ? t.title : "新对话");
    $("dfoot").hidden = state.tab === "hist";
    const body = $("dbody");
    if (state.tab === "hist") {
      body.innerHTML = state.history.map((h) => `<button class="hist" type="button" data-act="load" data-thread="${h.id}">
        <span class="t">${esc(h.title)}</span><small>${esc(h.when)} · ${esc(h.where)} · ${h.msgs.filter((m) => m.role !== "progress").length} 条</small></button>`).join("")
        + `<p class="muted">点一条就能接着问。更早的对话往下翻页（真实版本每页 20 条）。</p>`;
    } else if (!t) {
      body.innerHTML = `<p class="muted">还没有对话。可以在地图下方直接提问，或者在电脑的服务框里点“问问”，问题会自动带上是哪台电脑的哪个服务。</p>`;
    } else {
      body.innerHTML = t.msgs.map(msgHtml).join("");
      body.scrollTop = body.scrollHeight;
    }
    $("ctxHolder").innerHTML = state.ctx ? ctxTag(state.ctx) : "";
    $("chatBadge").hidden = !state.unread;
    $("chatBadge").textContent = String(state.unread);
  }
  function refreshDrawer() { if (drawerOpen() && state.tab === "now") drawDrawer(); }
  function pushMsg(tid, m) {
    const t = thread(tid); t.msgs.push(m); t.when = "刚刚";
    if (drawerOpen() && state.tab === "now" && state.current === tid) drawDrawer();
    else if (m.role === "agent") {
      // 抽屉关着时，下次打开直接显示有新消息的那条对话
      if (!drawerOpen()) { state.current = tid; state.tab = "now"; }
      state.unread += 1; drawDrawer();
    }
    return m;
  }

  /* ---------- 数据包动画：委派与代批准 ---------- */
  function sendPacket(from, to, color) {
    const a = center(node(from)), b = center(node(to));
    const r = document.createElementNS(NS, "rect");
    r.setAttribute("width", 14); r.setAttribute("height", 14); r.setAttribute("fill", color || "#ffcd75");
    r.setAttribute("stroke", "#1a1c2c"); r.setAttribute("stroke-width", 2);
    $("packets").appendChild(r);
    hot(from, true); hot(to, true);
    const dur = 1100, start = performance.now(), my = epoch;
    return new Promise((res) => {
      const step = (now) => {
        if (my !== epoch) { r.remove(); return; }
        const t = Math.min(1, (now - start) / dur);
        const x = Math.round((a.x + (b.x - a.x) * t) / 6) * 6, y = Math.round((a.y + (b.y - a.y) * t) / 6) * 6;
        r.setAttribute("x", x - 7); r.setAttribute("y", y - 7);
        if (t < 1) requestAnimationFrame(step); else { r.remove(); hot(from, false); hot(to, false); res(); }
      };
      requestAnimationFrame(step);
    });
  }
  function setBusy(id, what) {
    if (what) state.busyNode[id] = what; else delete state.busyNode[id];
    redrawMap();
  }

  /* ---------- 提问 ---------- */
  function planFor(q, ctx) {
    const about = ctx && ctx.svc ? ctx.svc : (/相册/.test(q) ? "photos" : /数据看板/.test(q) ? "dash" : null);
    const target = ctx ? ctx.node : (NODES.find((n) => !n.local && q.includes(n.name)) || {}).id || (about ? svc(about).node : "win");
    if (target === "old") return { target: "win", steps: ["看服务地图：旧笔记本 3 天前离线"], text: "旧笔记本现在不在线，我联系不上它。它开机并启动 TunnelMinion 以后，我才能把问题交给它。", basis: "checked", evidence: ["服务地图：旧笔记本最后在线 3 天前"] };
    if (about === "photos") {
      const p = svc("photos");
      if (p.status === "ok") return { target: "mac", work: "容器状态、端口", text: "相册现在是正常的：两个容器都在运行，首页能打开。", basis: "checked", evidence: ["容器列表（Mac mini，刚刚）", "网页探测：端口 2342 有响应"] };
      return { target: "mac", work: "容器状态、容器日志、端口",
        text: "相册的两个容器 13 分钟前都退出了，日志最后一行是“收到停止信号”，不像程序本身出错。Mac mini 建议重启这一组容器，已经放到 Mac mini 头上的感叹号里，点它就能批准。",
        basis: "checked", evidence: ["容器列表：photos-app-1、photos-db-1 都是“已退出”（Mac mini，刚刚）", "容器日志最后 50 行（只在 Mac mini 上读，原文不出 Mac mini）", "端口 2342 没人在听"], propose: "photos" };
    }
    if (about === "dash") {
      if (svc("dash").status === "ok") return { target: "win", steps: ["看服务地图：数据看板在这台电脑上", "本机查：端口、进程"], text: "数据看板现在是正常的，端口 8501 能打开。", basis: "checked", evidence: ["网页探测：端口 8501 有响应"] };
      return { target: "win", steps: ["看服务地图：数据看板在这台电脑上", "本机查：端口、进程、启动记录"], text: "数据看板的脚本 40 分钟前退出了。我之前已经提过一个修法：按原来的方式重新拉起，还在等你批准（这台电脑头上的感叹号）。", basis: "checked", evidence: ["端口 8501 没人在听", "启动记录：入口 dashboard.py"], fix: "dash" };
    }
    if (/内存|最占/.test(q)) return { target: "mac", work: "容器资源占用、进程资源占用", text: "容器里最占内存的是下载管理，约 1.4 GB；整台机器最占内存的是本地大模型 Qwen（不是容器），约 21 GB。", basis: "inferred", evidence: ["容器资源占用（Mac mini，刚刚）", "进程资源占用（Mac mini，刚刚）"] };
    if (target !== "win") {
      const n = node(target);
      return { target, work: "服务清单、端口", text: `${n.name} 一切正常，${nodeSummary(n)[0].slice(2)}。`, basis: "inferred", evidence: [`服务清单（${n.name}，刚刚）`] };
    }
    return { target: "win", steps: ["看服务地图"], text: "（这是草图，只演示几个示例问题：相册、数据看板、内存、某台电脑怎么样。真实版本里，这句话会交给合适的那台电脑去处理。）", basis: "inferred" };
  }

  function newThread(title, ctx) {
    const id = "t-" + Date.now();
    state.history.unshift({ id, title, when: "刚刚", where: ctx ? node(ctx.node).name : "这台电脑", msgs: [] });
    state.current = id;
    return id;
  }

  async function ask(q, ctx, sameThread) {
    q = q.trim();
    if (!q || state.asking) return;
    state.asking = true;
    const my = epoch;
    const tid = sameThread && state.current ? state.current : newThread(q, ctx);
    state.ctx = ctx || null;
    state.tab = "now";
    openDrawer("now");
    pushMsg(tid, { role: "user", text: q, ctx });
    const plan = planFor(q, ctx);
    const prog = pushMsg(tid, { role: "progress", steps: [] });
    const step = async (t, ms, fn) => {
      if (my !== epoch) throw new Error("reset");
      const s = { t, st: "doing" }; prog.steps.push(s); refreshDrawer();
      if (fn) await fn(); else await sleep(ms);
      if (my !== epoch) throw new Error("reset");
      s.st = "done"; refreshDrawer();
    };
    try {
      if (plan.target !== "win") {
        const n = node(plan.target);
        await step(`看服务地图：这件事归 ${n.name} 管`, 600);
        await step(`交给 ${n.name} 的 Agent`, 0, () => sendPacket("win", plan.target));
        await step(`${n.name} 正在查：${plan.work}`, 0, async () => { setBusy(plan.target, "thinking"); await sleep(2200); setBusy(plan.target, null); });
        await step(`${n.name} 交回结论`, 0, () => sendPacket(plan.target, "win", "#73eff7"));
      } else {
        for (const s of plan.steps) await step(s, 700);
      }
      prog.done = true;
      if (plan.propose) { state.pending[REPAIRS[plan.propose].node] = plan.propose; REPAIRS[plan.propose].thread = tid; redrawMap(); }
      pushMsg(tid, { role: "agent", who: plan.target, text: plan.text, basis: plan.basis, evidence: plan.evidence, fix: plan.propose || plan.fix });
    } catch (e) { /* 演示被重置 */ }
    state.asking = false;
  }

  function askAboutService(id) {
    const s = svc(id);
    const ctx = { node: s.node, svc: s.id };
    if (s.status === "ok") {
      // 服务正常时只带上上下文，让用户自己写问题
      state.current = null; state.ctx = ctx;
      openDrawer("now");
      $("followInput").value = "";
      $("followInput").placeholder = `关于${s.name}，想问什么？`;
      $("followInput").focus();
      return;
    }
    ask(`${s.name}怎么${s.status === "down" ? "打不开" : "停了"}？`, ctx);
  }
  function askAboutNode(id) {
    state.current = null; state.ctx = { node: id };
    openDrawer("now");
    $("followInput").placeholder = `想问 ${node(id).name} 什么？`;
    $("followInput").focus();
  }

  /* ---------- 批准框 ---------- */
  let countdown = null;
  function openFix(nodeId) {
    const key = state.pending[nodeId]; if (!key) return;
    const r = REPAIRS[key], { noProxy } = opts();
    state.modal = { key, phase: "ask" };
    const s = svc(r.svc);
    const blocked = r.remote && noProxy;
    $("modal").innerHTML = `
      ${r.remote ? `<div class="from">由 Mac mini 的 Agent 提出 · ${blocked ? "Mac mini 没有允许这台电脑替它批准" : "Mac mini 允许这台电脑替它批准"}</div>` : ""}
      <h2 id="fixTitle">要修好“${esc(s.name)}”吗？</h2>
      <div id="fixAsk">
        <dl>
          <dt>要做什么</dt><dd>${r.what}</dd>
          <dt>为什么</dt><dd>${esc(r.why)}</dd>
          <dt>会有什么影响</dt><dd>${esc(r.impact)}</dd>
          <dt>怎么确认修好</dt><dd>${esc(r.verify)}</dd>
          <dt>没修好怎么办</dt><dd>${esc(r.fallback)}</dd>
        </dl>
        <details><summary>高级：将执行的命令</summary><code>${r.cmd}</code></details>
        ${blocked ? `<div class="elsewhere">这件事要在 <b>Mac mini 本机</b>批准：在 Mac mini 上打开 TunnelMinion 的网页，点它头上的感叹号。<br><span class="muted">Mac mini 的主人可以在它的设置里为这台电脑打开“允许替我批准修复”。</span></div>
          <div class="acts"><button class="btn" type="button" data-act="close-fix">知道了</button></div>`
        : `<div class="acts">
          <button class="btn go" type="button" data-act="approve">批准并修复</button>
          <button class="btn" type="button" data-act="reject">先不用</button>
          <span class="expire" id="expire"></span></div>`}
      </div>
      <div id="fixRun" hidden>
        <ol class="steps" id="fixSteps"></ol>
        <div class="result" id="fixResult" hidden></div>
        <div class="acts"><button class="btn" type="button" data-act="close-fix" id="fixClose" hidden>关闭</button></div>
      </div>`;
    $("mask").hidden = false;
    let left = r.minutesLeft * 60 - 17;
    const tick = () => { const e = $("expire"); if (e) e.textContent = `10 分钟内有效 · 还剩 ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`; left -= 1; };
    tick(); clearInterval(countdown); countdown = setInterval(tick, 1000);
    const first = $("modal").querySelector("[data-act=reject], [data-act=close-fix]");
    if (first) first.focus();
  }
  function closeFix() {
    clearInterval(countdown);
    if (!state.modal) return;
    const r = REPAIRS[state.modal.key];
    state.modal = null; $("mask").hidden = true;
    const bang = document.querySelector(`[data-bang="${r.node}"]`);
    (bang || document.querySelector(`.node[data-id="${r.node}"]`) || $("chatBtn")).focus();
  }
  function writeBack(r, m) {
    const tid = r.thread && thread(r.thread) ? r.thread : null;
    if (tid) pushMsg(tid, m);
  }
  function reject() {
    const r = REPAIRS[state.modal.key];
    delete state.pending[r.node];
    writeBack(r, { role: "system", text: `你选择了“先不用”。这次修复已取消，${svc(r.svc).name}保持现在的样子。需要时再问我。` });
    closeFix(); redrawMap(); refreshDrawer();
  }
  async function approve() {
    clearInterval(countdown);
    const key = state.modal.key, r = REPAIRS[key], { fail } = opts(), my = epoch;
    state.modal.phase = "run";
    $("fixAsk").hidden = true; $("fixRun").hidden = false;
    const ol = $("fixSteps");
    ol.innerHTML = r.steps.map((t, i) => `<li data-i="${i}">${esc(t)}</li>`).join("");
    const li = (i) => ol.querySelector(`[data-i="${i}"]`);
    delete state.pending[r.node];
    writeBack(r, { role: "system", text: `你批准了修复“${svc(r.svc).name}”。` });
    refreshDrawer();
    const run = async (i, fn) => { if (my !== epoch) throw 0; li(i).className = "doing"; await fn(); if (my !== epoch) throw 0; li(i).className = "done"; };
    try {
      let i = 0;
      if (r.remote) await run(i++, () => sendPacket("win", r.node));
      setBusy(r.node, "working");
      await run(i++, () => sleep(900));
      await run(i++, () => sleep(1500));
      li(i).className = "doing";
      await sleep(1500);
      setBusy(r.node, null);
      if (r.remote) await sendPacket(r.node, "win", fail ? "#e05265" : "#73eff7");
      if (my !== epoch) return;
      const res = $("fixResult");
      if (fail) {
        li(i).className = "bad"; li(i).textContent = r.badStep;
        res.className = "result bad"; res.textContent = r.bad;
        svc(r.svc).status = r.svc === "dash" ? "stopped" : "down";
      } else {
        li(i).className = "done";
        res.className = "result"; res.textContent = r.ok;
        svc(r.svc).status = "ok";
      }
      res.hidden = false; $("fixClose").hidden = false; $("fixClose").focus();
      state.modal.phase = "done";
      writeBack(r, { role: "agent", who: r.node, basis: "checked", text: fail ? r.bad : r.ok,
        evidence: fail ? ["验证：首页打不开", "日志最后几十行的要点（原文留在本机）"] : ["验证：首页能打开", "进程 / 容器状态：运行中"] });
      redrawMap();
    } catch (e) { /* 演示被重置 */ }
  }

  /* ---------- 草图场景 ---------- */
  function reset() {
    epoch += 1;
    timers.forEach(clearTimeout); timers = [];
    clearInterval(countdown);
    $("packets").innerHTML = "";
    REPAIRS.photos.thread = null;
    state = freshState();
    $("mask").hidden = true;
    $("menu").hidden = true;
    document.body.classList.remove("drawer-open");
    $("drawer").setAttribute("aria-hidden", "true");
    $("askInput").value = "";
    $("followInput").placeholder = "接着问……";
    drawLinks(); drawNodes(); drawPop(); drawDrawer(); updateSummary();
  }
  function toast(text, ms) {
    const el = document.createElement("div");
    el.className = "box toast"; el.setAttribute("role", "status"); el.textContent = text;
    document.body.appendChild(el); setTimeout(() => el.remove(), ms || 2600);
  }
  const SCENES = {
    1: () => { select("mac"); toast("Mac mini 有 9 个服务：按状态排序、分页，用 ◀ ▶ 或键盘左右键翻页。", 3600); },
    2: () => { select("mac"); toast("点“相册”那一行的“问问”，对话会从右侧滑出，问题自动带上 Mac mini · 相册。", 4200); },
    3: () => { $("askInput").value = "Mac mini 上的相册怎么了？"; $("askInput").focus(); later(700, () => $("askForm").requestSubmit()); },
    4: () => { toast("点“这台电脑”头上的红色感叹号（③ 走完以后，Mac mini 头上也会冒一个）。", 4200); const b = document.querySelector('[data-bang="win"]'); if (b) b.focus(); },
    5: () => { openDrawer("hist"); },
  };

  /* ---------- 事件 ---------- */
  document.addEventListener("click", (e) => {
    const sceneBtn = e.target.closest("[data-scene]");
    if (sceneBtn) { reset(); SCENES[sceneBtn.dataset.scene](); return; }
    const bang = e.target.closest("[data-bang]");
    if (bang) { openFix(bang.dataset.bang); return; }
    const nodeEl = e.target.closest(".node");
    if (nodeEl) { select(nodeEl.dataset.id); return; }
    const act = e.target.closest("[data-act]");
    if (act) {
      const a = act.dataset.act;
      if (a === "close-pop") closePop();
      else if (a === "page") { state.page += Number(act.dataset.d); refreshList(); }
      else if (a === "open") toast(`真实版本会在新标签页打开 ${svc(act.dataset.svc).name}`);
      else if (a === "ask-svc") askAboutService(act.dataset.svc);
      else if (a === "ask-node") askAboutNode(act.dataset.node);
      else if (a === "fix") openFix(act.dataset.node);
      else if (a === "approve") approve();
      else if (a === "reject") reject();
      else if (a === "close-fix") closeFix();
      else if (a === "load") { state.current = act.dataset.thread; state.ctx = null; state.tab = "now"; drawDrawer(); $("followInput").focus(); }
      return;
    }
    // 点到服务框、抽屉、批准框、菜单以外的地方，收起服务框
    if (state.selected && !e.target.closest("#pop, #drawer, #mask, .demo, .bar")) closePop();
    if (!$("menu").hidden && !e.target.closest("#menu, #moreBtn")) toggleMenu(false);
  });
  $("map").addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const bang = e.target.closest("[data-bang]");
    if (bang) { e.preventDefault(); e.stopPropagation(); openFix(bang.dataset.bang); return; }
    const n = e.target.closest(".node");
    if (n) { e.preventDefault(); select(n.dataset.id); }
  });
  $("map").addEventListener("mousemove", (e) => { const n = e.target.closest(".node"); if (n) { showTip(e, n.dataset.id); hot(n.dataset.id, true); } else hideTip(); });
  $("map").addEventListener("mouseout", (e) => { const n = e.target.closest(".node"); if (n && !n.contains(e.relatedTarget)) { hideTip(); hot(n.dataset.id, false); } });
  $("pop").addEventListener("scroll", updateHint);

  function toggleMenu(open) {
    $("menu").hidden = !open;
    $("moreBtn").setAttribute("aria-expanded", String(open));
    if (open) $("menu").querySelector("button").focus();
  }
  $("moreBtn").addEventListener("click", () => toggleMenu($("menu").hidden));
  $("menu").addEventListener("click", (e) => {
    const b = e.target.closest("[data-go]"); if (!b) return;
    toggleMenu(false); toast(`真实版本打开 ${b.dataset.go}，左上角有“← 回到地图”。`);
  });
  $("chatBtn").addEventListener("click", () => (drawerOpen() ? closeDrawer() : openDrawer(state.unread ? "now" : state.tab)));
  $("closeDrawer").addEventListener("click", closeDrawer);
  $("newChat").addEventListener("click", () => { state.current = null; state.ctx = null; state.tab = "now"; $("followInput").placeholder = "接着问……"; drawDrawer(); $("followInput").focus(); });
  $("tabNow").addEventListener("click", () => { state.tab = "now"; state.unread = 0; drawDrawer(); });
  $("tabHist").addEventListener("click", () => { state.tab = "hist"; drawDrawer(); });
  $("askForm").addEventListener("submit", (e) => { e.preventDefault(); const q = $("askInput").value; $("askInput").value = ""; ask(q, null); });
  $("followForm").addEventListener("submit", (e) => {
    e.preventDefault();
    const q = $("followInput").value; $("followInput").value = "";
    ask(q, state.ctx, Boolean(state.current));
  });
  $("reset").addEventListener("click", reset);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (state.modal) { if (state.modal.phase !== "run") closeFix(); return; }
      if (!$("menu").hidden) { toggleMenu(false); $("moreBtn").focus(); return; }
      if (state.selected) { closePop(); return; }
      if (drawerOpen()) closeDrawer();
      return;
    }
    if (state.selected && !state.modal && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
      if (e.key === "ArrowLeft") { state.page -= 1; refreshList(); }
      if (e.key === "ArrowRight") { state.page += 1; refreshList(); }
    }
  });
  window.addEventListener("resize", () => { if (state.selected) { state.pageSize = 6; refreshList(); } });

  const CHIPS = ["Mac mini 上的相册怎么了？", "数据看板为什么打不开？", "Mac mini 上哪个容器最占内存？", "旧笔记本怎么样？"];
  $("chips").innerHTML = CHIPS.map((c) => `<button class="chip" type="button" data-chip="${esc(c)}">${esc(c)}</button>`).join("");
  $("chips").addEventListener("click", (e) => { const c = e.target.closest("[data-chip]"); if (c) ask(c.dataset.chip, null); });

  const fitDemo = () => document.documentElement.style.setProperty("--demo-h", document.querySelector(".demo").offsetHeight + "px");
  window.addEventListener("resize", fitDemo);
  fitDemo();
  reset();
})();

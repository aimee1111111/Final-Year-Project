const API = "http://localhost:5000";

const els = {
  // tabs
  tabAll: document.getElementById("tabAll"),
  tabMine: document.getElementById("tabMine"),
  tabNew: document.getElementById("tabNew"),

  // views
  viewList: document.getElementById("viewList"),
  viewNew: document.getElementById("viewNew"),
  viewDetail: document.getElementById("viewDetail"),

  // list
  listTitle: document.getElementById("listTitle"),
  posts: document.getElementById("posts"),
  refreshList: document.getElementById("refreshList"),

  // new post
  newPostForm: document.getElementById("newPostForm"),
  newTitle: document.getElementById("newTitle"),
  newBody: document.getElementById("newBody"),
  cancelNew: document.getElementById("cancelNew"),

  // detail
  backToList: document.getElementById("backToList"),
  refreshDetail: document.getElementById("refreshDetail"),
  detailTitle: document.getElementById("detailTitle"),
  detailMeta: document.getElementById("detailMeta"),
  detailBody: document.getElementById("detailBody"),

  // replies
  replyList: document.getElementById("replyList"),
  replyForm: document.getElementById("replyForm"),
  replyBody: document.getElementById("replyBody"),

  // toast
  toast: document.getElementById("toast"),

  // search
  searchInput: document.getElementById("searchInput"),
  searchBtn: document.getElementById("searchBtn"),
  clearSearch: document.getElementById("clearSearch"),
};

function getUserId() {
  const raw = localStorage.getItem("user_id") || "";
  const id = parseInt(raw, 10);
  return Number.isFinite(id) && id > 0 ? id : 0;
}

function headers() {
  const h = { "Content-Type": "application/json" };
  const uid = getUserId();
  if (uid > 0) h["X-User-Id"] = String(uid);
  return h;
}

let currentTab = "all";
let currentPostId = null;
let currentQuery = "";

function toast(msg, isError = false) {
  if (!els.toast) return;
  els.toast.textContent = msg;
  els.toast.classList.toggle("error", isError);
  els.toast.classList.remove("hidden");
  window.clearTimeout(toast._t);
  toast._t = window.setTimeout(() => els.toast.classList.add("hidden"), 2500);
}

function showView(name) {
  if (!els.viewList || !els.viewNew || !els.viewDetail) return;
  els.viewList.classList.toggle("hidden", name !== "list");
  els.viewNew.classList.toggle("hidden", name !== "new");
  els.viewDetail.classList.toggle("hidden", name !== "detail");
}

function setActiveTab(tab) {
  currentTab = tab;
  if (els.tabAll) els.tabAll.classList.toggle("active", tab === "all");
  if (els.tabMine) els.tabMine.classList.toggle("active", tab === "mine");
  if (els.tabNew) els.tabNew.classList.toggle("active", tab === "new");
}

function fmtDate(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function snippet(text, maxLen) {
  const s = (text || "").trim();
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen - 1) + "…";
}

function card(post) {
  const div = document.createElement("div");
  div.className = "postcard";
  div.innerHTML = `
    <div class="t">${escapeHtml(post.title)}</div>
    <div class="m">
      <span>post #${post.id}</span>
      <span>user ${post.user_id}</span>
      <span>${fmtDate(post.created_at)}</span>
      <span>${post.reply_count || 0} replies</span>
    </div>
    <div class="p">${escapeHtml(snippet(post.body, 220))}</div>
  `;
  div.addEventListener("click", () => openPost(post.id));
  return div;
}

async function loadList() {
  showView("list");
  if (els.posts) els.posts.innerHTML = "";

  const mine = currentTab === "mine";
  if (els.listTitle) els.listTitle.textContent = mine ? "my posts" : "all posts";

  if (mine && getUserId() <= 0) {
    toast("please log in to view my posts", true);
    return;
  }

  const params = new URLSearchParams();
  if (mine) params.set("mine", "1");
  if (currentQuery.trim()) params.set("q", currentQuery.trim());

  const url = `${API}/api/posts?${params.toString()}`;
  const res = await fetch(url, { headers: headers() });
  const data = await res.json();

  if (!res.ok) { toast(data.error || "failed to load posts", true); return; }

  if (!els.posts) return;

  if (data.length === 0) {
    const empty = document.createElement("div");
    empty.className = "postcard";
    empty.textContent = currentQuery ? "no posts match your search" : "no posts yet";
    els.posts.appendChild(empty);
    return;
  }

  for (const p of data) els.posts.appendChild(card(p));
}

async function openPost(postId) {
  currentPostId = postId;
  showView("detail");

  const res = await fetch(`${API}/api/posts/${postId}`, { headers: headers() });
  const data = await res.json();

  if (!res.ok) { toast(data.error || "failed to open post", true); showView("list"); return; }

  const post = data.post;
  const replies = data.replies || [];

  if (els.detailTitle) els.detailTitle.textContent = post.title;
  if (els.detailMeta) els.detailMeta.textContent = `post #${post.id} • user ${post.user_id} • ${fmtDate(post.created_at)}`;
  if (els.detailBody) els.detailBody.textContent = post.body;

  if (!els.replyList) return;
  els.replyList.innerHTML = "";

  if (replies.length === 0) {
    const d = document.createElement("div");
    d.className = "reply";
    d.textContent = "no replies yet";
    els.replyList.appendChild(d);
  } else {
    for (const r of replies) {
      const div = document.createElement("div");
      div.className = "reply";
      div.innerHTML = `
        <div class="rm">
          <span>reply #${r.id}</span>
          <span>user ${r.user_id}</span>
          <span>${fmtDate(r.created_at)}</span>
        </div>
        <div class="rb">${escapeHtml(r.body).replaceAll("\n", "<br/>")}</div>
      `;
      els.replyList.appendChild(div);
    }
  }
}

async function submitPost(e) {
  e.preventDefault();
  if (getUserId() <= 0) { toast("please log in first", true); return; }

  const title = (els.newTitle?.value || "").trim();
  const body = (els.newBody?.value || "").trim();

  const res = await fetch(`${API}/api/posts`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ title, body }),
  });

  const data = await res.json();
  if (!res.ok) { toast(data.error || "failed to create post", true); return; }

  toast("post created");
  if (els.newTitle) els.newTitle.value = "";
  if (els.newBody) els.newBody.value = "";
  setActiveTab("all");
  currentQuery = "";
  if (els.searchInput) els.searchInput.value = "";
  await loadList();
}

async function submitReply(e) {
  e.preventDefault();
  if (getUserId() <= 0) { toast("please log in first", true); return; }
  if (!currentPostId) return;

  const body = (els.replyBody?.value || "").trim();
  if (body.length < 2) { toast("reply too short", true); return; }

  const res = await fetch(`${API}/api/posts/${currentPostId}/replies`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify({ body }),
  });

  const data = await res.json();
  if (!res.ok) { toast(data.error || "failed to send reply", true); return; }

  if (els.replyBody) els.replyBody.value = "";
  toast("reply sent");
  await openPost(currentPostId);
}

function wire() {
  // tabs
  els.tabAll?.addEventListener("click", async () => { setActiveTab("all"); await loadList(); });
  els.tabMine?.addEventListener("click", async () => { setActiveTab("mine"); await loadList(); });

  els.tabNew?.addEventListener("click", () => {
    if (getUserId() <= 0) { toast("please log in first", true); return; }
    setActiveTab("new");
    showView("new");
  });

  // list/detail buttons
  els.refreshList?.addEventListener("click", loadList);
  els.backToList?.addEventListener("click", async () => { currentPostId = null; await loadList(); });
  els.refreshDetail?.addEventListener("click", async () => { if (currentPostId) await openPost(currentPostId); });

  // forms
  els.newPostForm?.addEventListener("submit", submitPost);
  els.replyForm?.addEventListener("submit", submitReply);

  // search 
  els.searchBtn?.addEventListener("click", async () => {
    currentQuery = els.searchInput?.value || "";
    await loadList();
  });

  els.clearSearch?.addEventListener("click", async () => {
    if (els.searchInput) els.searchInput.value = "";
    currentQuery = "";
    await loadList();
  });

  els.searchInput?.addEventListener("keydown", async (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      currentQuery = els.searchInput?.value || "";
      await loadList();
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  wire();
  loadList();
});
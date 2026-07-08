// 대시보드/설정 페이지 전체에서 공통으로 쓰는 헬퍼. 각 페이지의 스크립트보다 먼저 로드되어야 함.

const el = (id) => document.getElementById(id);

async function fetchJSON(url, options) {
  const res = await fetch(url, options);
  if (res.status === 401) {
    window.location.href = "/login";
    throw new Error("로그인이 필요합니다");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `요청 실패 (${res.status})`);
  return data;
}

let messageTimer = null;
function showMessage(text, type = "info") {
  const box = el("message");
  if (!box) return;
  box.textContent = text;
  box.className = `message ${type}`;
  box.classList.remove("hidden");
  clearTimeout(messageTimer);
  messageTimer = setTimeout(() => box.classList.add("hidden"), 8000);
}

function escapeHtml(s) {
  return (s || "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

document.addEventListener("DOMContentLoaded", () => {
  const logoutBtn = el("logoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => { window.location.href = "/logout"; });
});

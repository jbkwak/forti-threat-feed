const state = {
  page: 1,
  pageSize: 50,
  totalPages: 1,
  selected: new Set(),
  rowsByUrl: new Map(),
};

function formatDate(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Seoul",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  }).formatToParts(d);
  const get = (t) => parts.find((p) => p.type === t).value;
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")}`;
}

function buildQuery() {
  const params = new URLSearchParams();
  const date = el("filterDate").value;
  const source = el("filterSource").value;
  const q = el("filterQuery").value.trim();
  if (date) params.set("date", date);
  if (source) params.set("source", source);
  if (q) params.set("q", q);
  params.set("page", state.page);
  params.set("page_size", state.pageSize);
  return params.toString();
}

function vtBadge(row) {
  if (row.vt_status === "found") {
    const m = row.vt_malicious ?? 0;
    const cls = m === 0 ? "vt-ok" : m <= 2 ? "vt-warn" : "vt-bad";
    return `<span class="badge ${cls}">${m}/${row.vt_total} 탐지</span>`;
  }
  if (row.vt_status === "submitted") return `<span class="badge vt-pending">분석 대기중</span>`;
  if (row.vt_status === "not_found") return `<span class="badge vt-unknown">VT 미등록</span>`;
  if (row.vt_status === "error") return `<span class="badge vt-error">조회 오류</span>`;
  return `<span class="badge vt-unknown">미확인</span>`;
}

function fgBadge(row) {
  if (row.fg_status === "found") {
    return `<span class="badge vt-ok">${escapeHtml(row.fg_category || "")}${row.fg_category_id != null ? ` (#${row.fg_category_id})` : ""}</span>`;
  }
  if (row.fg_status === "not_found") return `<span class="badge vt-unknown">FortiGuard 미등록</span>`;
  if (row.fg_status === "error") return `<span class="badge vt-error">조회 오류</span>`;
  return `<span class="badge vt-unknown">미확인</span>`;
}

function renderRows(rows) {
  state.rowsByUrl.clear();
  for (const row of rows) state.rowsByUrl.set(row.url, row);

  const tbody = el("urlTableBody");
  tbody.innerHTML = rows.map((row) => `
    <tr>
      <td><input type="checkbox" class="rowCheck" data-url="${escapeHtml(row.url)}" ${state.selected.has(row.url) ? "checked" : ""}></td>
      <td class="url-cell" title="${escapeHtml(row.raw_url)}">${escapeHtml(row.url)}</td>
      <td><span class="badge source-${escapeHtml(row.source)}">${escapeHtml(row.source)}</span></td>
      <td>${formatDate(row.first_seen)}</td>
      <td>${row.pushed ? '<span class="badge pushed-yes">완료</span>' : '<span class="badge pushed-no">미반영</span>'}</td>
      <td class="vt-cell">${vtBadge(row)}<button class="vtSingleBtn" data-url="${escapeHtml(row.url)}">확인</button></td>
      <td class="vt-cell">${fgBadge(row)}<button class="fgSingleBtn" data-url="${escapeHtml(row.url)}">확인</button></td>
    </tr>
  `).join("");

  tbody.querySelectorAll(".rowCheck").forEach((cb) => {
    cb.addEventListener("change", () => {
      if (cb.checked) state.selected.add(cb.dataset.url);
      else state.selected.delete(cb.dataset.url);
      updateSelectionUI();
    });
  });
  tbody.querySelectorAll(".vtSingleBtn").forEach((btn) => {
    btn.addEventListener("click", () => runVtCheck([btn.dataset.url]));
  });
  tbody.querySelectorAll(".fgSingleBtn").forEach((btn) => {
    btn.addEventListener("click", () => runFgCheck([btn.dataset.url]));
  });

  updateSelectionUI();
}

function updateSelectionUI() {
  el("selectedCount").textContent = `${state.selected.size}개 선택됨`;
  el("pushBtn").disabled = state.selected.size === 0;
  el("vtCheckBtn").disabled = state.selected.size === 0;
  el("fgCheckBtn").disabled = state.selected.size === 0;

  const visibleUrls = Array.from(state.rowsByUrl.keys());
  const allChecked = visibleUrls.length > 0 && visibleUrls.every((u) => state.selected.has(u));
  el("selectAll").checked = allChecked;
}

async function loadPage() {
  try {
    const data = await fetchJSON(`/api/urls?${buildQuery()}`);
    state.totalPages = data.total_pages;
    renderRows(data.rows);
    el("pageInfo").textContent = `${data.page} / ${data.total_pages} 페이지 (총 ${data.total}건)`;
    el("prevPage").disabled = data.page <= 1;
    el("nextPage").disabled = data.page >= data.total_pages;
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function loadDates() {
  try {
    const dates = await fetchJSON("/api/dates");
    el("dateList").innerHTML = dates.map((d) => `<option value="${d}">`).join("");
  } catch (e) {
    /* 날짜 목록은 부가 기능이므로 실패해도 무시 */
  }
}

async function pushSelected() {
  const urls = Array.from(state.selected);
  if (!urls.length) return;
  el("pushBtn").disabled = true;
  showMessage(`FortiProxy로 ${urls.length}건 push 중...`, "info");
  try {
    const data = await fetchJSON("/api/push", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    showMessage(
      `Push 완료: 성공 ${data.succeeded.length}건 / 실패 ${data.failed.length}건`,
      data.failed.length ? "warn" : "success"
    );
    data.succeeded.forEach((u) => state.selected.delete(u));
    loadPage();
  } catch (e) {
    showMessage(e.message, "error");
  } finally {
    updateSelectionUI();
  }
}

async function runVtCheck(urls) {
  if (!urls.length) return;
  if (urls.length > 4) {
    showMessage("VirusTotal 무료 API 제한으로 한 번에 최대 4개까지만 확인됩니다. 앞 4개만 조회합니다.", "warn");
    urls = urls.slice(0, 4);
  }
  showMessage(`VirusTotal 조회 중... (${urls.length}건, 최대 ${urls.length * 15}초 소요될 수 있음)`, "info");
  try {
    await fetchJSON("/api/vt-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    showMessage("VirusTotal 조회 완료", "success");
    loadPage();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function runFgCheck(urls) {
  if (!urls.length) return;
  if (urls.length > 10) {
    showMessage("FortiGuard 조회는 한 번에 최대 10개까지만 가능합니다. 앞 10개만 조회합니다.", "warn");
    urls = urls.slice(0, 10);
  }
  showMessage(`FortiGuard 조회 중... (${urls.length}건)`, "info");
  try {
    await fetchJSON("/api/fortiguard-check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls }),
    });
    showMessage("FortiGuard 조회 완료", "success");
    loadPage();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

function bindEvents() {
  el("searchBtn").addEventListener("click", () => { state.page = 1; loadPage(); });
  el("resetBtn").addEventListener("click", () => {
    el("filterDate").value = "";
    el("filterSource").value = "";
    el("filterQuery").value = "";
    state.page = 1;
    loadPage();
  });
  el("prevPage").addEventListener("click", () => { if (state.page > 1) { state.page--; loadPage(); } });
  el("nextPage").addEventListener("click", () => { if (state.page < state.totalPages) { state.page++; loadPage(); } });
  el("selectAll").addEventListener("change", (e) => {
    const urls = Array.from(state.rowsByUrl.keys());
    if (e.target.checked) urls.forEach((u) => state.selected.add(u));
    else urls.forEach((u) => state.selected.delete(u));
    renderRows(Array.from(state.rowsByUrl.values()));
  });
  el("pushBtn").addEventListener("click", pushSelected);
  el("vtCheckBtn").addEventListener("click", () => runVtCheck(Array.from(state.selected)));
  el("fgCheckBtn").addEventListener("click", () => runFgCheck(Array.from(state.selected)));
}

bindEvents();
loadDates();
loadPage();

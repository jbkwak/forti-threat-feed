let schedulePresets = {};

async function loadSchedule() {
  try {
    const data = await fetchJSON("/api/schedule");
    schedulePresets = data.presets || {};

    if (data.schedule) {
      const label = schedulePresets[data.schedule.cron_expr] || "커스텀";
      el("scheduleStatus").textContent =
        `현재 주기: ${label} (${data.schedule.cron_expr})` + (data.schedule.enabled ? "" : " — 비활성 상태");
      el("scheduleStatus").className = `status-line ${data.schedule.enabled ? "ok" : "warn"}`;

      const matched = Array.from(el("scheduleSelect").options).some((o) => o.value === data.schedule.cron_expr);
      if (matched) {
        el("scheduleSelect").value = data.schedule.cron_expr;
        el("scheduleCustomInput").classList.add("hidden");
      } else {
        el("scheduleSelect").value = "custom";
        el("scheduleCustomInput").value = data.schedule.cron_expr;
        el("scheduleCustomInput").classList.remove("hidden");
      }
    } else {
      el("scheduleStatus").textContent = "수집 주기가 설정되어 있지 않습니다 (cron 미등록 — main.py가 자동 실행되지 않습니다)";
      el("scheduleStatus").className = "status-line warn";
    }
  } catch (e) {
    el("scheduleStatus").textContent = `cron 조회 실패: ${e.message}`;
    el("scheduleStatus").className = "status-line warn";
  }
}

function currentCronExpr() {
  const sel = el("scheduleSelect").value;
  return sel === "custom" ? el("scheduleCustomInput").value.trim() : sel;
}

async function saveSchedule() {
  const cron_expr = currentCronExpr();
  if (!cron_expr) {
    showMessage("cron 표현식을 입력하세요", "error");
    return;
  }
  try {
    await fetchJSON("/api/schedule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cron_expr }),
    });
    showMessage("수집 주기가 저장되어 crontab에 바로 반영되었습니다", "success");
    loadSchedule();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function clearSchedule() {
  try {
    await fetchJSON("/api/schedule", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "clear" }),
    });
    showMessage("수집 주기 cron이 해제되었습니다", "success");
    loadSchedule();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

el("scheduleSelect").addEventListener("change", (e) => {
  el("scheduleCustomInput").classList.toggle("hidden", e.target.value !== "custom");
});
el("scheduleSaveBtn").addEventListener("click", saveSchedule);
el("scheduleClearBtn").addEventListener("click", clearSchedule);
loadSchedule();

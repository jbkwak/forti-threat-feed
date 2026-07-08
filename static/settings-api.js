async function loadApiSettings() {
  try {
    const data = await fetchJSON("/api/settings");
    el("vtStatus").textContent = data.vt_api_key_set
      ? `VirusTotal API 키 설정됨 (${data.vt_api_key_masked})`
      : "VirusTotal API 키가 설정되어 있지 않습니다";
    el("fgStatus").textContent = data.fortiguard_api_key_set
      ? `FortiGuard API 키 설정됨 (${data.fortiguard_api_key_masked})`
      : "FortiGuard API 키가 설정되어 있지 않습니다";
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function saveVtKey() {
  const key = el("vtApiKeyInput").value.trim();
  try {
    await fetchJSON("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ vt_api_key: key }),
    });
    el("vtApiKeyInput").value = "";
    showMessage("VirusTotal API 키가 저장되었습니다", "success");
    loadApiSettings();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function saveFgKey() {
  const key = el("fgApiKeyInput").value.trim();
  try {
    await fetchJSON("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fortiguard_api_key: key }),
    });
    el("fgApiKeyInput").value = "";
    showMessage("FortiGuard API 키가 저장되었습니다", "success");
    loadApiSettings();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

el("vtSaveBtn").addEventListener("click", saveVtKey);
el("fgSaveBtn").addEventListener("click", saveFgKey);
loadApiSettings();

async function loadFortiProxy() {
  try {
    const data = await fetchJSON("/api/settings");
    el("fortiHostInput").value = data.forti_host || "";
    el("fortiResourceNameInput").value = data.forti_resource_name || "";
    el("fortiStatus").textContent = data.fortiproxy_configured
      ? `FortiProxy 설정 확인됨 (host: ${data.forti_host}, resource: ${data.forti_resource_name}, key: ${data.forti_api_key_masked})`
      : "FortiProxy 설정이 비어 있어 Push가 동작하지 않습니다 — host/API Key/리소스 이름을 입력하세요";
    el("fortiStatus").className = `status-line ${data.fortiproxy_configured ? "ok" : "warn"}`;
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function saveFortiSettings() {
  const host = el("fortiHostInput").value.trim();
  const apiKey = el("fortiApiKeyInput").value.trim();
  const resourceName = el("fortiResourceNameInput").value.trim();
  try {
    const body = { forti_host: host, forti_resource_name: resourceName };
    if (apiKey) body.forti_api_key = apiKey; // 빈 채로 두면 기존 저장된 키 유지
    await fetchJSON("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    el("fortiApiKeyInput").value = "";
    showMessage("FortiProxy 설정이 저장되었습니다", "success");
    loadFortiProxy();
  } catch (e) {
    showMessage(e.message, "error");
  }
}

el("fortiSaveBtn").addEventListener("click", saveFortiSettings);
loadFortiProxy();

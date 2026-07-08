async function loadAccount() {
  try {
    const data = await fetchJSON("/api/settings");
    el("accountStatus").textContent = data.username ? `로그인 계정: ${data.username}` : "";
  } catch (e) {
    showMessage(e.message, "error");
  }
}

async function changePassword() {
  const current = el("currentPasswordInput").value;
  const next = el("newPasswordInput").value;
  const confirm = el("confirmPasswordInput").value;

  if (!current || !next) {
    showMessage("현재 비밀번호와 새 비밀번호를 모두 입력하세요", "error");
    return;
  }
  if (next !== confirm) {
    showMessage("새 비밀번호가 서로 일치하지 않습니다", "error");
    return;
  }

  try {
    await fetchJSON("/api/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ current_password: current, new_password: next }),
    });
    el("currentPasswordInput").value = "";
    el("newPasswordInput").value = "";
    el("confirmPasswordInput").value = "";
    showMessage("비밀번호가 변경되었습니다", "success");
  } catch (e) {
    showMessage(e.message, "error");
  }
}

el("changePasswordBtn").addEventListener("click", changePassword);
loadAccount();

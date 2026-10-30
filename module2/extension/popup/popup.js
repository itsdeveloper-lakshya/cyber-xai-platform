document.addEventListener("DOMContentLoaded", () => {
  const connStatus = document.getElementById("conn-status");
  const userVal = document.getElementById("user-val");
  const queueVal = document.getElementById("queue-val");
  const versionVal = document.getElementById("version-val");
  const enrollForm = document.getElementById("enroll-form");
  const btnEnroll = document.getElementById("btn-enroll");
  const inputUserId = document.getElementById("input-userid");
  const inputCode = document.getElementById("input-code");

  function refresh() {
    chrome.runtime.sendMessage({ type: "GET_STATUS" }, (res) => {
      if (res && res.isRegistered) {
        connStatus.textContent = "Protected";
        connStatus.className = "status-badge status-active";
        userVal.textContent = res.userId || "Registered";
        queueVal.textContent = res.pendingEvents;
        versionVal.textContent = `v${res.rulesetVersion} / v${res.modelVersion}`;
        enrollForm.style.display = "none";
      } else {
        connStatus.textContent = "Unregistered";
        connStatus.className = "status-badge status-inactive";
        enrollForm.style.display = "block";
      }
    });
  }

  btnEnroll.addEventListener("click", () => {
    const code = inputCode.value.trim();
    const userId = inputUserId.value.trim();
    if (!code || !userId) {
      alert("Please provide both User ID and Enrollment Code.");
      return;
    }
    btnEnroll.textContent = "Registering...";
    chrome.runtime.sendMessage({ type: "REGISTER_DEVICE", enrollmentCode: code, userId: userId }, (res) => {
      btnEnroll.textContent = "Register Extension";
      if (res && res.success) {
        alert("Device successfully registered!");
        refresh();
      } else {
        alert("Registration failed: " + (res?.error || "Unknown error"));
      }
    });
  });

  refresh();
});

(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const forms = { auth: $("auth-form"), request: $("reset-request-form"), confirm: $("reset-confirm-form") };
  const tabs = document.querySelectorAll(".tab");
  const message = $("message");
  const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
  let mode = "login";
  let resetEmail = "";

  function show(text, kind = "") {
    message.textContent = text;
    message.className = kind;
  }

  function setError(field, text) {
    document.querySelector(`.field-error[data-for="${field.id}"]`).textContent = text;
    field.setAttribute("aria-invalid", text ? "true" : "false");
  }

  function checkEmail(field) {
    const ok = EMAIL.test(field.value.trim());
    setError(field, ok ? "" : "Enter a valid email address.");
    return ok;
  }

  function checkLength(field, label = "Password") {
    const ok = field.value.length >= 8;
    setError(field, ok ? "" : `${label} must be at least 8 characters.`);
    return ok;
  }

  async function post(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Something went wrong.");
    return data;
  }

  // ---- Views ----------------------------------------------------------------
  function setView(view) {
    mode = view;
    forms.auth.hidden = !(view === "login" || view === "register");
    forms.request.hidden = view !== "reset";
    forms.confirm.hidden = view !== "reset-confirm";
    document.querySelector(".tabs").classList.toggle("hidden", forms.auth.hidden);
    tabs.forEach((t) => {
      t.classList.toggle("active", t.dataset.mode === view);
      t.setAttribute("aria-selected", String(t.dataset.mode === view));
    });
    $("submit").textContent = view === "register" ? "Create account" : "Sign in";
    $("password").autocomplete = view === "register" ? "new-password" : "current-password";
    $("forgot-link").hidden = view !== "login";
    $("brand-subtitle").textContent =
      view === "register" ? "Create your account." : view.startsWith("reset") ? "Reset your password." : "Sign in to continue.";
    show("");
  }

  tabs.forEach((tab) => tab.addEventListener("click", () => setView(tab.dataset.mode)));
  $("forgot-link").addEventListener("click", () => {
    $("reset-email").value = $("email").value;
    setView("reset");
    $("reset-email").focus();
  });
  document.querySelectorAll(".back-to-login").forEach((b) => b.addEventListener("click", () => setView("login")));

  document.querySelectorAll(".toggle").forEach((button) =>
    button.addEventListener("click", () => {
      const field = $(button.dataset.target);
      const hidden = field.type === "password";
      field.type = hidden ? "text" : "password";
      button.textContent = hidden ? "Hide" : "Show";
      button.setAttribute("aria-label", hidden ? "Hide password" : "Show password");
    })
  );

  // ---- Sign in / create account -----------------------------------------------
  forms.auth.addEventListener("submit", async (event) => {
    event.preventDefault();
    const ok = [checkEmail($("email")), checkLength($("password"))].every(Boolean);
    if (!ok) return;
    const button = $("submit");
    button.disabled = true;
    show(mode === "login" ? "Signing in…" : "Creating account…");
    try {
      const body = { email: $("email").value.trim(), password: $("password").value };
      if (mode === "login") {
        const data = await post("/api/login", body);
        sessionStorage.setItem("token", data.token);
        show(`Welcome back, ${data.email}!`, "success");
      } else {
        await post("/api/register", body);
        setView("login");
        show("Account created. You can sign in now.", "success");
      }
    } catch (e) {
      show(e.message || "Could not reach the server. Check your connection.", "error");
    } finally {
      button.disabled = false;
    }
  });

  // ---- Forgot password ------------------------------------------------------------
  async function sendCode() {
    const data = await post("/api/password-reset/request", { email: resetEmail });
    $("reset-sent-to").textContent = `${data.message} Enter it below for ${resetEmail}.`;
    const demo = $("demo-code");
    demo.hidden = !data.demo_code;
    if (data.demo_code) {
      demo.innerHTML = `Demo mode (no email service configured): your code is <strong>${data.demo_code}</strong>`;
    }
  }

  forms.request.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!checkEmail($("reset-email"))) return;
    const button = $("reset-request-submit");
    button.disabled = true;
    try {
      resetEmail = $("reset-email").value.trim();
      await sendCode();
      setView("reset-confirm");
      $("reset-code").focus();
    } catch (e) {
      show(e.message, "error");
    } finally {
      button.disabled = false;
    }
  });

  $("resend-link").addEventListener("click", async () => {
    try {
      await sendCode();
      show("A new code has been sent.", "success");
    } catch (e) {
      show(e.message, "error");
    }
  });

  $("new-password").addEventListener("input", (e) => {
    const v = e.target.value;
    const score = [v.length >= 8, v.length >= 12, /[A-Z]/.test(v) && /[a-z]/.test(v), /\d/.test(v), /[^\w\s]/.test(v)]
      .filter(Boolean).length;
    const bar = $("strength-bar");
    bar.style.width = `${score * 20}%`;
    bar.style.background = score < 3 ? "#dc2626" : score < 4 ? "#d97706" : "#16a34a";
  });

  forms.confirm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = $("reset-code");
    const codeOk = /^\d{6}$/.test(code.value.trim());
    setError(code, codeOk ? "" : "Enter the 6-digit code.");
    const lengthOk = checkLength($("new-password"), "New password");
    const match = $("new-password").value === $("confirm-password").value;
    setError($("confirm-password"), match ? "" : "Passwords do not match.");
    if (!(codeOk && lengthOk && match)) return;
    const button = $("reset-confirm-submit");
    button.disabled = true;
    try {
      const data = await post("/api/password-reset/confirm", {
        email: resetEmail, code: code.value.trim(), new_password: $("new-password").value,
      });
      $("email").value = resetEmail;
      $("password").value = "";
      [code, $("new-password"), $("confirm-password")].forEach((f) => (f.value = ""));
      setView("login");
      show(data.message, "success");
    } catch (e) {
      show(e.message, "error");
    } finally {
      button.disabled = false;
    }
  });

  setView(document.body.dataset.startMode === "reset" ? "reset" : "login");
})();

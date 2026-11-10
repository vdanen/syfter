const API = {
  _keyStorageKey: "syfter_api_key",

  getKey() {
    return localStorage.getItem(this._keyStorageKey);
  },

  setKey(key) {
    localStorage.setItem(this._keyStorageKey, key);
  },

  clearKey() {
    localStorage.removeItem(this._keyStorageKey);
  },

  showLogin(message) {
    const app = document.getElementById("app");
    app.innerHTML = `
      <div class="login-container">
        <h2>Syfter</h2>
        <p>Enter your API key to continue</p>
        ${message ? `<div class="alert alert-error">${message}</div>` : ""}
        <div class="login-form">
          <input type="password" id="api-key-input" placeholder="API key">
          <button id="api-key-submit" class="btn-primary">Connect</button>
        </div>
      </div>`;

    const input = document.getElementById("api-key-input");
    const submit = document.getElementById("api-key-submit");

    const doLogin = () => {
      const key = input.value.trim();
      if (!key) return;
      this.setKey(key);
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    };

    submit.addEventListener("click", doLogin);
    input.addEventListener("keydown", e => { if (e.key === "Enter") doLogin(); });
    input.focus();
  },

  async request(path, params) {
    const url = new URL(path, window.location.origin);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v !== null && v !== undefined && v !== "") {
          url.searchParams.set(k, v);
        }
      }
    }

    const headers = {};
    const key = this.getKey();
    if (key) headers["X-API-Key"] = key;

    const resp = await fetch(url.toString(), { headers, redirect: "manual" });

    if (resp.type === "opaqueredirect" || resp.status === 302) {
      window.location.reload();
      throw new Error("__auth__");
    }

    if (resp.status === 401 || resp.status === 403) {
      this.clearKey();
      let hint = "Invalid or missing API key";
      try { const b = await resp.json(); hint = b.detail || b.error || hint; } catch (_) {}
      this.showLogin(hint);
      throw new Error("__auth__");
    }

    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try { const b = await resp.json(); detail = b.detail || b.error || detail; } catch (_) {}
      throw new Error(detail);
    }
    const data = await resp.json();
    data._headers = resp.headers;
    return data;
  },

  async upload(path, formData) {
    const headers = {};
    const key = this.getKey();
    if (key) headers["X-API-Key"] = key;

    const resp = await fetch(new URL(path, window.location.origin).toString(), {
      method: "POST",
      headers,
      body: formData,
      redirect: "manual",
    });

    if (resp.type === "opaqueredirect" || resp.status === 302) {
      window.location.reload();
      throw new Error("__auth__");
    }

    if (resp.status === 401 || resp.status === 403) {
      this.clearKey();
      this.showLogin("Session expired");
      throw new Error("__auth__");
    }

    if (!resp.ok) {
      let detail = `HTTP ${resp.status}`;
      try { const b = await resp.json(); detail = b.detail || b.error || detail; } catch (_) {}
      throw new Error(detail);
    }
    return resp.json();
  },

  stats() { return this.request("/api/v1/query/stats"); },

  products(limit = 50, offset = 0, name = null) {
    return this.request("/api/v1/products/", { limit, offset, name });
  },

  product(name, version) {
    return this.request(`/api/v1/products/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
  },

  productPackages(name, version, limit = 100, offset = 0) {
    return this.request(`/api/v1/query/list/packages/${encodeURIComponent(name)}/${encodeURIComponent(version)}`, { limit, offset });
  },

  searchPackages(params) {
    return this.request("/api/v1/query/packages", params);
  },

  frequency(params) {
    return this.request("/api/v1/query/packages/frequency", params);
  },

  importSbom(formData) {
    return this.upload("/api/v1/scans/import", formData);
  },
};

const App = {
  routes: {},

  register(pattern, handler) {
    this.routes[pattern] = handler;
  },

  start() {
    window.addEventListener("hashchange", () => this.route());
    document.getElementById("logout-btn").addEventListener("click", () => {
      API.clearKey();
      API.showLogin();
    });
    this.route();
  },

  route() {
    const hash = window.location.hash.slice(1) || "/";
    const app = document.getElementById("app");

    // Update nav active state
    document.querySelectorAll(".nav-links a").forEach(a => {
      const route = a.dataset.route;
      const isActive = route === "/" ? hash === "/" : hash.startsWith(route);
      a.classList.toggle("active", isActive);
    });

    // Match route -- try exact first, then pattern matches
    for (const [pattern, handler] of Object.entries(this.routes)) {
      const params = this.match(pattern, hash);
      if (params !== null) {
        try {
          handler(app, params);
        } catch (e) {
          if (e.message !== "__auth__") {
            const alert = document.createElement("div");
            alert.className = "alert alert-error";
            alert.textContent = e && e.message ? e.message : String(e);
            app.replaceChildren(alert);
          }
        }
        return;
      }
    }

    app.innerHTML = `<div class="empty-state"><p>Page not found</p></div>`;
  },

  match(pattern, path) {
    const pParts = pattern.split("/");
    const hParts = path.split("/");
    if (pParts.length !== hParts.length) return null;
    const params = {};
    for (let i = 0; i < pParts.length; i++) {
      if (pParts[i].startsWith(":")) {
        params[pParts[i].slice(1)] = decodeURIComponent(hParts[i]);
      } else if (pParts[i] !== hParts[i]) {
        return null;
      }
    }
    return params;
  },

  fmt(n) {
    if (n == null) return "--";
    return Number(n).toLocaleString();
  },

  skeleton(rows = 5) {
    return Array(rows).fill('<div class="skeleton" style="height:18px;margin-bottom:10px"></div>').join("");
  },
};

// Register views
App.register("/", (el) => StatsView.render(el));
App.register("/products", (el) => ProductsView.render(el));
App.register("/products/:name/:version", (el, p) => ProductDetailView.render(el, p));
App.register("/packages", (el) => PackagesView.render(el));
App.register("/import", (el) => ImportView.render(el));
App.register("/frequency", (el) => FrequencyView.render(el));

App.start();

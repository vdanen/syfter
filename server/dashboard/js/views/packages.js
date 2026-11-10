const PackagesView = {
  async render(el) {
    el.innerHTML = `
      <div class="page-header">
        <h2>Packages</h2>
        <p>Search across all products</p>
      </div>
      <div class="search-bar">
        <input type="search" id="pkg-search" placeholder="Package name (auto-adds % suffix for prefix match)">
        <input type="search" id="pkg-product" placeholder="Product filter (optional)" style="max-width:200px">
        <button class="btn-primary" id="pkg-go">Search</button>
      </div>
      <div class="card">
        <div id="pkg-results"><div class="empty-state"><p>Enter a package name to search</p></div></div>
      </div>`;

    const search = document.getElementById("pkg-search");
    const product = document.getElementById("pkg-product");
    const btn = document.getElementById("pkg-go");

    const doSearch = async () => {
      let name = search.value.trim();
      if (!name) return;
      if (!name.includes("%") && !name.includes("_")) name += "%";
      const resultsEl = document.getElementById("pkg-results");
      resultsEl.innerHTML = App.skeleton(6);

      try {
        const params = { name };
        const pf = product.value.trim();
        if (pf) params.product_name = pf + "%";

        const data = await API.searchPackages(params);
        const pkgs = Array.isArray(data) ? data : (data.packages || []);

        if (!pkgs.length) {
          resultsEl.innerHTML = `<div class="empty-state"><p>No packages matching "${esc(name)}"</p></div>`;
          return;
        }

        resultsEl.innerHTML = `
          <div class="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Version</th><th>Product</th><th>Arch</th><th>Type</th></tr></thead>
              <tbody>
                ${pkgs.map(p => `
                  <tr>
                    <td class="mono">${esc(p.name)}</td>
                    <td class="mono">${esc(p.version)}</td>
                    <td><a href="#/products/${encodeURIComponent(p.product_name)}/${encodeURIComponent(p.product_version)}" class="product-link">${esc(p.product_name)}-${esc(p.product_version)}</a></td>
                    <td>${esc(p.arch || "")}</td>
                    <td>${esc(p.type || "rpm")}</td>
                  </tr>`).join("")}
              </tbody>
            </table>
          </div>
          <div style="margin-top:8px;font-size:13px;color:var(--text-muted)">${pkgs.length} results (max 100)</div>`;
      } catch (e) {
        if (e.message !== "__auth__") {
          const isTimeout = e.message.includes("timeout") || e.message.includes("canceling statement");
          const hint = isTimeout ? " Try a more specific prefix (e.g., openssl instead of open)." : "";
          resultsEl.innerHTML = `<div class="alert alert-error">${e.message}${hint}</div>`;
        }
      }
    };

    btn.addEventListener("click", doSearch);
    search.addEventListener("keydown", e => { if (e.key === "Enter") doSearch(); });
    search.focus();
  },
};

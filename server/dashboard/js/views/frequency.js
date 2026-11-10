const FrequencyView = {
  async render(el) {
    el.innerHTML = `
      <div class="page-header">
        <h2>Package Frequency</h2>
        <p>See which products contain a given package version</p>
      </div>
      <div class="search-bar">
        <input type="search" id="freq-name" placeholder="Package name (e.g., openssl-libs or org.quarkus:quarkus-core)">
        <input type="search" id="freq-product" placeholder="Product filter (optional, use % wildcard)" style="max-width:240px">
        <button class="btn-primary" id="freq-go">Search</button>
      </div>
      <div id="freq-results"><div class="empty-state"><p>Enter a package name to see version frequency across products</p></div></div>`;

    const nameInput = document.getElementById("freq-name");
    const productInput = document.getElementById("freq-product");
    const btn = document.getElementById("freq-go");

    const doSearch = async () => {
      const name = nameInput.value.trim();
      if (!name) return;
      const resultsEl = document.getElementById("freq-results");
      resultsEl.innerHTML = App.skeleton(4);

      try {
        const params = { name };
        const pf = productInput.value.trim();
        if (pf) params.product_name = pf;

        const data = await API.frequency(params);
        const results = Array.isArray(data) ? data : [];

        if (!results.length) {
          resultsEl.innerHTML = `<div class="empty-state"><p>No results for "${esc(name)}"</p></div>`;
          return;
        }

        resultsEl.innerHTML = `
          <div class="freq-results">
            ${results.map(r => `
              <div class="freq-card">
                <div class="freq-header">
                  <span class="version">${esc(r.version)}</span>
                  <span class="count">${r.sbom_count} product${r.sbom_count !== 1 ? "s" : ""}</span>
                </div>
                <div class="product-tags">
                  ${r.products.map(p => `<span class="product-tag">${esc(p)}</span>`).join("")}
                </div>
              </div>`).join("")}
          </div>`;
      } catch (e) {
        if (e.message !== "__auth__") {
          resultsEl.innerHTML = `<div class="alert alert-error">${e.message}</div>`;
        }
      }
    };

    btn.addEventListener("click", doSearch);
    nameInput.addEventListener("keydown", e => { if (e.key === "Enter") doSearch(); });
    nameInput.focus();
  },
};

const ProductDetailView = {
  async render(el, params) {
    const { name, version } = params;

    el.innerHTML = `
      <div class="page-header">
        <h2>${esc(name)} <span class="mono" style="color:var(--text-secondary)">${esc(version)}</span></h2>
        <p>Loading...</p>
      </div>
      <div class="card">
        <div id="pkg-table">${App.skeleton(10)}</div>
        <div class="pagination" id="pkg-pag"></div>
      </div>`;

    let offset = 0;
    const limit = 100;

    const load = async () => {
      const tableEl = document.getElementById("pkg-table");
      const pagEl = document.getElementById("pkg-pag");
      if (!tableEl) return;

      try {
        const data = await API.productPackages(name, version, limit, offset);
        const pkgs = Array.isArray(data) ? data : (data.packages || []);
        const hasMore = pkgs.length === limit;
        const page = Math.floor(offset / limit) + 1;

        const header = el.querySelector(".page-header p");
        if (header) {
          const showing = offset + pkgs.length;
          header.textContent = hasMore ? `Showing ${App.fmt(offset + 1)}-${App.fmt(showing)} packages` : `${App.fmt(showing)} packages`;
        }

        if (!pkgs.length) {
          tableEl.innerHTML = `<div class="empty-state"><p>No packages found</p></div>`;
          pagEl.innerHTML = "";
          return;
        }

        tableEl.innerHTML = `
          <table>
            <thead><tr><th>Name</th><th>Version</th><th>Release</th><th>Arch</th><th>Type</th></tr></thead>
            <tbody>
              ${pkgs.map(p => `
                <tr>
                  <td class="mono">${esc(p.name)}</td>
                  <td class="mono">${esc(p.version)}</td>
                  <td class="mono">${esc(p.release || "")}</td>
                  <td>${esc(p.arch || "")}</td>
                  <td>${esc(p.type || "rpm")}</td>
                </tr>`).join("")}
            </tbody>
          </table>`;

        pagEl.innerHTML = `
          <button class="btn-ghost btn-sm" ${offset === 0 ? "disabled" : ""} id="pkg-prev">Prev</button>
          <span>Page ${page}</span>
          <button class="btn-ghost btn-sm" ${!hasMore ? "disabled" : ""} id="pkg-next">Next</button>`;

        document.getElementById("pkg-prev")?.addEventListener("click", () => { offset = Math.max(0, offset - limit); load(); });
        document.getElementById("pkg-next")?.addEventListener("click", () => { offset += limit; load(); });
      } catch (e) {
        if (e.message !== "__auth__") {
          tableEl.innerHTML = `<div class="alert alert-error">${e.message}</div>`;
        }
      }
    };

    await load();
  },
};

const StatsView = {
  async render(el) {
    el.innerHTML = `
      <div class="page-header">
        <h2>Overview</h2>
      </div>
      <div class="stats-grid">${Array(5).fill('<div class="stat-card"><div class="skeleton" style="height:14px;width:80px;margin-bottom:12px"></div><div class="skeleton" style="height:32px;width:120px"></div></div>').join("")}</div>`;

    try {
      const s = await API.stats();
      el.innerHTML = `
        <div class="page-header">
          <h2>Overview</h2>
          <p>Database: ${s.database_type} | Storage: ${s.storage_type}</p>
        </div>
        <div class="stats-grid">
          <div class="stat-card">
            <div class="label">Products</div>
            <div class="value">${App.fmt(s.products)}</div>
          </div>
          <div class="stat-card">
            <div class="label">Packages</div>
            <div class="value">${App.fmt(s.packages)}</div>
          </div>
          <div class="stat-card">
            <div class="label">Dependencies</div>
            <div class="value">${App.fmt(s.dependencies)}</div>
          </div>
          <div class="stat-card">
            <div class="label">Files</div>
            <div class="value">${App.fmt(s.files)}</div>
          </div>
          <div class="stat-card">
            <div class="label">Relationships</div>
            <div class="value">${App.fmt(s.component_relationships)}</div>
          </div>
        </div>`;
    } catch (e) {
      if (e.message !== "__auth__") {
        el.innerHTML = `<div class="alert alert-error">Failed to load stats: ${e.message}</div>`;
      }
    }
  },
};

const ImportView = {
  selectedFile: null,

  async render(el) {
    this.selectedFile = null;

    el.innerHTML = `
      <div class="page-header">
        <h2>Import SBOM</h2>
        <p>Upload an SPDX, CycloneDX, or syft-json SBOM file</p>
      </div>
      <div class="import-form">
        <div id="import-alert"></div>
        <div class="drop-zone" id="drop-zone">
          <div class="drop-label">Drop SBOM file here or click to browse</div>
          <div class="drop-hint">Accepts .spdx.json, .cdx.json, .bom.json, .syft.json (plain or gzip)</div>
          <input type="file" id="file-input" style="display:none" accept=".json,.gz,.spdx,.cdx,.bom">
        </div>
        <div class="form-row">
          <div class="form-group">
            <label for="import-product">Product name</label>
            <input type="text" id="import-product" placeholder="e.g., my-product">
          </div>
          <div class="form-group">
            <label for="import-version">Version</label>
            <input type="text" id="import-version" placeholder="e.g., 20260625">
          </div>
        </div>
        <div class="form-group">
          <label for="import-desc">Description (optional)</label>
          <input type="text" id="import-desc" placeholder="e.g., Acme Corp Q2 2026 application SBOM">
        </div>
        <button class="btn-primary" id="import-submit" disabled>Import</button>
      </div>`;

    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const submit = document.getElementById("import-submit");

    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
    dropZone.addEventListener("drop", e => {
      e.preventDefault();
      dropZone.classList.remove("drag-over");
      if (e.dataTransfer.files.length) this.setFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) this.setFile(fileInput.files[0]);
    });

    submit.addEventListener("click", () => this.submit());
  },

  setFile(file) {
    this.selectedFile = file;
    const dropZone = document.getElementById("drop-zone");
    const sizeKB = (file.size / 1024).toFixed(1);
    dropZone.innerHTML = `
      <div class="drop-label">${esc(file.name)}</div>
      <div class="file-name">${sizeKB} KB</div>
      <div class="drop-hint">Click to change file</div>`;
    this.checkReady();
  },

  checkReady() {
    const btn = document.getElementById("import-submit");
    const product = document.getElementById("import-product").value.trim();
    const version = document.getElementById("import-version").value.trim();
    btn.disabled = !(this.selectedFile && product && version);
  },

  async submit() {
    const product = document.getElementById("import-product").value.trim();
    const version = document.getElementById("import-version").value.trim();
    const desc = document.getElementById("import-desc").value.trim();
    const alertEl = document.getElementById("import-alert");
    const btn = document.getElementById("import-submit");

    if (!this.selectedFile || !product || !version) return;

    btn.disabled = true;
    btn.textContent = "Importing...";
    alertEl.innerHTML = "";

    const form = new FormData();
    form.append("sbom", this.selectedFile);
    form.append("product_name", product);
    form.append("product_version", version);
    if (desc) form.append("description", desc);

    try {
      const result = await API.importSbom(form);
      alertEl.innerHTML = `
        <div class="alert alert-success">
          Imported ${App.fmt(result.package_count)} packages as
          <a href="#/products/${encodeURIComponent(product)}/${encodeURIComponent(version)}" class="product-link" style="color:var(--success);text-decoration:underline">
            ${esc(product)}-${esc(version)}
          </a>
          (format: ${result.sbom_format})
        </div>`;
      btn.textContent = "Import";
      btn.disabled = false;
    } catch (e) {
      if (e.message !== "__auth__") {
        alertEl.innerHTML = `<div class="alert alert-error">Import failed: ${e.message}</div>`;
        btn.textContent = "Import";
        btn.disabled = false;
      }
    }
  },
};

document.addEventListener("input", e => {
  if (e.target.id === "import-product" || e.target.id === "import-version") {
    ImportView.checkReady();
  }
});

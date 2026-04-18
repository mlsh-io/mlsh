(function () {
  var picker = document.getElementById('version-picker');
  if (!picker) return;

  // Versions.json lives at the site root (one level above /vX.Y.Z/).
  var parts = window.location.pathname.split('/').filter(Boolean);
  var versionRe = /^v\d+\.\d+\.\d+/;
  var currentIdx = parts.findIndex(function (p) { return versionRe.test(p); });
  var currentVersion = currentIdx >= 0 ? parts[currentIdx] : null;
  var siteRoot = currentIdx >= 0 ? '/' : '/';
  var subPath = currentIdx >= 0 ? '/' + parts.slice(currentIdx + 1).join('/') : window.location.pathname;

  fetch(siteRoot + 'versions.json', { cache: 'no-cache' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data || !Array.isArray(data.versions)) return;
      picker.innerHTML = '';
      data.versions.forEach(function (v) {
        var opt = document.createElement('option');
        opt.value = v.version;
        opt.textContent = v.version + (v.latest ? ' (latest)' : '');
        if (v.version === currentVersion) opt.selected = true;
        picker.appendChild(opt);
      });
    })
    .catch(function () {});

  picker.addEventListener('change', function () {
    var target = picker.value;
    var newPath = '/' + target + subPath;
    // If target page doesn't exist, fall back to version root.
    fetch(newPath, { method: 'HEAD' })
      .then(function (r) {
        window.location.href = r.ok ? newPath : ('/' + target + '/');
      })
      .catch(function () {
        window.location.href = '/' + target + '/';
      });
  });
})();

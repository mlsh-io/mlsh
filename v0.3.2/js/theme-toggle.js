(function () {
  var root = document.documentElement;
  var btn = document.getElementById('theme-toggle');
  var light = document.getElementById('giallo-light');
  var dark = document.getElementById('giallo-dark');

  function current() {
    return root.getAttribute('data-theme') || 'dark';
  }

  function syncHighlightCss(theme) {
    if (!light || !dark) return;
    // Override prefers-color-scheme so the active highlight sheet matches the chosen theme.
    if (theme === 'light') {
      light.media = 'all';
      dark.media = 'not all';
    } else {
      light.media = 'not all';
      dark.media = 'all';
    }
  }

  // Apply on initial load in case data-theme came from localStorage.
  syncHighlightCss(current());

  if (!btn) return;
  btn.addEventListener('click', function () {
    var next = current() === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    if (next === 'dark') root.setAttribute('data-pf-theme', 'dark');
    else root.removeAttribute('data-pf-theme');
    syncHighlightCss(next);
    try { localStorage.setItem('mlsh-theme', next); } catch (_) {}
  });
})();

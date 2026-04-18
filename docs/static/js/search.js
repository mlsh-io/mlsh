(function () {
  var modal = document.getElementById('search-modal');
  var trigger = document.getElementById('search-trigger');
  var mountPoint = document.getElementById('pagefind-search');
  if (!modal || !trigger || !mountPoint) return;

  var ui = null;
  function mount() {
    if (ui || typeof PagefindUI === 'undefined') return;
    ui = new PagefindUI({
      element: '#pagefind-search',
      showSubResults: true,
      showImages: false,
      resetStyles: false,
      autofocus: true,
    });
  }

  function open() {
    modal.hidden = false;
    if (typeof PagefindUI !== 'undefined') {
      mount();
    } else {
      // Pagefind loads async; retry briefly.
      var tries = 0;
      var t = setInterval(function () {
        if (typeof PagefindUI !== 'undefined' || tries++ > 40) {
          clearInterval(t);
          mount();
        }
      }, 50);
    }
    setTimeout(function () {
      var input = modal.querySelector('input');
      if (input) input.focus();
    }, 30);
  }

  function close() { modal.hidden = true; }

  trigger.addEventListener('click', open);
  modal.addEventListener('click', function (e) {
    if (e.target.matches('[data-search-close]')) close();
  });

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      modal.hidden ? open() : close();
    } else if (e.key === 'Escape' && !modal.hidden) {
      close();
    }
  });
})();

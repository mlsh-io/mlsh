// Opens the <pagefind-modal> on click or Cmd/Ctrl+K.
(function () {
  var trigger = document.getElementById('search-trigger');
  var modal = document.getElementById('pagefind-modal');
  if (!trigger || !modal) return;

  function open() {
    if (typeof modal.open === 'function') modal.open();
  }
  function close() {
    if (typeof modal.close === 'function') modal.close();
  }
  function isOpen() {
    return !!modal.isOpen;
  }

  trigger.addEventListener('click', open);

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      isOpen() ? close() : open();
    }
  });
})();

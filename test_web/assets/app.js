// DemoShop Pro client script — static asset (should fast-pass the WAF)
(function () {
  // live search suggestions on the catalog page
  var box = document.querySelector('.filters input[name=q]');
  if (box) {
    var dl = document.createElement('datalist'); dl.id = 'suggest'; document.body.appendChild(dl);
    box.setAttribute('list', 'suggest');
    box.addEventListener('input', function () {
      if (box.value.length < 2) return;
      fetch('/suggest.php?term=' + encodeURIComponent(box.value))
        .then(function (r) { return r.json(); })
        .then(function (j) {
          dl.innerHTML = (j.suggestions || []).map(function (s) {
            return '<option value="' + s.replace(/"/g, '&quot;') + '">';
          }).join('');
        }).catch(function () {});
    });
  }
})();

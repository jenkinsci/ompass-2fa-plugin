(function () {
  function renameSecretKeyButton() {
    var inputs = document.querySelectorAll('[name="_.secretKey"]');
    inputs.forEach(function (el) {
      var wrapper = el.closest('.hidden-password');
      if (wrapper) {
        var btn = wrapper.querySelector('.hidden-password-update-btn');
        if (btn) {
          btn.textContent = 'Change SecretKey';
        }
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renameSecretKeyButton);
  } else {
    renameSecretKeyButton();
  }
})();

(function() {
  'use strict';

  var configDataEl = document.getElementById('ompass-config-data');
  var rootUrl = configDataEl.getAttribute('data-root-url') || '';

  var testBtn = document.getElementById('test-connection-btn');
  var spinner = document.getElementById('test-connection-spinner');
  var resultDiv = document.getElementById('test-connection-result');

  function getCrumb() {
    var crumbField = document.querySelector('[name=Jenkins-Crumb]');
    if (crumbField) {
      return crumbField.value;
    }
    return null;
  }

  function showResult(message, isSuccess) {
    resultDiv.className = isSuccess ? 'ok' : 'error';
    resultDiv.innerHTML = message;
  }

  testBtn.addEventListener('click', function() {
    spinner.className = '';
    resultDiv.innerHTML = '';
    resultDiv.className = '';
    testBtn.disabled = true;

    var params = 'ompassServerUrl=' + encodeURIComponent(document.querySelector('[name=ompassServerUrl]').value)
      + '&clientId=' + encodeURIComponent(document.querySelector('[name=clientId]').value)
      + '&secretKey=' + encodeURIComponent(document.querySelector('[name=secretKey]').value);

    var crumbValue = getCrumb();
    if (crumbValue) {
      params += '&Jenkins-Crumb=' + encodeURIComponent(crumbValue);
    }

    var xhr = new XMLHttpRequest();
    xhr.open('POST', rootUrl + '/ompass2fa-config/testConnection', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

    if (crumbValue) {
      xhr.setRequestHeader('Jenkins-Crumb', crumbValue);
    }

    if (window.crumb) {
      crumb.wrap(xhr);
    }

    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4) {
        spinner.className = 'jenkins-hidden';
        testBtn.disabled = false;

        if (xhr.status === 200) {
          try {
            var response = JSON.parse(xhr.responseText);
            if (response.success) {
              showResult('Connection successful.', true);
            } else {
              showResult('Connection failed: ' + (response.message || 'Unknown error'), false);
            }
          } catch (e) {
            showResult('Unexpected response from server.', false);
          }
        } else {
          showResult('Request failed (HTTP ' + xhr.status + '). Please check the server URL and try again.', false);
        }
      }
    };

    xhr.send(params);
  });
})();

(function() {
  function injectTokenBar() {
    if (document.getElementById('msf-token-bar')) return;

    var topbar = document.querySelector('.swagger-ui .topbar');
    if (!topbar) { setTimeout(injectTokenBar, 300); return; }

    var bar = document.createElement('div');
    bar.id = 'msf-token-bar';

    var label = document.createElement('label');
    label.textContent = '\uD83D\uDD11 API Token';

    var input = document.createElement('input');
    input.id = 'msf-token-input';
    input.type = 'password';
    input.placeholder = 'Cole seu token aqui: JWT (eyJ...) ou API Token (msy_...)';
    input.autocomplete = 'off';
    input.spellcheck = false;

    var eyeBtn = document.createElement('button');
    eyeBtn.id = 'msf-eye-btn';
    eyeBtn.textContent = '\uD83D\uDC41\uFE0F';
    eyeBtn.title = 'Revelar/Ocultar';
    eyeBtn.type = 'button';

    var applyBtn = document.createElement('button');
    applyBtn.id = 'msf-token-btn';
    applyBtn.textContent = 'Aplicar';
    applyBtn.type = 'button';

    var clearBtn = document.createElement('button');
    clearBtn.id = 'msf-clear-btn';
    clearBtn.textContent = 'Limpar';
    clearBtn.type = 'button';

    var status = document.createElement('span');
    status.id = 'msf-token-status';
    status.className = 'empty';
    status.textContent = '\u26A0\uFE0F Sem token — endpoints protegidos retornarão 401';

    bar.appendChild(label);
    bar.appendChild(input);
    bar.appendChild(eyeBtn);
    bar.appendChild(applyBtn);
    bar.appendChild(clearBtn);
    bar.appendChild(status);

    topbar.parentNode.insertBefore(bar, topbar.nextSibling);

    // Restaura token salvo
    var saved = localStorage.getItem('msf_api_token');
    if (saved) {
      input.value = saved;
      status.textContent = '\u2705 Token ativo \u2014 ' + saved.slice(0, 16) + '...';
      status.className = 'ok';
    }

    // Revelar/ocultar
    var revealed = false;
    eyeBtn.addEventListener('click', function() {
      revealed = !revealed;
      input.type = revealed ? 'text' : 'password';
      eyeBtn.textContent = revealed ? '\uD83D\uDE48' : '\uD83D\uDC41\uFE0F';
    });

    // Aplicar
    applyBtn.addEventListener('click', function() {
      var val = input.value.trim();
      if (!val) {
        localStorage.removeItem('msf_api_token');
        status.textContent = '\u26A0\uFE0F Sem token — endpoints protegidos retornarão 401';
        status.className = 'empty';
        return;
      }
      localStorage.setItem('msf_api_token', val);
      status.textContent = '\u2705 Token ativo \u2014 ' + val.slice(0, 16) + '...';
      status.className = 'ok';
      input.type = 'password';
      revealed = false;
      eyeBtn.textContent = '\uD83D\uDC41\uFE0F';
    });

    // Limpar
    clearBtn.addEventListener('click', function() {
      input.value = '';
      localStorage.removeItem('msf_api_token');
      status.textContent = '\u26A0\uFE0F Sem token — endpoints protegidos retornarão 401';
      status.className = 'empty';
    });

    // Enter aplica
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') applyBtn.click();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() { setTimeout(injectTokenBar, 800); });
  } else {
    setTimeout(injectTokenBar, 800);
  }
})();

(() => {
  'use strict';

  let activeModal = null;
  let modalOpener = null;
  let historyAbortController = null;

  const pageContent = document.querySelector('[data-page-content]');
  const focusableSelector = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])'
  ].join(',');

  function setPageContentInert(isInert) {
    if (!pageContent) return;

    pageContent.inert = isInert;
    if (isInert) {
      pageContent.setAttribute('aria-hidden', 'true');
    } else {
      pageContent.removeAttribute('aria-hidden');
    }
  }

  function openModal(modal, opener) {
    if (!modal) return;

    if (activeModal && activeModal !== modal) {
      closeModal(activeModal, false);
    }

    activeModal = modal;
    modalOpener = opener || document.activeElement;
    modal.hidden = false;
    document.body.classList.add('modal-open');
    setPageContentInert(true);

    window.requestAnimationFrame(() => {
      modal.classList.add('active');
      modal.querySelector(focusableSelector)?.focus();
    });
  }

  function closeModal(modal, restoreFocus = true) {
    if (!modal) return;

    modal.classList.remove('active');
    modal.hidden = true;

    if (modal.id === 'loginHistoryModal' && historyAbortController) {
      historyAbortController.abort();
      historyAbortController = null;
    }

    if (activeModal === modal) activeModal = null;
    if (!activeModal) {
      document.body.classList.remove('modal-open');
      setPageContentInert(false);
    }

    if (restoreFocus && modalOpener instanceof HTMLElement) modalOpener.focus();
    modalOpener = null;
  }

  function trapModalFocus(event) {
    if (!activeModal || event.key !== 'Tab') return;

    const focusable = [...activeModal.querySelectorAll(focusableSelector)]
      .filter(element => element instanceof HTMLElement && element.offsetParent !== null);

    if (!focusable.length) {
      event.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (!activeModal.contains(document.activeElement)) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  function setupModalControls() {
    document.querySelectorAll('[data-modal-target]').forEach(button => {
      button.addEventListener('click', () => {
        openModal(document.getElementById(button.dataset.modalTarget), button);
      });
    });

    document.querySelectorAll('[data-modal-close]').forEach(button => {
      button.addEventListener('click', () => closeModal(button.closest('.account-modal')));
    });

    document.querySelectorAll('.account-modal').forEach(modal => {
      modal.addEventListener('mousedown', event => {
        if (event.target === modal) closeModal(modal);
      });
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && activeModal) {
        event.preventDefault();
        closeModal(activeModal);
        return;
      }

      trapModalFocus(event);
    });
  }

  function setupEmployeePreview() {
    const select = document.querySelector('[data-employee-select]');
    const preview = document.querySelector('[data-employee-preview]');
    if (!select || !preview) return;

    select.addEventListener('change', () => {
      const option = select.selectedOptions[0];
      const username = option?.dataset.suggestedUsername;
      const email = option?.dataset.email;

      preview.textContent = username
        ? `Tên đăng nhập đề xuất: ${username} · Email: ${email || 'Chưa có'}`
        : 'Họ tên, email và tên đăng nhập được lấy từ hồ sơ nhân sự.';
    });
  }

  function setupRoleModal() {
    const modal = document.getElementById('changeRoleModal');
    const userId = modal?.querySelector('[data-role-user-id]');
    const expectedSecurityStamp = modal?.querySelector('[data-role-security-stamp]');
    const select = modal?.querySelector('[data-role-select]');
    const accountName = modal?.querySelector('[data-role-account-name]');
    if (!modal || !userId || !expectedSecurityStamp || !select || !accountName) return;

    document.querySelectorAll('[data-change-role]').forEach(button => {
      button.addEventListener('click', () => {
        userId.value = button.dataset.userId || '';
        expectedSecurityStamp.value = button.dataset.securityStamp || '';
        select.value = button.dataset.currentRole || '';
        accountName.textContent = `${button.dataset.displayName || ''} (${button.dataset.username || ''})`;
        openModal(modal, button);
      });
    });
  }

  function setupConfirmations() {
    document.querySelectorAll('form[data-confirm]').forEach(form => {
      form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm || 'Xác nhận thao tác này?')) {
          event.preventDefault();
        }
      });
    });
  }

  function setupPostFormGuards() {
    document.querySelectorAll('form[method="post"]').forEach(form => {
      form.addEventListener('submit', event => {
        if (event.defaultPrevented) return;
        if (form.dataset.submitting === 'true') {
          event.preventDefault();
          return;
        }

        form.dataset.submitting = 'true';
        form.setAttribute('aria-busy', 'true');
        form.querySelectorAll('button[type="submit"]').forEach(button => {
          button.disabled = true;
        });
      });
    });
  }

  function setupPasswordCopy() {
    const button = document.querySelector('[data-copy-password]');
    const value = document.getElementById('temporaryPasswordValue');
    const feedback = document.querySelector('[data-copy-feedback]');
    if (!button || !value || !feedback) return;

    button.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value.textContent || '');
        feedback.textContent = 'Đã sao chép mật khẩu.';
        const label = button.querySelector('span');
        if (label) label.textContent = 'Đã sao chép';
      } catch {
        const range = document.createRange();
        range.selectNodeContents(value);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
        feedback.textContent = 'Không thể tự sao chép. Mật khẩu đã được chọn để bạn sao chép thủ công.';
      }
    });
  }

  function badgeClass(action) {
    const normalized = String(action || '').toLowerCase();
    if (normalized.includes('fail') || normalized.includes('thất bại') || normalized.includes('blocked')) return 'badge-danger';
    if (normalized.includes('logout') || normalized.includes('đăng xuất')) return 'badge-info';
    return 'badge-success';
  }

  function appendCell(row, text, className) {
    const cell = document.createElement('td');
    cell.textContent = text || '—';
    if (className) cell.className = className;
    row.appendChild(cell);
  }

  function renderHistory(items, rows) {
    rows.replaceChildren();

    items.forEach(item => {
      const row = document.createElement('tr');
      appendCell(row, item.occurredAt || 'Không rõ');

      const actionCell = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge ${badgeClass(item.action)}`;
      badge.textContent = item.label || item.action || 'Sự kiện';
      actionCell.appendChild(badge);
      row.appendChild(actionCell);

      appendCell(row, item.deviceInfo || 'Không rõ');
      appendCell(row, item.ipAddress || 'Không rõ');
      appendCell(row, item.detail || '—', 'history-detail');
      rows.appendChild(row);
    });
  }

  function setupLoginHistory() {
    const modal = document.getElementById('loginHistoryModal');
    const endpoint = document.body.dataset.loginHistoryUrl;
    const accountName = modal?.querySelector('[data-history-account-name]');
    const loading = modal?.querySelector('[data-history-loading]');
    const error = modal?.querySelector('[data-history-error]');
    const empty = modal?.querySelector('[data-history-empty]');
    const table = modal?.querySelector('[data-history-table]');
    const rows = modal?.querySelector('[data-history-rows]');

    if (!modal || !endpoint || !accountName || !loading || !error || !empty || !table || !rows) return;

    document.querySelectorAll('[data-login-history]').forEach(button => {
      button.addEventListener('click', async () => {
        accountName.textContent = button.dataset.displayName || '';
        loading.hidden = false;
        error.hidden = true;
        empty.hidden = true;
        table.hidden = true;
        rows.replaceChildren();
        openModal(modal, button);

        historyAbortController?.abort();
        const requestController = new AbortController();
        historyAbortController = requestController;

        try {
          const url = new URL(endpoint, window.location.origin);
          url.searchParams.set('userId', button.dataset.userId || '');
          const response = await fetch(url, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
            signal: requestController.signal
          });

          if (response.redirected) {
            window.location.assign(response.url);
            return;
          }

          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const contentType = response.headers.get('content-type') || '';
          if (!contentType.includes('application/json')) throw new Error('Expected JSON response.');

          const payload = await response.json();
          const items = Array.isArray(payload.items) ? payload.items : [];
          accountName.textContent = payload.displayName
            ? `${payload.displayName} (${payload.username || ''})`
            : (button.dataset.displayName || '');

          if (!items.length) {
            empty.hidden = false;
          } else {
            renderHistory(items, rows);
            table.hidden = false;
          }
        } catch (requestError) {
          if (requestError.name !== 'AbortError') error.hidden = false;
        } finally {
          if (historyAbortController === requestController) {
            loading.hidden = true;
            historyAbortController = null;
          }
        }
      });
    });
  }

  setupModalControls();
  setupEmployeePreview();
  setupRoleModal();
  setupConfirmations();
  setupPostFormGuards();
  setupPasswordCopy();
  setupLoginHistory();
})();

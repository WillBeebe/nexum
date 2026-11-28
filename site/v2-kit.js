'use strict';
/* Shared zero-dependency interactive kit for nexum.fyi and comlink.fyi (Apache-2.0).
 * Uses document-level event delegation so it works identically in plain static HTML,
 * Next.js dev mode, and zero-hydration static exports.
 */
(() => {
  if (window.__v2KitLoaded) return;
  window.__v2KitLoaded = true;

  function activateTab(group, tabId) {
    const tabs = group.querySelectorAll('[data-v2-tab]');
    const panels = group.querySelectorAll('[data-v2-panel]');
    for (const tab of tabs) {
      const active = tab.getAttribute('data-v2-tab') === tabId;
      tab.setAttribute('data-active', active ? 'true' : 'false');
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    }
    for (const panel of panels) {
      panel.hidden = panel.getAttribute('data-v2-panel') !== tabId;
    }
  }

  function renderMatrix(matrix) {
    const branch = matrix.getAttribute('data-v2-branch') || 'accept';
    const step = matrix.getAttribute('data-v2-step') || '0';
    const warnBranch = branch !== 'accept';
    for (const btn of matrix.querySelectorAll('[data-v2-branch-btn]')) {
      const active = btn.getAttribute('data-v2-branch-btn') === branch;
      btn.setAttribute('data-active', active ? 'true' : 'false');
      btn.setAttribute('aria-pressed', active ? 'true' : 'false');
    }
    for (const btn of matrix.querySelectorAll('[data-v2-step-btn]')) {
      const value = btn.getAttribute('data-v2-step-btn');
      const idx = Number(value);
      const active = value === step;
      btn.setAttribute('data-active', active ? 'true' : 'false');
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
      btn.setAttribute('tabindex', active ? '0' : '-1');
      btn.setAttribute('data-warn', warnBranch && idx >= 2 && idx <= 4 ? 'true' : 'false');
    }
    const target = `${branch}:${step}`;
    for (const cell of matrix.querySelectorAll('[data-v2-cell]')) {
      cell.hidden = cell.getAttribute('data-v2-cell') !== target;
    }
  }

  document.addEventListener('click', async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const tabBtn = target.closest('[data-v2-tab]');
    if (tabBtn) {
      const group = tabBtn.closest('[data-v2-tabs]');
      if (group) activateTab(group, tabBtn.getAttribute('data-v2-tab'));
      return;
    }

    const branchBtn = target.closest('[data-v2-branch-btn]');
    if (branchBtn) {
      const matrix = branchBtn.closest('[data-v2-matrix]');
      if (matrix) {
        const nextBranch = branchBtn.getAttribute('data-v2-branch-btn');
        const currentStep = Number(matrix.getAttribute('data-v2-step') || '0');
        const jump = branchBtn.getAttribute('data-v2-jump');
        matrix.setAttribute('data-v2-branch', nextBranch);
        if (jump && currentStep < Number(jump)) {
          matrix.setAttribute('data-v2-step', jump);
        }
        renderMatrix(matrix);
      }
      return;
    }

    const stepBtn = target.closest('[data-v2-step-btn]');
    if (stepBtn) {
      const matrix = stepBtn.closest('[data-v2-matrix]');
      if (matrix) {
        matrix.setAttribute('data-v2-step', stepBtn.getAttribute('data-v2-step-btn'));
        renderMatrix(matrix);
      }
      return;
    }

    const copyBtn = target.closest('[data-v2-copy-text], [data-v2-copy-target]');
    if (copyBtn) {
      const sourceId = copyBtn.getAttribute('data-v2-copy-target');
      const sourceEl = sourceId ? document.getElementById(sourceId) : null;
      const text = sourceEl
        ? ('value' in sourceEl && typeof sourceEl.value === 'string' ? sourceEl.value : sourceEl.textContent)
        : (copyBtn.getAttribute('data-v2-copy-text') || '');
      const statusId = copyBtn.getAttribute('data-v2-copy-status');
      const statusEl = statusId ? document.getElementById(statusId) : null;
      const copiedMsg = copyBtn.getAttribute('data-v2-copied-status') || 'Copied.';
      const copiedLabel = copyBtn.getAttribute('data-v2-copied-label');
      const originalLabel = copyBtn.getAttribute('data-v2-original-label') || copyBtn.textContent;
      if (!copyBtn.hasAttribute('data-v2-original-label')) {
        copyBtn.setAttribute('data-v2-original-label', originalLabel);
      }
      copyBtn.disabled = true;
      try {
        await navigator.clipboard.writeText(text);
        if (statusEl) statusEl.textContent = copiedMsg;
        if (copiedLabel) {
          copyBtn.textContent = copiedLabel;
          setTimeout(() => { copyBtn.textContent = originalLabel; }, 1800);
        }
      } catch {
        if (statusEl) {
          let field = document.getElementById('v2-manual-copy');
          if (!field) {
            field = document.createElement('textarea');
            field.id = 'v2-manual-copy';
            field.className = 'manual-copy';
            field.readOnly = true;
            field.setAttribute('aria-label', 'Copyable instructions');
            statusEl.after(field);
          }
          field.value = text;
          field.focus();
          field.select();
          statusEl.textContent = 'Clipboard unavailable. Content selected below — use your device’s Copy command.';
        }
      } finally {
        copyBtn.disabled = false;
      }
    }
  });

  document.addEventListener('keydown', (event) => {
    if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(event.key)) return;
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;

    const tab = target.closest('[data-v2-tab], [data-v2-step-btn]');
    if (!tab) return;
    const isStep = tab.hasAttribute('data-v2-step-btn');
    const container = tab.closest(isStep ? '[data-v2-matrix]' : '[data-v2-tabs]');
    if (!container) return;

    const items = [...container.querySelectorAll(isStep ? '[data-v2-step-btn]' : '[data-v2-tab]')];
    const index = items.indexOf(tab);
    if (index === -1) return;

    event.preventDefault();
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % items.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + items.length) % items.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = items.length - 1;

    const nextEl = items[next];
    nextEl.focus();
    if (isStep) {
      container.setAttribute('data-v2-step', nextEl.getAttribute('data-v2-step-btn'));
      renderMatrix(container);
    } else {
      activateTab(container, nextEl.getAttribute('data-v2-tab'));
    }
  });
})();

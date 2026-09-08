'use strict';
const copyButton = document.getElementById('copy-instructions');
const brief = document.getElementById('agent-instructions');
const status = document.getElementById('copy-status');
copyButton?.addEventListener('click', async () => {
  copyButton.disabled = true;
  try {
    await navigator.clipboard.writeText(brief.textContent);
    status.textContent = 'Collaboration kit copied. Give that good idea a plan.';
  } catch {
    let field = document.getElementById('manual-copy');
    if (!field) {
      field = document.createElement('textarea');
      field.id = 'manual-copy';
      field.className = 'manual-copy';
      field.readOnly = true;
      field.setAttribute('aria-label', 'Collaboration kit in Markdown');
      field.value = brief.textContent;
      status.after(field);
    }
    field.focus();
    field.select();
    status.textContent = 'Instructions selected below. Use your device’s Copy command.';
  } finally {
    copyButton.disabled = false;
  }
});

// Decorate rendered copy only; leave code, agent instructions and metadata intact.
const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
  acceptNode(node) {
    return /\bnexum\b/i.test(node.textContent) &&
      !node.parentElement.closest('script, style, pre, code, textarea, svg, [hidden], .nexum-egg')
      ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
  }
});
const mentions = [];
while (walker.nextNode()) mentions.push(walker.currentNode);
for (const node of mentions) {
  const fragment = document.createDocumentFragment();
  const parts = node.textContent.split(/(\bnexum\b)/gi);
  for (const part of parts) {
    if (!/^nexum$/i.test(part)) {
      fragment.append(document.createTextNode(part));
      continue;
    }
    // A link keeps its navigation and keyboard behavior; never nest a button in it.
    const egg = document.createElement(node.parentElement.closest('a, button') ? 'span' : 'button');
    egg.className = 'nexum-egg';
    if (egg.tagName === 'BUTTON') egg.type = 'button';
    egg.setAttribute('aria-label', part);
    const label = document.createElement('span');
    label.className = 'egg-word';
    label.textContent = part;
    label.setAttribute('aria-hidden', 'true');
    const bubble = document.createElement('span');
    bubble.className = 'egg-message';
    bubble.setAttribute('role', 'status');
    egg.append(label, bubble);
    fragment.append(egg);
  }
  node.replaceWith(fragment);
}
for (const nexumEgg of document.querySelectorAll('.nexum-egg')) {
  const word = nexumEgg.querySelector('.egg-word');
  const message = nexumEgg.querySelector('.egg-message');
  const originalWord = word.textContent;
  word.style.width = `${word.getBoundingClientRect().width}px`;
  const trigger = nexumEgg.closest('a') || nexumEgg;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let shuffle;
  let reset;
  function restoreWord() {
    clearInterval(shuffle);
    word.textContent = originalWord;
  }
  function scramble() {
    if (reducedMotion.matches || nexumEgg.classList.contains('is-complete')) return;
    restoreWord();
    let step = 0;
    shuffle = setInterval(() => {
      step++;
      word.textContent = [...originalWord].map((letter, i) => i < Math.floor(step / 2) ? letter : '01<>/+*'[Math.floor(Math.random() * 7)]).join('');
      if (step >= 10) restoreWord();
    }, 45);
  }
  nexumEgg.addEventListener('pointerenter', scramble);
  trigger.addEventListener('focus', scramble);
  nexumEgg.addEventListener('pointerleave', restoreWord);
  trigger.addEventListener('blur', restoreWord);
  trigger.addEventListener('click', () => {
    restoreWord();
    clearTimeout(reset);
    nexumEgg.querySelectorAll('.egg-spark').forEach(spark => spark.remove());
    nexumEgg.classList.remove('is-complete');
    void nexumEgg.offsetWidth;
    message.textContent = '✓ Task complete.';
    nexumEgg.classList.add('is-complete');
    if (!reducedMotion.matches) {
      for (let i = 0; i < 12; i++) {
        const spark = document.createElement('span');
        spark.className = 'egg-spark';
        spark.setAttribute('aria-hidden', 'true');
        const angle = i * Math.PI / 6;
        spark.style.setProperty('--spark-x', `${Math.cos(angle) * 65}px`);
        spark.style.setProperty('--spark-y', `${Math.sin(angle) * 45}px`);
        spark.style.setProperty('--spark-color', ['#7bf4ca', '#bda4fa', '#ffbc79'][i % 3]);
        spark.addEventListener('animationend', () => spark.remove(), { once: true });
        nexumEgg.append(spark);
      }
    }
    reset = setTimeout(() => {
      nexumEgg.classList.remove('is-complete');
      message.textContent = '';
      nexumEgg.querySelectorAll('.egg-spark').forEach(spark => spark.remove());
    }, 2400);
  });
}

'use strict';

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const COPY_FEEDBACK_DURATION = 1800;
const PARALLAX_SCROLL_LIMIT = 1800;
const BACK_TO_TOP_THRESHOLD = 500;
const POINTER_RANGE = 2;
const root = document.documentElement;
const menuButton = document.querySelector('.menu-toggle');
const mobileMenu = document.querySelector('#mobile-menu');
menuButton.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? '关闭导航' : '打开导航');
  mobileMenu.hidden = !open;
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    mobileMenu.hidden = true;
    menuButton.setAttribute('aria-expanded', 'false');
    menuButton.setAttribute('aria-label', '打开导航');
  }
  if (event.key === '/' && !event.ctrlKey && !event.metaKey && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
    const search = document.querySelector('input[type="search"]');
    if (search) { event.preventDefault(); search.focus(); }
  }
});

document.querySelectorAll('[data-post-browser], [data-star-browser]').forEach(container => {
  const posts = container.hasAttribute('data-post-browser');
  const search = container.querySelector('input[type="search"]');
  const cards = [...container.querySelectorAll(posts ? '.post-card' : '.star-card')];
  const sourceFilter = container.querySelector('#source-filter');
  const chips = [...container.querySelectorAll('[data-filter]')];
  const parameters = new URLSearchParams(location.search);
  const filterKey = posts ? 'direction' : 'language';
  const requestedFilter = parameters.get(filterKey) || container.dataset.defaultFilter || 'all';
  let activeFilter = chips.some(chip => chip.dataset.filter === requestedFilter) ? requestedFilter : 'all';
  search.value = parameters.get('q') || '';
  if (sourceFilter && [...sourceFilter.options].some(option => option.value === parameters.get('source'))) sourceFilter.value = parameters.get('source');
  const applyFilters = () => {
    const query = search.value.trim().toLocaleLowerCase();
    let count = 0;
    cards.forEach(card => {
      const category = posts ? card.dataset.category : card.dataset.language;
      const sourceMatches = !sourceFilter || sourceFilter.value === 'all' || card.dataset.event === sourceFilter.value;
      card.hidden = !(activeFilter === 'all' || category === activeFilter) || !sourceMatches || !card.dataset.search.includes(query);
      if (!card.hidden) count++;
    });
    chips.forEach(chip => { const active = chip.dataset.filter === activeFilter; chip.classList.toggle('is-active', active); chip.setAttribute('aria-pressed', String(active)); });
    container.querySelector('[data-result-count]').textContent = count;
    container.querySelector('.empty-state').hidden = count > 0;
  };
  chips.forEach(chip => chip.addEventListener('click', event => { event.preventDefault(); activeFilter = chip.dataset.filter; applyFilters(); }));
  search.addEventListener('input', applyFilters);
  sourceFilter?.addEventListener('change', applyFilters);
  container.querySelector('[data-reset-search]').addEventListener('click', () => { activeFilter = 'all'; search.value = ''; if (sourceFilter) sourceFilter.value = 'all'; applyFilters(); search.focus(); });
  applyFilters();
});

document.querySelectorAll('.article-body pre').forEach(pre => {
  const code = pre.innerText;
  const button = document.createElement('button');
  button.className = 'copy-code';
  button.textContent = '复制';
  button.setAttribute('aria-label', '复制代码');
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(code);
      button.textContent = '已复制';
    } catch {
      button.textContent = '请选中后复制';
    }
    window.setTimeout(() => { button.textContent = '复制'; }, COPY_FEEDBACK_DURATION);
  });
  pre.append(button);
});

const backToTop = document.querySelector('.back-to-top');
const progress = document.querySelector('.reading-progress');
let scrollPending = false;
const paintScroll = () => {
  root.style.setProperty('--scroll', Math.min(window.scrollY, PARALLAX_SCROLL_LIMIT));
  const scrollable = root.scrollHeight - window.innerHeight;
  progress.style.transform = `scaleX(${scrollable > 0 ? window.scrollY / scrollable : 0})`;
  backToTop.hidden = window.scrollY < BACK_TO_TOP_THRESHOLD;
  backToTop.classList.toggle('is-visible', window.scrollY >= BACK_TO_TOP_THRESHOLD);
  scrollPending = false;
};
window.addEventListener('scroll', () => { if (!scrollPending) { scrollPending = true; requestAnimationFrame(paintScroll); } }, { passive: true });
window.addEventListener('resize', paintScroll, { passive: true });
backToTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: reducedMotion.matches ? 'instant' : 'smooth' }));
paintScroll();
if (window.matchMedia('(pointer: fine)').matches) {
  window.addEventListener('pointermove', event => {
    if (reducedMotion.matches) return;
    root.style.setProperty('--pointer-x', event.clientX / innerWidth * POINTER_RANGE - 1);
    root.style.setProperty('--pointer-y', event.clientY / innerHeight * POINTER_RANGE - 1);
  }, { passive: true });
}

const headings = document.querySelectorAll('.article-body h2[id], .article-body h3[id]');
if (headings.length) {
  const observer = new IntersectionObserver(entries => {
    const visible = entries.find(entry => entry.isIntersecting);
    if (!visible) return;
    document.querySelectorAll('.toc-link').forEach(link => link.classList.toggle('is-active', decodeURIComponent(link.hash.slice(1)) === visible.target.id));
  }, { rootMargin: '-15% 0px -65% 0px' });
  headings.forEach(heading => observer.observe(heading));
}

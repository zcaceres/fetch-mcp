(() => {
  // Tabbed terminal switchers
  for (const block of document.querySelectorAll('[data-tabs]')) {
    const buttons = block.querySelectorAll('[data-tab-target]');
    const panels = block.querySelectorAll('[data-tab-panel]');
    const filenameEl = block.querySelector('[data-tab-filename]');

    for (const btn of buttons) {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-tab-target');
        const filename = btn.getAttribute('data-filename');
        for (const b of buttons) {
          const active = b === btn;
          b.classList.toggle('is-active', active);
          b.setAttribute('aria-selected', String(active));
        }
        for (const panel of panels) {
          panel.classList.toggle('is-active', panel.getAttribute('data-tab-panel') === target);
        }
        if (filenameEl && filename) {
          filenameEl.textContent = filename;
        }
      });
    }
  }

  // Copy-to-clipboard buttons
  for (const btn of document.querySelectorAll('[data-copy-block]')) {
    btn.addEventListener('click', async () => {
      const container = btn.closest('.terminal-block');
      if (!container) return;
      const activePanel = container.querySelector('.terminal-panel.is-active pre') || container.querySelector('pre');
      if (!activePanel) return;
      const text = activePanel.textContent || '';
      try {
        await navigator.clipboard.writeText(text);
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('is-copied');
        window.setTimeout(() => {
          btn.textContent = orig;
          btn.classList.remove('is-copied');
        }, 1600);
      } catch {
        // Ignore clipboard errors in restricted contexts
      }
    });
  }

  // Mobile sidebar drawer
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebar-backdrop');
  const toggleBtn = document.getElementById('menu-toggle');

  const closeSidebar = () => {
    sidebar?.classList.remove('is-open');
    backdrop?.classList.remove('is-open');
    toggleBtn?.setAttribute('aria-expanded', 'false');
  };

  toggleBtn?.addEventListener('click', () => {
    const open = !sidebar?.classList.contains('is-open');
    sidebar?.classList.toggle('is-open', open);
    backdrop?.classList.toggle('is-open', open);
    toggleBtn.setAttribute('aria-expanded', String(open));
  });

  backdrop?.addEventListener('click', closeSidebar);
  for (const link of document.querySelectorAll('.sidebar-link')) {
    link.addEventListener('click', closeSidebar);
  }

  // Dismissible floating zach.dev statue badge
  const zachBadge = document.getElementById('zach-footer-logo');
  const zachDismiss = document.getElementById('zach-footer-dismiss');
  zachDismiss?.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (zachBadge) zachBadge.hidden = true;
  });

  // Scroll-spy active section highlighting
  const sections = Array.from(document.querySelectorAll('[data-section]'));
  const sidebarLinks = Array.from(document.querySelectorAll('.sidebar-link'));
  const topLinks = Array.from(document.querySelectorAll('.topbar-nav-link'));

  const setActive = (id) => {
    for (const link of sidebarLinks) {
      link.classList.toggle('is-active', link.getAttribute('href') === `#${id}`);
    }
    for (const link of topLinks) {
      const target = link.getAttribute('href');
      const active =
        target === `#${id}` ||
        (target === '#overview' && (id === 'overview' || id === 'quickstart' || id === 'clients')) ||
        (target === '#tools' && (id === 'tools' || id === 'http' || id === 'proxies')) ||
        (target === '#security' && (id === 'security' || id === 'migration'));
      link.classList.toggle('is-active', active);
    }
  };

  if ('IntersectionObserver' in window && sections.length > 0) {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]?.target.id) {
          setActive(visible[0].target.id);
        }
      },
      { rootMargin: '-88px 0px -65% 0px', threshold: 0 },
    );

    for (const section of sections) {
      observer.observe(section);
    }
  }
})();

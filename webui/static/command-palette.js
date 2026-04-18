/**
 * K8s-Janus Command Palette
 * Premium command palette with fuzzy search, keyboard navigation, and smooth animations
 */

class CommandPalette {
  constructor() {
    this.isOpen = false;
    this.selectedIndex = 0;
    this.filteredCommands = [];
    this.commands = [];
    this.init();
  }

  init() {
    this.createPaletteDOM();
    this.registerKeyboardShortcuts();
    this.loadCommands();
  }

  createPaletteDOM() {
    const backdrop = document.createElement('div');
    backdrop.id = 'cmd-palette-backdrop';
    backdrop.className = 'cmd-palette-backdrop';
    backdrop.addEventListener('click', () => this.close());

    const palette = document.createElement('div');
    palette.id = 'cmd-palette';
    palette.className = 'cmd-palette';
    palette.innerHTML = `
      <div class="cmd-palette-header">
        <i data-lucide="search" style="width:18px;height:18px;color:var(--text-dim);flex-shrink:0;"></i>
        <input
          type="text"
          id="cmd-palette-input"
          placeholder="Type a command or search..."
          autocomplete="off"
          spellcheck="false"
        />
        <div class="cmd-palette-shortcut">
          <kbd>⌘K</kbd>
        </div>
      </div>
      <div class="cmd-palette-results" id="cmd-palette-results">
        <!-- Results populated dynamically -->
      </div>
      <div class="cmd-palette-footer">
        <div class="cmd-palette-hint">
          <kbd>↑</kbd><kbd>↓</kbd> Navigate
          <kbd>↵</kbd> Select
          <kbd>ESC</kbd> Close
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);
    document.body.appendChild(palette);

    // Input event handlers
    const input = document.getElementById('cmd-palette-input');
    input.addEventListener('input', (e) => this.handleInput(e.target.value));
    input.addEventListener('keydown', (e) => this.handleKeydown(e));
  }

  registerKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Cmd+K or Ctrl+K to toggle
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        this.toggle();
      }
      // ESC to close
      if (e.key === 'Escape' && this.isOpen) {
        this.close();
      }
    });
  }

  loadCommands() {
    const currentPath = window.location.pathname;

    // Global commands (available everywhere)
    this.commands = [
      {
        id: 'home',
        label: 'Go to Home',
        icon: 'home',
        action: () => window.location.href = '/',
        group: 'Navigation'
      },
      {
        id: 'admin',
        label: 'Go to Admin Panel',
        icon: 'shield',
        action: () => window.location.href = '/admin',
        group: 'Navigation'
      },
      {
        id: 'profile',
        label: 'Open Profile',
        icon: 'user',
        action: () => window.location.href = '/#profile',
        group: 'Navigation'
      },
      {
        id: 'new-request',
        label: 'New Access Request',
        icon: 'plus-circle',
        action: () => window.location.href = '/',
        group: 'Actions'
      },
      {
        id: 'refresh',
        label: 'Refresh Page',
        icon: 'refresh-cw',
        action: () => window.location.reload(),
        group: 'Actions'
      },
      {
        id: 'toggle-theme',
        label: 'Toggle Dark Mode',
        icon: 'moon',
        action: () => this.toggleTheme(),
        group: 'Settings'
      }
    ];

    // Page-specific commands
    if (currentPath === '/admin') {
      this.commands.push(
        {
          id: 'filter-pending',
          label: 'Filter: Pending Requests',
          icon: 'clock',
          action: () => this.filterAdmin('Pending'),
          group: 'Admin'
        },
        {
          id: 'filter-active',
          label: 'Filter: Active Requests',
          icon: 'check-circle',
          action: () => this.filterAdmin('Active'),
          group: 'Admin'
        },
        {
          id: 'filter-all',
          label: 'Show All Requests',
          icon: 'list',
          action: () => this.filterAdmin('all'),
          group: 'Admin'
        }
      );
    }

    if (currentPath.startsWith('/terminal/')) {
      this.commands.push(
        {
          id: 'split-terminal',
          label: 'Split Terminal',
          icon: 'columns-2',
          action: () => typeof toggleSplit === 'function' && toggleSplit(),
          group: 'Terminal'
        },
        {
          id: 'copy-output',
          label: 'Copy Terminal Output',
          icon: 'copy',
          action: () => typeof copyTerminalOutput === 'function' && copyTerminalOutput(),
          group: 'Terminal'
        },
        {
          id: 'clear-terminal',
          label: 'Clear Terminal',
          icon: 'trash-2',
          action: () => this.clearTerminal(),
          group: 'Terminal'
        }
      );
    }

    // Quick commands from localStorage (if available)
    try {
      const quickCmds = JSON.parse(localStorage.getItem('quickCommands') || '[]');
      quickCmds.forEach((cmd, idx) => {
        this.commands.push({
          id: `qcmd-${idx}`,
          label: `Run: ${cmd.label}`,
          icon: 'zap',
          action: () => this.runQuickCommand(cmd.command),
          group: 'Quick Commands',
          meta: cmd.command
        });
      });
    } catch (e) {
      console.debug('No quick commands found');
    }
  }

  toggle() {
    if (this.isOpen) {
      this.close();
    } else {
      this.open();
    }
  }

  open() {
    this.isOpen = true;
    this.selectedIndex = 0;
    this.loadCommands(); // Refresh commands

    const backdrop = document.getElementById('cmd-palette-backdrop');
    const palette = document.getElementById('cmd-palette');
    const input = document.getElementById('cmd-palette-input');

    backdrop.classList.add('active');
    palette.classList.add('active');

    // Focus input after animation starts
    setTimeout(() => input.focus(), 50);

    // Show all commands initially
    this.handleInput('');

    // Animate in
    requestAnimationFrame(() => {
      backdrop.style.opacity = '1';
      palette.style.transform = 'translate(-50%, -50%) scale(1)';
      palette.style.opacity = '1';
    });
  }

  close() {
    this.isOpen = false;
    const backdrop = document.getElementById('cmd-palette-backdrop');
    const palette = document.getElementById('cmd-palette');
    const input = document.getElementById('cmd-palette-input');

    backdrop.style.opacity = '0';
    palette.style.transform = 'translate(-50%, -50%) scale(0.95)';
    palette.style.opacity = '0';
    palette.style.pointerEvents = 'none';

    setTimeout(() => {
      backdrop.classList.remove('active');
      palette.classList.remove('active');
      palette.style.pointerEvents = '';
      input.value = '';
    }, 200);
  }

  handleInput(query) {
    this.selectedIndex = 0;
    this.filteredCommands = this.fuzzySearch(query);
    this.renderResults();
  }

  fuzzySearch(query) {
    if (!query.trim()) {
      return this.commands;
    }

    const lowerQuery = query.toLowerCase();

    return this.commands
      .map(cmd => {
        const labelLower = cmd.label.toLowerCase();
        const metaLower = (cmd.meta || '').toLowerCase();

        // Calculate match score
        let score = 0;
        if (labelLower.includes(lowerQuery)) score += 10;
        if (metaLower.includes(lowerQuery)) score += 5;
        if (labelLower.startsWith(lowerQuery)) score += 20;

        // Character-by-character fuzzy match
        let queryIdx = 0;
        for (let i = 0; i < labelLower.length && queryIdx < lowerQuery.length; i++) {
          if (labelLower[i] === lowerQuery[queryIdx]) {
            score += 1;
            queryIdx++;
          }
        }

        return { cmd, score };
      })
      .filter(item => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .map(item => item.cmd);
  }

  renderResults() {
    const resultsEl = document.getElementById('cmd-palette-results');

    if (this.filteredCommands.length === 0) {
      resultsEl.innerHTML = `
        <div class="cmd-palette-empty">
          <i data-lucide="search-x" style="width:32px;height:32px;opacity:0.3;"></i>
          <p style="margin-top:8px;font-size:0.85rem;color:var(--text-dim);">No commands found</p>
        </div>
      `;
      if (typeof lucide !== 'undefined') lucide.createIcons();
      return;
    }

    // Group commands
    const groups = {};
    this.filteredCommands.forEach(cmd => {
      if (!groups[cmd.group]) groups[cmd.group] = [];
      groups[cmd.group].push(cmd);
    });

    let html = '';
    Object.entries(groups).forEach(([groupName, commands]) => {
      html += `<div class="cmd-palette-group-label">${groupName}</div>`;
      commands.forEach((cmd, idx) => {
        const globalIdx = this.filteredCommands.indexOf(cmd);
        const isSelected = globalIdx === this.selectedIndex;
        html += `
          <div
            class="cmd-palette-item ${isSelected ? 'selected' : ''}"
            data-idx="${globalIdx}"
            onmouseenter="commandPalette.selectedIndex = ${globalIdx}; commandPalette.renderResults();"
            onclick="commandPalette.executeCommand(${globalIdx})"
          >
            <div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">
              <i data-lucide="${cmd.icon}" style="width:16px;height:16px;flex-shrink:0;"></i>
              <span class="cmd-palette-item-label">${this.escapeHtml(cmd.label)}</span>
            </div>
            ${cmd.meta ? `<span class="cmd-palette-item-meta">${this.escapeHtml(cmd.meta)}</span>` : ''}
          </div>
        `;
      });
    });

    resultsEl.innerHTML = html;

    // Re-init lucide icons
    if (typeof lucide !== 'undefined') lucide.createIcons();

    // Scroll selected item into view
    const selectedEl = resultsEl.querySelector('.cmd-palette-item.selected');
    if (selectedEl) {
      selectedEl.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  handleKeydown(e) {
    switch(e.key) {
      case 'ArrowDown':
        e.preventDefault();
        this.selectedIndex = Math.min(this.selectedIndex + 1, this.filteredCommands.length - 1);
        this.renderResults();
        break;
      case 'ArrowUp':
        e.preventDefault();
        this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
        this.renderResults();
        break;
      case 'Enter':
        e.preventDefault();
        this.executeCommand(this.selectedIndex);
        break;
    }
  }

  executeCommand(idx) {
    const cmd = this.filteredCommands[idx];
    if (cmd && cmd.action) {
      this.close();
      setTimeout(() => cmd.action(), 100);
    }
  }

  // Helper actions
  toggleTheme() {
    // Placeholder for theme toggle
    alert('Theme toggle coming soon!');
  }

  filterAdmin(phase) {
    if (typeof window.filterRequests === 'function') {
      window.filterRequests(phase);
    }
  }

  clearTerminal() {
    if (typeof window.activePane !== 'undefined' && window[`term${window.activePane}`]) {
      window[`term${window.activePane}`].clear();
    }
  }

  runQuickCommand(command) {
    if (typeof window.executeQuickCommand === 'function') {
      window.executeQuickCommand(command);
    }
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize command palette on page load
let commandPalette;
document.addEventListener('DOMContentLoaded', () => {
  commandPalette = new CommandPalette();
});

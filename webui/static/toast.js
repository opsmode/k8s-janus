/**
 * K8s-Janus Toast Notification System
 * Minimal and non-intrusive
 */

class ToastManager {
  constructor() {
    this.container = null;
    this.toasts = new Map();
    this.init();
  }

  init() {
    if (!document.querySelector('.toast-container')) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    } else {
      this.container = document.querySelector('.toast-container');
    }
  }

  show(type, title, message = '', duration = 5000) {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'i'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.id = id;

    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-content">
        <div class="toast-title">${this.escapeHtml(title)}</div>
        ${message ? `<div class="toast-message">${this.escapeHtml(message)}</div>` : ''}
      </div>
      <div class="toast-close">×</div>
    `;

    this.container.appendChild(toast);

    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        toast.classList.add('show');
      });
    });

    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.dismiss(id);
    });

    toast.addEventListener('click', () => {
      this.dismiss(id);
    });

    if (duration > 0) {
      const timeoutId = setTimeout(() => {
        this.dismiss(id);
      }, duration);

      this.toasts.set(id, { element: toast, timeoutId });
    } else {
      this.toasts.set(id, { element: toast, timeoutId: null });
    }

    return id;
  }

  dismiss(id) {
    const toastData = this.toasts.get(id);
    if (!toastData) return;

    const { element, timeoutId } = toastData;

    if (timeoutId) {
      clearTimeout(timeoutId);
    }

    element.classList.remove('show');
    element.classList.add('hide');

    setTimeout(() => {
      if (element.parentNode) {
        element.parentNode.removeChild(element);
      }
      this.toasts.delete(id);
    }, 300);
  }

  dismissAll() {
    this.toasts.forEach((_, id) => {
      this.dismiss(id);
    });
  }

  success(title, message = '', duration = 5000) {
    return this.show('success', title, message, duration);
  }

  error(title, message = '', duration = 5000) {
    return this.show('error', title, message, duration);
  }

  warning(title, message = '', duration = 5000) {
    return this.show('warning', title, message, duration);
  }

  info(title, message = '', duration = 5000) {
    return this.show('info', title, message, duration);
  }

  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize after DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.toast = new ToastManager();
  });
} else {
  window.toast = new ToastManager();
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = ToastManager;
}

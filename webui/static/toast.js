/**
 * K8s-Janus Toast Notification System
 * Premium animated toast notifications with icons and auto-dismiss
 */

class ToastManager {
  constructor() {
    this.container = null;
    this.toasts = new Map();
    this.init();
  }

  init() {
    // Create container if it doesn't exist
    if (!document.querySelector('.toast-container')) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    } else {
      this.container = document.querySelector('.toast-container');
    }
  }

  /**
   * Show a toast notification
   * @param {string} type - Type of toast: 'success', 'error', 'warning', 'info'
   * @param {string} title - Toast title
   * @param {string} message - Toast message (optional)
   * @param {number} duration - Duration in ms (default: 5000, 0 for persistent)
   * @returns {string} Toast ID for manual dismissal
   */
  show(type, title, message = '', duration = 5000) {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.id = id;

    // Icon mapping
    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ'
    };

    toast.innerHTML = `
      <div class="toast-icon">${icons[type] || icons.info}</div>
      <div class="toast-content">
        <div class="toast-title">${this.escapeHtml(title)}</div>
        ${message ? `<div class="toast-message">${this.escapeHtml(message)}</div>` : ''}
      </div>
      <div class="toast-close" title="Dismiss">×</div>
    `;

    // Add to container
    this.container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        toast.classList.add('show');
      });
    });

    // Close button handler
    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.dismiss(id);
    });

    // Click to dismiss
    toast.addEventListener('click', () => {
      this.dismiss(id);
    });

    // Auto-dismiss if duration > 0
    if (duration > 0) {
      const timeoutId = setTimeout(() => {
        this.dismiss(id);
      }, duration);

      this.toasts.set(id, { element: toast, timeoutId });

      // Pause on hover
      toast.addEventListener('mouseenter', () => {
        clearTimeout(timeoutId);
      });

      toast.addEventListener('mouseleave', () => {
        const newTimeoutId = setTimeout(() => {
          this.dismiss(id);
        }, 2000); // Give 2 more seconds after hover

        const toastData = this.toasts.get(id);
        if (toastData) {
          toastData.timeoutId = newTimeoutId;
        }
      });
    } else {
      this.toasts.set(id, { element: toast, timeoutId: null });
    }

    return id;
  }

  /**
   * Dismiss a toast by ID
   * @param {string} id - Toast ID
   */
  dismiss(id) {
    const toastData = this.toasts.get(id);
    if (!toastData) return;

    const { element, timeoutId } = toastData;

    // Clear timeout if exists
    if (timeoutId) {
      clearTimeout(timeoutId);
    }

    // Animate out
    element.classList.remove('show');
    element.classList.add('hide');

    // Remove from DOM after animation
    setTimeout(() => {
      if (element.parentNode) {
        element.parentNode.removeChild(element);
      }
      this.toasts.delete(id);
    }, 300);
  }

  /**
   * Dismiss all toasts
   */
  dismissAll() {
    this.toasts.forEach((_, id) => {
      this.dismiss(id);
    });
  }

  /**
   * Helper methods for specific toast types
   */
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

  /**
   * Escape HTML to prevent XSS
   * @param {string} text - Text to escape
   * @returns {string} Escaped text
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Create global instance
window.toast = new ToastManager();

// Export for ES modules if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ToastManager;
}

/* ============================================================
   RESPONSIVE UTILITIES - JavaScript Helper Functions
   ============================================================ */

/**
 * Mobile Detection
 */
const ResponsiveUtils = {
    isMobile: function() {
        return window.innerWidth < 640;
    },

    isTablet: function() {
        return window.innerWidth >= 640 && window.innerWidth < 1024;
    },

    isDesktop: function() {
        return window.innerWidth >= 1024;
    },

    /**
     * Show/Hide elements based on screen size
     */
    toggleElementByScreen: function(elementId, condition) {
        const element = document.getElementById(elementId);
        if (element) {
            if (condition) {
                element.style.display = 'block';
                element.classList.remove('hidden');
            } else {
                element.style.display = 'none';
                element.classList.add('hidden');
            }
        }
    },

    /**
     * Handle button group wrapping on mobile
     */
    wrapButtonGroup: function(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const buttons = container.querySelectorAll('button, a.btn');
        if (this.isMobile() && buttons.length > 0) {
            container.style.display = 'flex';
            container.style.flexDirection = 'column';
            container.style.gap = '8px';
            buttons.forEach(btn => {
                btn.style.width = '100%';
            });
        } else {
            container.style.display = 'flex';
            container.style.flexDirection = 'row';
            container.style.gap = '12px';
            buttons.forEach(btn => {
                btn.style.width = 'auto';
            });
        }
    },

    /**
     * Convert table to mobile card view
     */
    makeTableResponsive: function(tableId) {
        const table = document.getElementById(tableId);
        if (!table) return;

        const rows = table.querySelectorAll('tbody tr');
        const headers = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent);

        rows.forEach((row, rowIndex) => {
            const cells = row.querySelectorAll('td');
            cells.forEach((cell, cellIndex) => {
                if (headers[cellIndex]) {
                    cell.setAttribute('data-label', headers[cellIndex]);
                }
            });
        });
    },

    /**
     * Lock scroll when mobile menu is open
     */
    lockScroll: function() {
        document.body.style.overflow = 'hidden';
    },

    /**
     * Unlock scroll
     */
    unlockScroll: function() {
        document.body.style.overflow = '';
    },

    /**
     * Handle responsive modals
     */
    openModal: function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('active');
            this.lockScroll();
        }
    },

    closeModal: function(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('active');
            this.unlockScroll();
        }
    },

    /**
     * Stack grid on mobile
     */
    makeGridResponsive: function(gridId) {
        const grid = document.getElementById(gridId);
        if (!grid) return;

        if (this.isMobile()) {
            grid.style.gridTemplateColumns = '1fr';
        } else if (this.isTablet()) {
            grid.style.gridTemplateColumns = 'repeat(2, 1fr)';
        } else {
            grid.style.gridTemplateColumns = 'repeat(3, 1fr)';
        }
    },

    /**
     * Initialize all responsive features
     */
    init: function() {
        // Handle window resize
        let resizeTimer;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimer);
            resizeTimer = setTimeout(() => {
                this.updateResponsiveElements();
            }, 250);
        });
    },

    updateResponsiveElements: function() {
        // Update any responsive elements that need recalculation
        document.querySelectorAll('[data-responsive-grid]').forEach(grid => {
            this.makeGridResponsive(grid.id);
        });
    }
};

// Initialize responsive utilities on page load
document.addEventListener('DOMContentLoaded', function() {
    ResponsiveUtils.init();
});

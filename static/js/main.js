// Main JavaScript file for Sistema de Transferência de Arquivos

// Global variables
let toastContainer = null;
let currentTheme = 'light';

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    setupTooltips();
    setupFormValidation();
    setupFileUpload();
    setupTableInteractions();
    setupAutoRefresh();
    setupThemeToggle();
    setupAccessibility();
    setupSidebarPersistence();
    setupSidebarInteractions();
    setupImageExpansion();
});

// Initialize the application
function initializeApp() {
    console.log('Sistema de Transferência de Arquivos - Inicializando...');

    // Create toast container
    createToastContainer();

    // Initialize current page
    initializePage();

    // Setup search functionality
    setupSearch();

    // Setup pagination
    setupPagination();

    // Load user preferences
    loadUserPreferences();

    console.log('Aplicação inicializada com sucesso!');
}

// Setup event listeners
function setupEventListeners() {
    // Sidebar toggle for mobile
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', toggleSidebar);
    }

    // Let Bootstrap handle dropdowns - removing custom dropdown logic that conflicts

    // Close custom dropdowns when clicking outside (only for non-Bootstrap dropdowns)
    document.addEventListener('click', function(e) {
        if (!e.target.closest('.dropdown') && !e.target.hasAttribute('data-bs-toggle')) {
            document.querySelectorAll('.dropdown-menu.show:not([data-bs-popper])').forEach(menu => {
                menu.classList.remove('show');
            });
        }
    });

    // Form submission handlers
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', handleFormSubmit);
    });

    // Modal handlers
    document.querySelectorAll('[data-bs-toggle="modal"]').forEach(trigger => {
        trigger.addEventListener('click', handleModalTrigger);
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// Setup tooltips
function setupTooltips() {
    // Initialize Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Setup form validation
function setupFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');

    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();

                // Show first invalid field
                const firstInvalid = form.querySelector(':invalid');
                if (firstInvalid) {
                    firstInvalid.focus();
                    showToast('Por favor, corrija os erros no formulário', 'error');
                }
            }

            form.classList.add('was-validated');
        });
    });

    // Real-time validation
    document.querySelectorAll('.form-control, .form-select').forEach(field => {
        field.addEventListener('blur', function() {
            validateField(this);
        });

        field.addEventListener('input', function() {
            if (this.classList.contains('is-invalid')) {
                validateField(this);
            }
        });
    });
}

// Validate individual field
function validateField(field) {
    const isValid = field.checkValidity();

    field.classList.remove('is-valid', 'is-invalid');
    field.classList.add(isValid ? 'is-valid' : 'is-invalid');

    // Update feedback message
    const feedback = field.parentNode.querySelector('.invalid-feedback');
    if (feedback && !isValid) {
        feedback.textContent = field.validationMessage;
    }
}

// Setup file upload functionality
function setupFileUpload() {
    const fileInputs = document.querySelectorAll('input[type="file"]');

    fileInputs.forEach(input => {
        // Create custom file upload zone
        createFileUploadZone(input);

        // Handle file selection
        input.addEventListener('change', function(e) {
            handleFileSelection(e.target);
        });
    });
}

// Create file upload zone
function createFileUploadZone(input) {
    const wrapper = document.createElement('div');
    wrapper.className = 'file-upload-zone';
    wrapper.innerHTML = `
        <div class="file-upload-content">
            <i class="fas fa-cloud-upload-alt fa-3x text-muted mb-3"></i>
            <p class="mb-2">Arraste arquivos aqui ou clique para selecionar</p>
            <small class="text-muted">Formatos aceitos: ${getAcceptedFormats(input)}</small>
        </div>
        <div class="file-upload-preview" style="display: none;"></div>
    `;

    // Insert wrapper before input
    input.parentNode.insertBefore(wrapper, input);
    input.style.display = 'none';

    // Setup drag and drop
    setupDragAndDrop(wrapper, input);

    // Click to open file dialog
    wrapper.addEventListener('click', () => input.click());
}

// Setup drag and drop
function setupDragAndDrop(zone, input) {
    zone.addEventListener('dragover', function(e) {
        e.preventDefault();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', function(e) {
        e.preventDefault();
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', function(e) {
        e.preventDefault();
        zone.classList.remove('dragover');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            input.files = files;
            handleFileSelection(input);
        }
    });
}

// Handle file selection
function handleFileSelection(input) {
    const zone = input.parentNode.querySelector('.file-upload-zone');
    const preview = zone.querySelector('.file-upload-preview');
    const content = zone.querySelector('.file-upload-content');

    if (input.files.length > 0) {
        const file = input.files[0];

        // Show preview
        preview.innerHTML = `
            <div class="selected-file">
                <i class="fas fa-file fa-2x text-primary mb-2"></i>
                <p class="mb-1"><strong>${file.name}</strong></p>
                <small class="text-muted">${formatFileSize(file.size)}</small>
                <button type="button" class="btn btn-sm btn-outline-danger ms-2" onclick="clearFileSelection(this)">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        content.style.display = 'none';
        preview.style.display = 'block';

        // Validate file
        if (!validateFile(file, input)) {
            showToast('Arquivo inválido. Verifique o formato e tamanho.', 'error');
            clearFileSelection(preview.querySelector('button'));
        }
    }
}

// Clear file selection
function clearFileSelection(button) {
    const zone = button.closest('.file-upload-zone');
    const input = zone.parentNode.querySelector('input[type="file"]');
    const preview = zone.querySelector('.file-upload-preview');
    const content = zone.querySelector('.file-upload-content');

    input.value = '';
    preview.style.display = 'none';
    content.style.display = 'block';
}

// Validate file
function validateFile(file, input) {
    const accept = input.getAttribute('accept');
    const maxSize = input.getAttribute('data-max-size') || 16777216; // 16MB default

    // Check file size
    if (file.size > maxSize) {
        return false;
    }

    // Check file type
    if (accept) {
        const acceptedTypes = accept.split(',').map(type => type.trim());
        const fileExtension = '.' + file.name.split('.').pop().toLowerCase();

        if (!acceptedTypes.some(type => {
            if (type.startsWith('.')) {
                return type === fileExtension;
            }
            return file.type.match(type);
        })) {
            return false;
        }
    }

    return true;
}

// Get accepted formats for display
function getAcceptedFormats(input) {
    const accept = input.getAttribute('accept');
    if (!accept) return 'Todos os formatos';

    return accept.split(',').map(type => type.trim().toUpperCase()).join(', ');
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Setup table interactions
function setupTableInteractions() {
    // Clickable rows
    document.querySelectorAll('tr[onclick]').forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function(e) {
            // Don't trigger if clicked on button or link
            if (e.target.closest('.btn, a')) {
                return;
            }

            // Execute onclick attribute
            eval(this.getAttribute('onclick'));
        });
    });

    // Table sorting
    document.querySelectorAll('th[data-sort]').forEach(header => {
        header.style.cursor = 'pointer';
        header.addEventListener('click', function() {
            sortTable(this);
        });
    });

    // Row selection
    document.querySelectorAll('input[type="checkbox"][data-row-select]').forEach(checkbox => {
        checkbox.addEventListener('change', handleRowSelection);
    });

    // Select all checkbox
    const selectAllCheckbox = document.querySelector('#selectAll');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', handleSelectAll);
    }
}

// Handle row selection
function handleRowSelection(e) {
    const checkbox = e.target;
    const row = checkbox.closest('tr');

    if (checkbox.checked) {
        row.classList.add('table-active');
    } else {
        row.classList.remove('table-active');
    }

    updateSelectionActions();
}

// Handle select all
function handleSelectAll(e) {
    const selectAll = e.target;
    const checkboxes = document.querySelectorAll('input[type="checkbox"][data-row-select]');

    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAll.checked;
        checkbox.dispatchEvent(new Event('change'));
    });
}

// Update selection actions
function updateSelectionActions() {
    const selectedRows = document.querySelectorAll('input[type="checkbox"][data-row-select]:checked');
    const actionButtons = document.querySelectorAll('.selection-actions .btn');

    if (selectedRows.length > 0) {
        actionButtons.forEach(btn => btn.disabled = false);
        document.querySelector('.selection-count').textContent = selectedRows.length;
    } else {
        actionButtons.forEach(btn => btn.disabled = true);
        document.querySelector('.selection-count').textContent = '0';
    }
}

// Sort table
function sortTable(header) {
    const table = header.closest('table');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const column = header.cellIndex;
    const sortOrder = header.dataset.sort === 'asc' ? 'desc' : 'asc';

    // Update sort indicators
    table.querySelectorAll('th[data-sort]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        th.dataset.sort = '';
    });

    header.classList.add(`sort-${sortOrder}`);
    header.dataset.sort = sortOrder;

    // Sort rows
    rows.sort((a, b) => {
        const aText = a.cells[column].textContent.trim();
        const bText = b.cells[column].textContent.trim();

        // Try to parse as numbers
        const aNum = parseFloat(aText);
        const bNum = parseFloat(bText);

        if (!isNaN(aNum) && !isNaN(bNum)) {
            return sortOrder === 'asc' ? aNum - bNum : bNum - aNum;
        }

        // Sort as strings
        return sortOrder === 'asc' ? aText.localeCompare(bText) : bText.localeCompare(aText);
    });

    // Reorder rows
    rows.forEach(row => tbody.appendChild(row));
}

// Setup auto refresh
function setupAutoRefresh() {
    const refreshElements = document.querySelectorAll('[data-auto-refresh]');

    refreshElements.forEach(element => {
        const interval = parseInt(element.dataset.autoRefresh) || 10000;
        const url = element.dataset.refreshUrl;

        if (url) {
            setInterval(() => {
                refreshElement(element, url);
            }, interval);
        }
    });
}

// Refresh element content
function refreshElement(element, url) {
    fetch(url)
        .then(response => response.text())
        .then(html => {
            element.innerHTML = html;

            // Update timestamp
            const timestamp = element.querySelector('.last-update');
            if (timestamp) {
                timestamp.textContent = 'Última atualização: ' + new Date().toLocaleTimeString();
            }
        })
        .catch(error => {
            console.error('Erro ao atualizar conteúdo:', error);
        });
}

// Setup search functionality
function setupSearch() {
    const searchInputs = document.querySelectorAll('input[type="search"], .search-input');

    searchInputs.forEach(input => {
        let searchTimeout;

        input.addEventListener('input', function() {
            clearTimeout(searchTimeout);

            // Debounce search
            searchTimeout = setTimeout(() => {
                performSearch(this);
            }, 300);
        });

        // Clear search
        const clearButton = input.parentNode.querySelector('.search-clear');
        if (clearButton) {
            clearButton.addEventListener('click', function() {
                input.value = '';
                performSearch(input);
            });
        }
    });
}

// Perform search
function performSearch(input) {
    const form = input.closest('form');
    const query = input.value.trim();

    if (form) {
        // Update URL without form submission
        const formData = new FormData(form);
        const params = new URLSearchParams(formData);

        // Update browser history
        const newUrl = `${window.location.pathname}?${params.toString()}`;
        history.pushState(null, '', newUrl);

        // Submit form
        form.submit();
    }
}

// Setup pagination
function setupPagination() {
    const paginationLinks = document.querySelectorAll('.pagination .page-link');

    paginationLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();

            const url = this.href;
            if (url && url !== '#') {
                window.location.href = url;
            }
        });
    });
}

// Setup theme toggle
function setupThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }

    // Load saved theme
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        currentTheme = savedTheme;
        applyTheme(currentTheme);
    }
}

// Toggle theme
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    applyTheme(currentTheme);
    localStorage.setItem('theme', currentTheme);
}

// Apply theme
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);

    const themeIcon = document.querySelector('#themeToggle i');
    if (themeIcon) {
        themeIcon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
    }
}

// Setup accessibility
function setupAccessibility() {
    // Skip link
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.className = 'skip-link';
    skipLink.textContent = 'Pular para o conteúdo principal';
    document.body.insertBefore(skipLink, document.body.firstChild);

    // ARIA live regions
    const liveRegion = document.createElement('div');
    liveRegion.setAttribute('aria-live', 'polite');
    liveRegion.setAttribute('aria-atomic', 'true');
    liveRegion.className = 'sr-only';
    liveRegion.id = 'live-region';
    document.body.appendChild(liveRegion);

    // Focus management
    document.addEventListener('keydown', handleFocusManagement);
}

// Handle focus management
function handleFocusManagement(e) {
    // Escape key closes modals
    if (e.key === 'Escape') {
        const openModal = document.querySelector('.modal.show');
        if (openModal) {
            const modal = bootstrap.Modal.getInstance(openModal);
            if (modal) {
                modal.hide();
            }
        }

        // Close dropdowns
        document.querySelectorAll('.dropdown-menu.show').forEach(menu => {
            menu.classList.remove('show');
        });
    }

    // Tab trapping in modals
    if (e.key === 'Tab') {
        const openModal = document.querySelector('.modal.show');
        if (openModal) {
            trapFocus(e, openModal);
        }
    }
}

// Trap focus within element
function trapFocus(e, element) {
    const focusableElements = element.querySelectorAll(
        'a[href], button, textarea, input[type="text"], input[type="radio"], input[type="checkbox"], select'
    );

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    if (e.shiftKey) {
        if (document.activeElement === firstElement) {
            lastElement.focus();
            e.preventDefault();
        }
    } else {
        if (document.activeElement === lastElement) {
            firstElement.focus();
            e.preventDefault();
        }
    }
}

// Initialize page-specific functionality
function initializePage() {
    const body = document.body;
    const pageClass = body.className;

    // Dashboard page
    if (pageClass.includes('dashboard')) {
        initializeDashboard();
    }

    // Profiles page
    if (pageClass.includes('profiles')) {
        initializeProfiles();
    }

    // Users page
    if (pageClass.includes('users')) {
        initializeUsers();
    }

    // Audit page
    if (pageClass.includes('audit')) {
        initializeAudit();
    }
}

// Initialize dashboard
function initializeDashboard() {
    // Auto-refresh stats
    setInterval(updateDashboardStats, 30000);

    // Initialize charts if needed
    initializeCharts();
}

// Initialize profiles
function initializeProfiles() {
    // Profile-specific functionality
    setupProfileActions();
}

// Initialize users
function initializeUsers() {
    // User-specific functionality
    setupUserActions();
}

// Initialize audit
function initializeAudit() {
    // Audit-specific functionality
    setupAuditActions();
}

// Update dashboard stats
function updateDashboardStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(stats => {
            updateStatCards(stats);
        })
        .catch(error => {
            console.error('Erro ao atualizar estatísticas:', error);
        });
}

// Update stat cards
function updateStatCards(stats) {
    Object.keys(stats).forEach(key => {
        const card = document.querySelector(`[data-stat="${key}"]`);
        if (card) {
            const number = card.querySelector('.stat-number, .h5, .h4');
            if (number) {
                number.textContent = stats[key];
            }
        }
    });
}

// Initialize charts
function initializeCharts() {
    // Chart.js initialization if needed
    const chartElements = document.querySelectorAll('[data-chart]');

    chartElements.forEach(element => {
        const chartType = element.dataset.chart;
        const chartData = JSON.parse(element.dataset.chartData || '{}');

        initializeChart(element, chartType, chartData);
    });
}

// Initialize individual chart
function initializeChart(element, type, data) {
    // This would initialize Chart.js charts
    console.log('Initializing chart:', type, data);
}

// Setup profile actions
function setupProfileActions() {
    // Profile duplication
    window.duplicateProfile = function(profileId) {
        if (confirm('Deseja duplicar este perfil? Uma cópia será criada com todas as configurações.')) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `/perfis/${profileId}/duplicar`;
            document.body.appendChild(form);
            form.submit();
        }
    };

    // Profile deletion
    window.deleteProfile = function(profileId, profileName) {
        if (confirm(`Tem certeza que deseja excluir o perfil "${profileName}"?`)) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `/perfis/${profileId}/deletar`;
            document.body.appendChild(form);
            form.submit();
        }
    };
}

// Setup user actions
function setupUserActions() {
    // User-specific actions
    window.toggleUserStatus = function(userId) {
        // Implementation for toggling user status
        console.log('Toggling user status for:', userId);
    };
}

// Setup audit actions
function setupAuditActions() {
    // Audit-specific actions
    window.restoreRecord = function(table, recordId) {
        if (confirm('Tem certeza que deseja restaurar este registro?')) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `/historico/restaurar/${table}/${recordId}`;
            document.body.appendChild(form);
            form.submit();
        }
    };
}

// Handle form submission
function handleFormSubmit(e) {
    const form = e.target;
    const submitBtn = form.querySelector('button[type="submit"]');

    if (submitBtn) {
        // Show loading state
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner"></span> Processando...';
        submitBtn.disabled = true;

        // Restore button after delay if form doesn't redirect
        setTimeout(() => {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }, 5000);
    }
}

// Handle modal trigger
function handleModalTrigger(e) {
    const trigger = e.target;
    const modalId = trigger.dataset.bsTarget;

    if (modalId) {
        const modal = document.querySelector(modalId);
        if (modal) {
            // Custom modal initialization
            const bsModal = new bootstrap.Modal(modal);
            bsModal.show();
        }
    }
}

// Handle keyboard shortcuts
function handleKeyboardShortcuts(e) {
    // Ctrl+/ or Cmd+/ for help
    if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        showHelp();
    }

    // Ctrl+K or Cmd+K for search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        focusSearch();
    }

    // Ctrl+N or Cmd+N for new record
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
        e.preventDefault();
        createNewRecord();
    }
}

// Show help
function showHelp() {
    const helpModal = document.getElementById('helpModal');
    if (helpModal) {
        const modal = new bootstrap.Modal(helpModal);
        modal.show();
    } else {
        showToast('Ajuda: Use Ctrl+K para buscar, Ctrl+N para criar novo registro', 'info');
    }
}

// Focus search
function focusSearch() {
    const searchInput = document.querySelector('input[type="search"], .search-input');
    if (searchInput) {
        searchInput.focus();
    }
}

// Create new record
function createNewRecord() {
    const newButton = document.querySelector('.btn-primary[href*="/novo"]');
    if (newButton) {
        window.location.href = newButton.href;
    }
}

// Toggle sidebar for mobile
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    
    if (sidebar) {
        sidebar.classList.toggle('show');
        
        // Close sidebar when clicking outside on mobile
        if (sidebar.classList.contains('show')) {
            document.addEventListener('click', closeSidebarOnOutsideClick);
        } else {
            document.removeEventListener('click', closeSidebarOnOutsideClick);
        }
    }
}

// Close sidebar when clicking outside on mobile
function closeSidebarOnOutsideClick(e) {
    const sidebar = document.querySelector('.sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');
    
    if (sidebar && !sidebar.contains(e.target) && !sidebarToggle.contains(e.target)) {
        sidebar.classList.remove('show');
        document.removeEventListener('click', closeSidebarOnOutsideClick);
    }
}

// Load user preferences
function loadUserPreferences() {
    const preferences = JSON.parse(localStorage.getItem('userPreferences') || '{}');

    // Apply preferences
    if (preferences.theme) {
        applyTheme(preferences.theme);
    }

    if (preferences.sidebarCollapsed) {
        toggleSidebar();
    }
}

// Save user preferences
function saveUserPreferences() {
    const preferences = {
        theme: currentTheme,
        sidebarCollapsed: document.querySelector('.sidebar').classList.contains('sidebar-collapsed')
    };

    localStorage.setItem('userPreferences', JSON.stringify(preferences));
}

// Create toast container
function createToastContainer() {
    toastContainer = document.createElement('div');
    toastContainer.className = 'toast-container';
    toastContainer.id = 'toast-container';
    document.body.appendChild(toastContainer);
}

// Show toast notification
function showToast(message, type = 'info', duration = 5000) {
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');

    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-triangle',
        warning: 'fas fa-exclamation-circle',
        info: 'fas fa-info-circle'
    };

    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="${icons[type] || icons.info}"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    toastContainer.appendChild(toast);

    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: duration
    });

    bsToast.show();

    // Remove toast element after hiding
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });

    // Update live region for screen readers
    const liveRegion = document.getElementById('live-region');
    if (liveRegion) {
        liveRegion.textContent = message;
    }
}

// Utility functions
const Utils = {
    // Debounce function
    debounce: function(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Throttle function
    throttle: function(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    // Format currency
    formatCurrency: function(amount, currency = 'BRL') {
        return new Intl.NumberFormat('pt-BR', {
            style: 'currency',
            currency: currency
        }).format(amount);
    },

    // Format date
    formatDate: function(date, format = 'dd/MM/yyyy') {
        return new Intl.DateTimeFormat('pt-BR').format(new Date(date));
    },

    // Get relative time
    getRelativeTime: function(date) {
        const rtf = new Intl.RelativeTimeFormat('pt-BR', { numeric: 'auto' });
        const now = new Date();
        const diff = new Date(date) - now;

        const seconds = Math.floor(diff / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (Math.abs(days) > 0) return rtf.format(days, 'day');
        if (Math.abs(hours) > 0) return rtf.format(hours, 'hour');
        if (Math.abs(minutes) > 0) return rtf.format(minutes, 'minute');
        return rtf.format(seconds, 'second');
    },

    // Copy to clipboard
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copiado para a área de transferência', 'success');
        }).catch(err => {
            console.error('Erro ao copiar:', err);
            showToast('Erro ao copiar para a área de transferência', 'error');
        });
    },

    // Download file
    downloadFile: function(url, filename) {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    },

    // Validate email
    validateEmail: function(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Generate random ID
    generateId: function() {
        return Math.random().toString(36).substr(2, 9);
    },

    // Escape HTML
    escapeHtml: function(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }
};

// Export utilities to global scope
window.Utils = Utils;
window.showToast = showToast;

// Save preferences on page unload
window.addEventListener('beforeunload', saveUserPreferences);

// Setup sidebar menu persistence
function setupSidebarPersistence() {
    // Get current page URL to determine which menu should be active
    const currentPath = window.location.pathname;

    // Define menu mapping for different pages
    const menuMapping = {
        // Protocols
        '/protocolos/ftp': 'protocolos',
        '/protocolos/scp': 'protocolos', 
        '/protocolos/cd': 'protocolos',
        '/protocolos/http': 'protocolos',
        '/protocolos/jasppion': 'protocolos',
        '/protocolos/s3': 'protocolos',
        '/protocolos/mq': 'protocolos',
        // Functionalities  
        '/funcionalidades/cmd': 'funcionalidades',
        '/funcionalidades/formato': 'funcionalidades',
        '/funcionalidades/headertrailer': 'funcionalidades',
        '/funcionalidades/jcl': 'funcionalidades',
        '/funcionalidades/mail': 'funcionalidades',
        '/funcionalidades/prm': 'funcionalidades',
        '/funcionalidades/traducao': 'funcionalidades',
        '/funcionalidades/ser': 'funcionalidades',
        // Notifications
        '/notificacoes/ftpusers': 'notificacoes',
        '/notificacoes/mailgroup': 'notificacoes',
        '/notificacoes/roscoe': 'notificacoes',
        // FAQ
        '/faq': 'faq'
    };

    // Setup submenu functionality
    setupSubmenuHandlers();
    
    // Mark active menu items
    markActiveMenuItems(currentPath, menuMapping);
}

// Setup submenu click handlers
function setupSubmenuHandlers() {
    document.querySelectorAll('.menu-link[data-submenu]').forEach(menuLink => {
        menuLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            const submenuId = this.getAttribute('data-submenu');
            const submenu = document.getElementById(`submenu-${submenuId}`);
            const arrow = this.querySelector('.submenu-arrow');
            
            if (submenu) {
                // Close all other submenus
                document.querySelectorAll('.submenu.expanded').forEach(otherSubmenu => {
                    if (otherSubmenu !== submenu) {
                        otherSubmenu.classList.remove('expanded');
                        const otherArrow = document.querySelector(`[data-submenu="${otherSubmenu.id.replace('submenu-', '')}"] .submenu-arrow`);
                        if (otherArrow) {
                            otherArrow.parentElement.classList.remove('expanded');
                        }
                    }
                });
                
                // Toggle current submenu
                submenu.classList.toggle('expanded');
                this.classList.toggle('expanded');
            }
        });
    });
}

// Mark active menu items based on current path
function markActiveMenuItems(currentPath, menuMapping) {
    // Remove all active classes first
    document.querySelectorAll('.menu-link.active, .submenu-link.active').forEach(link => {
        link.classList.remove('active');
    });
    
    // Find and mark active main menu links
    document.querySelectorAll('.menu-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href && href === currentPath) {
            link.classList.add('active');
        }
    });
    
    // Find and mark active submenu links and expand parent menu
    document.querySelectorAll('.submenu-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href && href === currentPath) {
            link.classList.add('active');
            
            // Expand parent submenu
            const submenu = link.closest('.submenu');
            if (submenu) {
                submenu.classList.add('expanded');
                const submenuId = submenu.id.replace('submenu-', '');
                const parentMenuLink = document.querySelector(`[data-submenu="${submenuId}"]`);
                if (parentMenuLink) {
                    parentMenuLink.classList.add('expanded');
                }
            }
        }
    });
    
    // Handle exact path matches for main categories
    for (const [path, menuCategory] of Object.entries(menuMapping)) {
        if (currentPath.startsWith(path)) {
            const submenu = document.getElementById(`submenu-${menuCategory}`);
            const parentMenuLink = document.querySelector(`[data-submenu="${menuCategory}"]`);
            
            if (submenu && parentMenuLink) {
                submenu.classList.add('expanded');
                parentMenuLink.classList.add('expanded');
            }
            break;
        }
    }
}

// Setup additional sidebar interactions
function setupSidebarInteractions() {
    // Handle escape key to close sidebar on mobile
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            const sidebar = document.querySelector('.sidebar');
            if (sidebar && sidebar.classList.contains('show')) {
                sidebar.classList.remove('show');
                document.removeEventListener('click', closeSidebarOnOutsideClick);
            }
        }
    });
    
    // Auto-close sidebar on mobile when navigating to a new page
    document.querySelectorAll('.submenu-link').forEach(link => {
        link.addEventListener('click', function() {
            const sidebar = document.querySelector('.sidebar');
            if (window.innerWidth <= 768 && sidebar && sidebar.classList.contains('show')) {
                setTimeout(() => {
                    sidebar.classList.remove('show');
                    document.removeEventListener('click', closeSidebarOnOutsideClick);
                }, 150); // Small delay to prevent conflicts
            }
        });
    });
    
    // Handle window resize to ensure proper behavior
    window.addEventListener('resize', function() {
        const sidebar = document.querySelector('.sidebar');
        if (window.innerWidth > 768 && sidebar) {
            sidebar.classList.remove('show');
            document.removeEventListener('click', closeSidebarOnOutsideClick);
        }
    });
}

// Setup image expansion functionality
function setupImageExpansion() {
    // Find all images that should be expandable (diagrams)
    const expandableImages = document.querySelectorAll('img.img-fluid.img-thumbnail, img[alt*="Diagrama"]');

    expandableImages.forEach(img => {
        // Add cursor pointer style
        img.style.cursor = 'pointer';
        img.title = 'Clique para ampliar';

        // Add click handler for expansion
        img.addEventListener('click', function(e) {
            e.preventDefault();
            expandImage(this);
        });
    });
}

// Function to expand image in modal
function expandImage(imgElement) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('imageExpansionModal');
    if (!modal) {
        modal = createImageExpansionModal();
    }

    // Set the image source in the modal
    const modalImg = modal.querySelector('#expandedImage');
    const modalTitle = modal.querySelector('.modal-title');

    modalImg.src = imgElement.src;
    modalImg.alt = imgElement.alt;
    modalTitle.textContent = imgElement.alt || 'Diagrama';

    // Show the modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}

// Create image expansion modal
function createImageExpansionModal() {
    const modalHTML = `
    <div class="modal fade" id="imageExpansionModal" tabindex="-1" aria-labelledby="imageExpansionModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-xl modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="imageExpansionModalLabel">Diagrama</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body text-center">
                    <img id="expandedImage" class="img-fluid" src="" alt="">
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Fechar</button>
                    <a id="downloadImage" class="btn btn-primary" href="" download target="_blank">
                        <i class="fas fa-download"></i> Download
                    </a>
                </div>
            </div>
        </div>
    </div>`;

    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    const modal = document.getElementById('imageExpansionModal');

    // Update download link when modal opens
    modal.addEventListener('show.bs.modal', function() {
        const expandedImg = modal.querySelector('#expandedImage');
        const downloadLink = modal.querySelector('#downloadImage');
        downloadLink.href = expandedImg.src;
    });

    return modal;
}

// Function to view profile in quick modal
function viewProfileQuick(profileId) {
    fetch(`/perfis/${profileId}/view`)
        .then(response => response.json())
        .then(data => {
            // Create modal content with profile data
            const modalContent = `
                <div class="row">
                    <div class="col-md-8">
                        <table class="table table-borderless">
                            <tr>
                                <td><strong>Nome:</strong></td>
                                <td>${data.nome}</td>
                            </tr>
                            <tr>
                                <td><strong>CAD:</strong></td>
                                <td>${data.cad || '-'}</td>
                            </tr>
                            <tr>
                                <td><strong>ASS:</strong></td>
                                <td>${data.ass || '-'}</td>
                            </tr>
                            <tr>
                                <td><strong>Criado em:</strong></td>
                                <td>${data.criado_em || '-'}</td>
                            </tr>
                            <tr>
                                <td><strong>Atualizado em:</strong></td>
                                <td>${data.atualizado_em || '-'}</td>
                            </tr>
                        </table>

                        ${data.comentario ? `
                        <div class="mb-3">
                            <h6>Comentário:</h6>
                            <p class="text-muted">${data.comentario}</p>
                        </div>` : ''}

                        <div class="row">
                            <div class="col-md-6">
                                <h6>Protocolos Habilitados:</h6>
                                ${data.protocolos.length > 0 ? 
                                    data.protocolos.map(p => `<span class="badge bg-info me-1">${p}</span>`).join('') :
                                    '<span class="text-muted">Nenhum protocolo habilitado</span>'
                                }
                            </div>
                            <div class="col-md-6">
                                <h6>Funcionalidades Habilitadas:</h6>
                                ${data.funcionalidades.length > 0 ? 
                                    data.funcionalidades.map(f => `<span class="badge bg-success me-1">${f}</span>`).join('') :
                                    '<span class="text-muted">Nenhuma funcionalidade habilitada</span>'
                                }
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        ${data.possui_diagrama ? `
                        <div class="text-center">
                            <h6>Diagrama:</h6>
                            <img src="${data.diagrama_url}" 
                                 class="img-fluid img-thumbnail" 
                                 style="max-height: 200px; cursor: pointer;"
                                 alt="Diagrama do Perfil"
                                 onclick="expandImage(this)">
                        </div>` : '<div class="text-center text-muted">Sem diagrama</div>'}
                    </div>
                </div>
            `;

            showModal(`Perfil: ${data.nome}`, modalContent);

            // Update the "Ver Perfil Completo" button link
            const fullProfileBtn = document.getElementById('viewFullProfileBtn');
            if (fullProfileBtn) {
                fullProfileBtn.href = `/perfis/${data.id}`;
            }
        })
        .catch(error => {
            console.error('Erro ao carregar dados do perfil:', error);
            showToast('Erro ao carregar dados do perfil', 'error');
        });
}

// Helper function to show modal with custom content
function showModal(title, content) {
    // Create modal if it doesn't exist
    let modal = document.getElementById('quickViewModal');
    if (!modal) {
        modal = createQuickViewModal();
    }

    // Set modal content
    const modalTitle = modal.querySelector('.modal-title');
    const modalBody = modal.querySelector('.modal-body');

    modalTitle.textContent = title;
    modalBody.innerHTML = content;

    // Show modal
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();
}

// Create quick view modal
function createQuickViewModal() {
    const modalHTML = `
    <div class="modal fade" id="quickViewModal" tabindex="-1" aria-labelledby="quickViewModalLabel" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="quickViewModalLabel">Visualização Rápida</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <!-- Content will be dynamically inserted here -->
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Fechar</button>
                    <a id="viewFullProfileBtn" href="#" class="btn btn-primary">Ver Perfil Completo</a>
                </div>
            </div>
        </div>
    </div>`;

    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', modalHTML);
    return document.getElementById('quickViewModal');
}

// Function to view PRM configuration in quick modal
function viewPRMQuick(prmId) {
    fetch(`/funcionalidades/prm/${prmId}/view`)
        .then(response => response.json())
        .then(data => {
            // Create modal content with PRM data
            const modalContent = `
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-borderless">
                            <tr>
                                <td><strong>Perfil:</strong></td>
                                <td>${data.perfil}</td>
                            </tr>
                            <tr>
                                <td><strong>ID:</strong></td>
                                <td>${data.id}</td>
                            </tr>
                            ${data.criado_em ? `
                            <tr>
                                <td><strong>Criado em:</strong></td>
                                <td>${data.criado_em}</td>
                            </tr>` : ''}
                            ${data.atualizado_em ? `
                            <tr>
                                <td><strong>Atualizado em:</strong></td>
                                <td>${data.atualizado_em}</td>
                            </tr>` : ''}
                        </table>
                    </div>
                    <div class="col-md-6">
                        <h6>Status das Flags:</h6>
                        <div class="row">
                            ${data.flags.map(flag => `
                            <div class="col-6 mb-2">
                                <span class="badge ${flag.ativo ? 'bg-success' : 'bg-secondary'} w-100">
                                    ${flag.nome}: ${flag.ativo ? 'Ativo' : 'Inativo'}
                                </span>
                            </div>
                            `).join('')}
                        </div>
                    </div>
                </div>

                <div class="mt-3">
                    <h6>Parâmetros:</h6>
                    <div class="table-responsive">
                        <table class="table table-sm table-striped">
                            <thead>
                                <tr>
                                    <th>Índice</th>
                                    <th>Valor (V)</th>
                                    <th>Nome (N)</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${data.parametros.map(param => `
                                <tr>
                                    <td><strong>V${param.indice}/N${param.indice}</strong></td>
                                    <td><code>${param.valor || '-'}</code></td>
                                    <td><code>${param.nome || '-'}</code></td>
                                    <td>
                                        <span class="badge ${param.valor || param.nome ? 'bg-success' : 'bg-secondary'}">
                                            ${param.valor || param.nome ? 'Configurado' : 'Vazio'}
                                        </span>
                                    </td>
                                </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            showModal(`Configuração PRM: ${data.perfil}`, modalContent);

            // Update the "Ver Perfil Completo" button link
            const fullProfileBtn = document.getElementById('viewFullProfileBtn');
            if (fullProfileBtn) {
                fullProfileBtn.href = `/funcionalidades/prm/${data.id}/visualizar`;
                fullProfileBtn.textContent = 'Ver Configuração Completa';
            }
        })
        .catch(error => {
            console.error('Erro ao carregar dados da configuração PRM:', error);
            showToast('Erro ao carregar dados da configuração PRM', 'error');
        });
}

// Handle menu persistence - keep parent menus expanded when submenus are clicked
function handleMenuPersistence() {
    const currentPath = window.location.pathname;

    // Check if we're on any Funcionalidades page
    const funcionalidadesPages = [
        '/funcionalidades/cmd',
        '/funcionalidades/formato', 
        '/funcionalidades/header-trailer',
        '/funcionalidades/jcl',
        '/funcionalidades/mail',
        '/funcionalidades/prm',
        '/funcionalidades/traducao',
        '/funcionalidades/ser'
    ];

    // Check if we're on any Notificações page  
    const notificacoesPages = [
        '/notificacoes/ftpusers',
        '/notificacoes/mailgroup', 
        '/notificacoes/roscoe'
    ];

    const isOnFuncionalidadesPage = funcionalidadesPages.some(page => currentPath.includes(page));
    const isOnNotificacoesPage = notificacoesPages.some(page => currentPath.includes(page));

    // Special case: Mail Groups page should expand Notificações menu 
    const isOnMailGroupPage = currentPath.includes('/notificacoes/mailgroup');

    if (isOnFuncionalidadesPage) {
        // Keep Funcionalidades menu expanded
        const funcionalidadesMenu = document.getElementById('funcionalidades');
        if (funcionalidadesMenu) {
            funcionalidadesMenu.classList.add('show');

            // Also mark the parent link as expanded
            const funcionalidadesToggle = document.querySelector('[href="#funcionalidades"]');
            if (funcionalidadesToggle) {
                funcionalidadesToggle.setAttribute('aria-expanded', 'true');
                funcionalidadesToggle.classList.remove('collapsed');
            }
        }
    }

    if (isOnNotificacoesPage || isOnMailGroupPage) {
        // Keep Notificações menu expanded
        const notificacoesMenu = document.getElementById('notificacoes');
        if (notificacoesMenu) {
            notificacoesMenu.classList.add('show');

            // Also mark the parent link as expanded
            const notificacoesToggle = document.querySelector('[href="#notificacoes"]');
            if (notificacoesToggle) {
                notificacoesToggle.setAttribute('aria-expanded', 'true');
                notificacoesToggle.classList.remove('collapsed');
            }
        }
    }
}

// Initialize menu persistence on page load
document.addEventListener('DOMContentLoaded', function() {
    handleMenuPersistence();
});

// Log application ready
console.log('Sistema de Transferência de Arquivos - Pronto!');
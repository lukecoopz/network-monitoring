// Network Monitoring Tool - Frontend JavaScript

let pieChart = null;
let currentDeviceMac = 'all';
let refreshInterval = null;
let allSitesData = []; // Store all sites data for filtering
let filteredSitesData = []; // Currently displayed sites
let searchTimeout = null; // Debounce search
let isSearching = false; // Track if we're in search mode

// Dracula theme colors for charts
const chartColors = [
    '#bd93f9', // purple
    '#ff79c6', // pink
    '#8be9fd', // cyan
    '#50fa7b', // green
    '#f1fa8c', // yellow
    '#ffb86c', // orange
    '#ff5555', // red
    '#6272a4', // comment
];

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeChart();
    loadDevices();
    loadStats();
    loadSites();
    
    // Set up event listeners
    document.getElementById('deviceFilter').addEventListener('change', handleDeviceFilter);
    document.getElementById('refreshBtn').addEventListener('click', refreshAll);
    document.getElementById('scanBtn').addEventListener('click', triggerNetworkScan);
    const forceSyncBtn = document.getElementById('forceSyncBtn');
    if (forceSyncBtn) {
        forceSyncBtn.addEventListener('click', forceSyncQueries);
    }
    document.getElementById('siteFilter').addEventListener('input', handleSiteFilter);
    document.getElementById('sortBy').addEventListener('change', handleSortChange);
    document.getElementById('globalSearch').addEventListener('input', handleGlobalSearch);
    document.getElementById('clearSearch').addEventListener('click', clearGlobalSearch);
    
    // Auto-refresh every 10 seconds
    refreshInterval = setInterval(() => {
        if (!isSearching) {
            loadStats();
            if (currentDeviceMac === 'all') {
                loadSites();
            } else {
                loadDeviceSites(currentDeviceMac);
            }
        }
    }, 10000);
});

function initializeChart() {
    const ctx = document.getElementById('pieChart').getContext('2d');
    pieChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: chartColors,
                borderColor: '#282a36',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#f8f8f2',
                        font: {
                            size: 12
                        },
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: '#21222c',
                    titleColor: '#bd93f9',
                    bodyColor: '#f8f8f2',
                    borderColor: '#44475a',
                    borderWidth: 1,
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

async function loadDevices() {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();
        
        const filterSelect = document.getElementById('deviceFilter');
        const devicesGrid = document.getElementById('devicesGrid');
        
        // Clear existing options except "All Devices"
        filterSelect.innerHTML = '<option value="all">All Devices</option>';
        
        // Add device options
        devices.forEach(device => {
            const option = document.createElement('option');
            option.value = device.mac;
            option.textContent = `${device.hostname || 'Unknown'} (${device.ip})`;
            filterSelect.appendChild(option);
        });
        
        // Display device cards
        if (devices.length === 0) {
            devicesGrid.innerHTML = '<div class="empty-state">No devices discovered yet. Scanning network...</div>';
        } else {
            devicesGrid.innerHTML = devices.map(device => `
                <div class="device-card ${device.mac === currentDeviceMac ? 'active' : ''}" 
                     onclick="selectDevice('${device.mac}')">
                    <h3>${device.hostname || 'Unknown Device'}</h3>
                    <div class="device-info"><strong>IP:</strong> ${device.ip}</div>
                    <div class="device-info"><strong>MAC:</strong> ${device.mac}</div>
                    <div class="device-info"><strong>Vendor:</strong> ${device.vendor || 'Unknown'}</div>
                    <div class="device-info"><strong>Last Seen:</strong> ${formatDate(device.last_seen)}</div>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading devices:', error);
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('deviceCount').textContent = stats.device_count || 0;
        document.getElementById('totalQueries').textContent = stats.total_queries || 0;
        document.getElementById('uniqueDomains').textContent = stats.unique_domains || 0;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadSites() {
    try {
        const response = await fetch('/api/sites/all');
        const sites = await response.json();
        
        allSitesData = sites;
        applyFiltersAndSort();
        updateChart(filteredSitesData, 'Top Sites Visited (All Devices)');
    } catch (error) {
        console.error('Error loading sites:', error);
    }
}

async function loadDeviceSites(deviceMac) {
    try {
        const response = await fetch(`/api/devices/${deviceMac}/sites`);
        const sites = await response.json();
        
        allSitesData = sites;
        applyFiltersAndSort();
        
        const device = await getDeviceInfo(deviceMac);
        const deviceName = device ? (device.hostname || device.ip) : 'Unknown';
        
        updateChart(filteredSitesData, `Top Sites Visited - ${deviceName}`);
    } catch (error) {
        console.error('Error loading device sites:', error);
    }
}

async function getDeviceInfo(deviceMac) {
    try {
        const response = await fetch('/api/devices');
        const devices = await response.json();
        return devices.find(d => d.mac === deviceMac);
    } catch (error) {
        return null;
    }
}

function updateChart(sites, title) {
    if (!pieChart) return;
    
    const labels = sites.map(site => site.domain);
    const data = sites.map(site => site.total_count);
    
    pieChart.data.labels = labels;
    pieChart.data.datasets[0].data = data;
    pieChart.update();
    
    document.getElementById('chartTitle').textContent = title;
}

function updateTable(sites) {
    const tbody = document.getElementById('sitesTableBody');
    
    if (sites.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No sites visited yet</td></tr>';
        return;
    }
    
    const total = sites.reduce((sum, site) => sum + site.total_count, 0);
    
    tbody.innerHTML = sites.map((site, index) => {
        const percentage = ((site.total_count / total) * 100).toFixed(1);
        const lastVisited = site.last_visited ? formatDate(site.last_visited) : 'Unknown';
        return `
            <tr>
                <td class="rank">#${index + 1}</td>
                <td class="domain">${site.domain}</td>
                <td class="visits">${site.total_count}</td>
                <td class="percentage">${percentage}%</td>
                <td class="timestamp">${lastVisited}</td>
            </tr>
        `;
    }).join('');
}

function applyFiltersAndSort() {
    const filterText = document.getElementById('siteFilter').value.toLowerCase();
    const sortBy = document.getElementById('sortBy').value;
    
    // Filter sites
    filteredSitesData = allSitesData.filter(site => 
        site.domain.toLowerCase().includes(filterText)
    );
    
    // Sort sites
    filteredSitesData.sort((a, b) => {
        switch(sortBy) {
            case 'domain':
                return a.domain.localeCompare(b.domain);
            case 'timestamp':
                const timeA = a.last_visited ? new Date(a.last_visited).getTime() : 0;
                const timeB = b.last_visited ? new Date(b.last_visited).getTime() : 0;
                return timeB - timeA; // Most recent first
            case 'visits':
            default:
                return b.total_count - a.total_count; // Most visits first
        }
    });
    
    // Update table
    updateTable(filteredSitesData);
    
    // Update chart with filtered data (limit to top 20 for chart)
    const chartData = filteredSitesData.slice(0, 20);
    const title = currentDeviceMac === 'all' 
        ? 'Top Sites Visited (All Devices)' 
        : `Top Sites Visited - ${document.getElementById('deviceFilter').selectedOptions[0]?.text || 'Device'}`;
    updateChart(chartData, title);
}

function handleSiteFilter() {
    applyFiltersAndSort();
}

function handleSortChange() {
    applyFiltersAndSort();
}

function handleDeviceFilter(event) {
    const deviceMac = event.target.value;
    currentDeviceMac = deviceMac;
    
    // Reset site filter when switching devices
    document.getElementById('siteFilter').value = '';
    document.getElementById('sortBy').value = 'visits';
    
    // Update device card selection
    document.querySelectorAll('.device-card').forEach(card => {
        card.classList.remove('active');
    });
    
    if (deviceMac === 'all') {
        loadSites();
    } else {
        loadDeviceSites(deviceMac);
        const selectedCard = document.querySelector(`[onclick="selectDevice('${deviceMac}')"]`);
        if (selectedCard) {
            selectedCard.classList.add('active');
        }
    }
}

function selectDevice(deviceMac) {
    currentDeviceMac = deviceMac;
    document.getElementById('deviceFilter').value = deviceMac;
    handleDeviceFilter({ target: document.getElementById('deviceFilter') });
}

function refreshAll() {
    loadDevices();
    loadStats();
    if (currentDeviceMac === 'all') {
        loadSites();
    } else {
        loadDeviceSites(currentDeviceMac);
    }
}

async function triggerNetworkScan() {
    try {
        const response = await fetch('/api/scan', { method: 'POST' });
        const result = await response.json();
        
        if (result.status === 'success') {
            // Wait a moment for scan to complete, then refresh
            setTimeout(() => {
                loadDevices();
                loadStats();
            }, 2000);
            
            // Show notification
            alert('Network scan triggered. Devices will update in a few seconds.');
        } else {
            alert('Scan failed: ' + result.message);
        }
    } catch (error) {
        console.error('Error triggering scan:', error);
        alert('Error triggering network scan');
    }
}

async function forceSyncQueries() {
    try {
        const btn = document.getElementById('forceSyncBtn');
        btn.disabled = true;
        btn.textContent = 'Syncing...';
        
        const response = await fetch('/api/debug/force-sync', { method: 'POST' });
        const result = await response.json();
        
        if (result.status === 'success') {
            // Wait a moment, then refresh
            setTimeout(() => {
                loadSites();
                loadStats();
                if (currentDeviceMac !== 'all') {
                    loadDeviceSites(currentDeviceMac);
                }
            }, 2000);
            
            alert(`Success: ${result.message}`);
        } else {
            alert(result.message || 'Sync completed');
        }
        
        btn.disabled = false;
        btn.textContent = 'Force Sync Queries';
    } catch (error) {
        console.error('Error forcing sync:', error);
        alert('Error forcing query sync');
        const btn = document.getElementById('forceSyncBtn');
        btn.disabled = false;
        btn.textContent = 'Force Sync Queries';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'Unknown';
    try {
        const date = new Date(dateString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        // Show relative time for recent visits
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        // For older dates, show formatted date
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    } catch (e) {
        return 'Unknown';
    }
}

async function handleGlobalSearch(event) {
    const query = event.target.value.trim();
    const clearBtn = document.getElementById('clearSearch');
    
    // Show/hide clear button
    if (query.length > 0) {
        clearBtn.style.display = 'block';
    } else {
        clearBtn.style.display = 'none';
        clearGlobalSearch();
        return;
    }
    
    // Debounce search
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
        if (query.length < 2) {
            clearGlobalSearch();
            return;
        }
        
        isSearching = true;
        await performSearch(query);
    }, 300);
}

async function performSearch(query) {
    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        const results = await response.json();
        
        displaySearchResults(results, query);
    } catch (error) {
        console.error('Error performing search:', error);
    }
}

function displaySearchResults(results, query) {
    const searchSection = document.getElementById('searchResults');
    const searchContent = document.getElementById('searchResultsContent');
    const devicesSection = document.getElementById('devicesSection');
    const contentGrid = document.querySelector('.content-grid');
    
    // Hide normal views
    devicesSection.style.display = 'none';
    contentGrid.style.display = 'none';
    
    // Show search results
    searchSection.style.display = 'block';
    
    let html = '';
    
    // Display matching devices
    if (results.devices && results.devices.length > 0) {
        html += '<div class="search-category"><h3>🔌 Matching Devices</h3>';
        html += '<div class="devices-grid">';
        html += results.devices.map(device => `
            <div class="device-card" onclick="selectDevice('${device.mac}')">
                <h3>${highlightMatch(device.hostname || 'Unknown Device', query)}</h3>
                <div class="device-info"><strong>IP:</strong> ${highlightMatch(device.ip, query)}</div>
                <div class="device-info"><strong>MAC:</strong> ${highlightMatch(device.mac, query)}</div>
                <div class="device-info"><strong>Vendor:</strong> ${highlightMatch(device.vendor || 'Unknown', query)}</div>
                <div class="device-info"><strong>Last Seen:</strong> ${formatDate(device.last_seen)}</div>
            </div>
        `).join('');
        html += '</div></div>';
    }
    
    // Display matching sites
    if (results.sites && results.sites.length > 0) {
        html += '<div class="search-category"><h3>🌐 Matching Sites</h3>';
        html += '<div class="table-container"><table><thead><tr><th>Domain</th><th>Visits</th><th>Last Visited</th></tr></thead><tbody>';
        html += results.sites.map(site => `
            <tr onclick="selectSite('${site.domain}')" style="cursor: pointer;">
                <td class="domain">${highlightMatch(site.domain, query)}</td>
                <td class="visits">${site.total_count}</td>
                <td class="timestamp">${formatDate(site.last_visited)}</td>
            </tr>
        `).join('');
        html += '</tbody></table></div></div>';
    }
    
    // No results
    if ((!results.devices || results.devices.length === 0) && 
        (!results.sites || results.sites.length === 0)) {
        html = '<div class="empty-state">No results found. Try a different search term.</div>';
    }
    
    searchContent.innerHTML = html;
}

function highlightMatch(text, query) {
    if (!query || !text) return text;
    const regex = new RegExp(`(${query})`, 'gi');
    return text.toString().replace(regex, '<mark>$1</mark>');
}

function clearGlobalSearch() {
    const searchInput = document.getElementById('globalSearch');
    const clearBtn = document.getElementById('clearSearch');
    const searchSection = document.getElementById('searchResults');
    const devicesSection = document.getElementById('devicesSection');
    const contentGrid = document.querySelector('.content-grid');
    
    searchInput.value = '';
    clearBtn.style.display = 'none';
    searchSection.style.display = 'none';
    devicesSection.style.display = 'block';
    contentGrid.style.display = 'grid';
    
    isSearching = false;
    
    // Reload normal views
    if (currentDeviceMac === 'all') {
        loadSites();
    } else {
        loadDeviceSites(currentDeviceMac);
    }
    loadDevices();
}

function selectSite(domain) {
    // Filter sites table to show this domain
    document.getElementById('siteFilter').value = domain;
    document.getElementById('deviceFilter').value = 'all';
    currentDeviceMac = 'all';
    clearGlobalSearch();
    handleSiteFilter();
}

// Logs functionality
let logsAutoRefresh = null;
let logsExpanded = false;

function toggleLogs() {
    const logsContent = document.getElementById('logsContent');
    const logsToggle = document.getElementById('logsToggle');
    
    logsExpanded = !logsExpanded;
    
    if (logsExpanded) {
        logsContent.style.display = 'block';
        logsToggle.textContent = '▲';
        loadLogs();
        startLogsAutoRefresh();
    } else {
        logsContent.style.display = 'none';
        logsToggle.textContent = '▼';
        stopLogsAutoRefresh();
    }
}

async function loadLogs() {
    try {
        const response = await fetch('/api/logs');
        const data = await response.json();
        
        const logsDisplay = document.getElementById('logsDisplay');
        
        if (data.status === 'success' || data.status === 'info') {
            logsDisplay.textContent = data.logs || 'No logs available';
            // Auto-scroll to bottom
            logsDisplay.scrollTop = logsDisplay.scrollHeight;
        } else {
            logsDisplay.textContent = `Error: ${data.logs || 'Failed to load logs'}`;
        }
    } catch (error) {
        console.error('Error loading logs:', error);
        document.getElementById('logsDisplay').textContent = `Error loading logs: ${error.message}`;
    }
}

function startLogsAutoRefresh() {
    const autoRefreshCheckbox = document.getElementById('autoRefreshLogs');
    
    if (autoRefreshCheckbox.checked && logsExpanded) {
        logsAutoRefresh = setInterval(() => {
            if (logsExpanded) {
                loadLogs();
            }
        }, 5000); // Refresh every 5 seconds
    }
}

function stopLogsAutoRefresh() {
    if (logsAutoRefresh) {
        clearInterval(logsAutoRefresh);
        logsAutoRefresh = null;
    }
}

// Set up logs event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Add logs event listeners after initial setup
    setTimeout(() => {
        const refreshLogsBtn = document.getElementById('refreshLogsBtn');
        const clearLogsBtn = document.getElementById('clearLogsBtn');
        const autoRefreshCheckbox = document.getElementById('autoRefreshLogs');
        
        if (refreshLogsBtn) {
            refreshLogsBtn.addEventListener('click', loadLogs);
        }
        
        if (clearLogsBtn) {
            clearLogsBtn.addEventListener('click', () => {
                document.getElementById('logsDisplay').textContent = 'Logs cleared.\n';
            });
        }
        
        if (autoRefreshCheckbox) {
            autoRefreshCheckbox.addEventListener('change', () => {
                if (autoRefreshCheckbox.checked && logsExpanded) {
                    startLogsAutoRefresh();
                } else {
                    stopLogsAutoRefresh();
                }
            });
        }
    }, 100);
});


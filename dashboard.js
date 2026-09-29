document.addEventListener('DOMContentLoaded', () => {
    // Single Socket.IO Connection to current origin (http://127.0.0.1:5000)
    const socket = io(window.location.origin, {
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000
    });

    // DOM Elements
    const wsStatusBadge = document.getElementById('ws-status-badge');
    const captureStatusBadge = document.getElementById('capture-status-badge');
    const packetsTbody = document.getElementById('packets-tbody');
    const countTotal = document.getElementById('count-total');
    const countTcp = document.getElementById('count-tcp');
    const countUdp = document.getElementById('count-udp');
    const countIcmp = document.getElementById('count-icmp');
    const ratioTcp = document.getElementById('ratio-tcp');
    const ratioUdp = document.getElementById('ratio-udp');
    const ratioIcmp = document.getElementById('ratio-icmp');
    const valPps = document.getElementById('val-pps');
    const ifaceSelect = document.getElementById('iface-select');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const btnClear = document.getElementById('btn-clear');
    const packetSearch = document.getElementById('packet-search');
    const protoBtns = document.querySelectorAll('.proto-btn');
    const alertsFeed = document.getElementById('alerts-feed');
    const alertCounter = document.getElementById('alert-counter');

    // State variables
    let packetsList = [];
    let currentFilterProto = 'ALL';
    let currentSearchTerm = '';
    let alertCount = 0;
    let ppsHistory = Array(15).fill(0);
    let ppsLabels = Array(15).fill('');
    let bytesHistory = Array(15).fill(0);

    // Socket Event Listeners
    socket.on('connect', () => {
        console.log('[SOCKET] Client connected');
        if (wsStatusBadge) {
            wsStatusBadge.className = 'status-val status-green';
            wsStatusBadge.innerHTML = '<i class="fa-solid fa-circle"></i> WEBSOCKET CONNECTED';
        }
    });

    socket.on('disconnect', () => {
        console.log('[SOCKET] Client disconnected');
        if (wsStatusBadge) {
            wsStatusBadge.className = 'status-val status-red';
            wsStatusBadge.innerHTML = '<i class="fa-solid fa-circle"></i> WEBSOCKET DISCONNECTED';
        }
    });

    socket.on('init_state', (data) => {
        if (data.interfaces && ifaceSelect) {
            ifaceSelect.innerHTML = '';
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                opt.value = iface;
                opt.textContent = iface;
                if (iface === data.selected_interface) opt.selected = true;
                ifaceSelect.appendChild(opt);
            });
        }
        if (data.stats) updateStatsDisplay(data.stats);
        if (data.packets && data.packets.length > 0) {
            packetsList = data.packets;
            renderPacketsTable();
        }
    });

    // Single required packet event listener
    socket.on('packet_update', (packet) => {
        packetsList.unshift(packet);
        if (packetsList.length > 500) packetsList.pop();

        appendPacketRow(packet);
        triggerNetworkTopologyParticle(packet);
    });

    socket.on('stats_update', (stats) => {
        updateStatsDisplay(stats);
    });

    socket.on('status_change', (stats) => {
        updateStatsDisplay(stats);
    });

    socket.on('security_alert', (alert) => {
        addSecurityAlert(alert);
    });

    socket.on('clear_packets', () => {
        packetsList = [];
        if (packetsTbody) {
            packetsTbody.innerHTML = `
                <tr id="empty-row">
                    <td colspan="8" class="text-center empty-cell">
                        <i class="fa-solid fa-info-circle"></i> Packet history cleared.
                    </td>
                </tr>`;
        }
    });

    // UI Buttons Controls
    if (btnStart) {
        btnStart.addEventListener('click', () => {
            const iface = ifaceSelect ? ifaceSelect.value : 'any';
            socket.emit('start_capture', { interface: iface });
        });
    }

    if (btnStop) {
        btnStop.addEventListener('click', () => {
            socket.emit('stop_capture');
        });
    }

    if (btnClear) {
        btnClear.addEventListener('click', () => {
            socket.emit('clear_packets');
        });
    }

    if (ifaceSelect) {
        ifaceSelect.addEventListener('change', () => {
            socket.emit('change_interface', { interface: ifaceSelect.value });
        });
    }

    if (packetSearch) {
        packetSearch.addEventListener('input', (e) => {
            currentSearchTerm = e.target.value.toLowerCase().trim();
            renderPacketsTable();
        });
    }

    protoBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            protoBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            currentFilterProto = btn.getAttribute('data-proto') || 'ALL';
            renderPacketsTable();
        });
    });

    // Stats and Table Rendering
    function updateStatsDisplay(stats) {
        if (!stats) return;

        if (countTotal) countTotal.textContent = stats.total.toLocaleString();
        if (countTcp) countTcp.textContent = stats.tcp.toLocaleString();
        if (countUdp) countUdp.textContent = stats.udp.toLocaleString();
        if (countIcmp) countIcmp.textContent = stats.icmp.toLocaleString();
        if (valPps) valPps.textContent = stats.pps || 0;

        const total = stats.total || 1;
        if (ratioTcp) ratioTcp.textContent = `${Math.round((stats.tcp / total) * 100)}%`;
        if (ratioUdp) ratioUdp.textContent = `${Math.round((stats.udp / total) * 100)}%`;
        if (ratioIcmp) ratioIcmp.textContent = `${Math.round((stats.icmp / total) * 100)}%`;

        if (captureStatusBadge) {
            if (stats.status === 'RUNNING') {
                captureStatusBadge.className = 'status-val status-green';
                captureStatusBadge.innerHTML = `<i class="fa-solid fa-circle"></i> RUNNING (${stats.interface})`;
            } else {
                captureStatusBadge.className = 'status-val status-amber';
                captureStatusBadge.innerHTML = '<i class="fa-solid fa-circle"></i> STOPPED';
            }
        }

        updateCharts(stats);
    }

    function appendPacketRow(packet) {
        const rowEmpty = document.getElementById('empty-row');
        if (rowEmpty) rowEmpty.remove();

        if (!matchesFilter(packet)) return;

        const tr = document.createElement('tr');
        tr.className = 'packet-row new-row';

        const protoLower = (packet.protocol || 'OTHER').toLowerCase();
        
        tr.innerHTML = `
            <td><span class="mono-time">${packet.timestamp || '-'}</span></td>
            <td><span class="mono-ip ip-src">${packet.source_ip || '-'}</span></td>
            <td><span class="mono-ip ip-dst">${packet.destination_ip || '-'}</span></td>
            <td><span class="badge badge-proto proto-${protoLower}">${packet.protocol || 'OTHER'}</span></td>
            <td><span class="mono-port">${packet.source_port || '-'}</span></td>
            <td><span class="mono-port">${packet.destination_port || '-'}</span></td>
            <td><span class="mono-size">${packet.payload_size || 0} B</span></td>
            <td><span class="status-pill status-captured">CAPTURED</span></td>
        `;

        if (packetsTbody) {
            packetsTbody.insertBefore(tr, packetsTbody.firstChild);
            while (packetsTbody.children.length > 200) {
                packetsTbody.removeChild(packetsTbody.lastChild);
            }
        }
    }

    function renderPacketsTable() {
        if (!packetsTbody) return;
        packetsTbody.innerHTML = '';

        const filtered = packetsList.filter(p => matchesFilter(p));

        if (filtered.length === 0) {
            packetsTbody.innerHTML = `
                <tr id="empty-row">
                    <td colspan="8" class="text-center empty-cell">
                        <i class="fa-solid fa-filter"></i> No packets matching filter/search.
                    </td>
                </tr>`;
            return;
        }

        filtered.slice(0, 200).forEach(packet => {
            const tr = document.createElement('tr');
            tr.className = 'packet-row';
            const protoLower = (packet.protocol || 'OTHER').toLowerCase();

            tr.innerHTML = `
                <td><span class="mono-time">${packet.timestamp || '-'}</span></td>
                <td><span class="mono-ip ip-src">${packet.source_ip || '-'}</span></td>
                <td><span class="mono-ip ip-dst">${packet.destination_ip || '-'}</span></td>
                <td><span class="badge badge-proto proto-${protoLower}">${packet.protocol || 'OTHER'}</span></td>
                <td><span class="mono-port">${packet.source_port || '-'}</span></td>
                <td><span class="mono-port">${packet.destination_port || '-'}</span></td>
                <td><span class="mono-size">${packet.payload_size || 0} B</span></td>
                <td><span class="status-pill status-captured">CAPTURED</span></td>
            `;
            packetsTbody.appendChild(tr);
        });
    }

    function matchesFilter(packet) {
        if (!packet) return false;
        
        if (currentFilterProto !== 'ALL') {
            const pProto = (packet.protocol || '').toUpperCase();
            if (currentFilterProto === 'OTHER') {
                if (['TCP', 'UDP', 'ICMP', 'DNS'].includes(pProto)) return false;
            } else if (pProto !== currentFilterProto) {
                return false;
            }
        }

        if (currentSearchTerm) {
            const src = (packet.source_ip || '').toLowerCase();
            const dst = (packet.destination_ip || '').toLowerCase();
            const srcP = String(packet.source_port || '');
            const dstP = String(packet.destination_port || '');
            const proto = (packet.protocol || '').toLowerCase();

            return src.includes(currentSearchTerm) ||
                   dst.includes(currentSearchTerm) ||
                   srcP.includes(currentSearchTerm) ||
                   dstP.includes(currentSearchTerm) ||
                   proto.includes(currentSearchTerm);
        }

        return true;
    }

    function addSecurityAlert(alert) {
        if (!alertsFeed) return;
        alertCount++;
        if (alertCounter) alertCounter.textContent = `${alertCount} EVENTS`;

        const alertItem = document.createElement('div');
        const isHigh = alert.level === 'HIGH';
        alertItem.className = `alert-item ${isHigh ? 'alert-danger' : 'alert-warning'}`;

        alertItem.innerHTML = `
            <div class="alert-icon"><i class="fa-solid ${isHigh ? 'fa-triangle-exclamation' : 'fa-circle-exclamation'}"></i></div>
            <div class="alert-content">
                <div class="alert-title">${alert.title}</div>
                <div class="alert-desc">${alert.details}</div>
                <div class="alert-time">${alert.timestamp || new Date().toLocaleTimeString()}</div>
            </div>
        `;

        alertsFeed.insertBefore(alertItem, alertsFeed.firstChild);
    }

    // Chart.js Graphs
    let chartProto = null;
    let chartPps = null;
    let chartTraffic = null;

    function initCharts() {
        const ctxProto = document.getElementById('chart-protocol');
        const ctxPps = document.getElementById('chart-pps');
        const ctxTraffic = document.getElementById('chart-traffic');

        if (ctxProto && typeof Chart !== 'undefined') {
            chartProto = new Chart(ctxProto, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#06b6d4', '#10b981', '#f59e0b', '#8b5cf6'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
                }
            });
        }

        if (ctxPps && typeof Chart !== 'undefined') {
            chartPps = new Chart(ctxPps, {
                type: 'line',
                data: {
                    labels: ppsLabels,
                    datasets: [{
                        label: 'PPS',
                        data: ppsHistory,
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { ticks: { color: '#64748b' }, grid: { display: false } },
                        y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        if (ctxTraffic && typeof Chart !== 'undefined') {
            chartTraffic = new Chart(ctxTraffic, {
                type: 'bar',
                data: {
                    labels: ppsLabels,
                    datasets: [{
                        label: 'Bytes',
                        data: bytesHistory,
                        backgroundColor: '#10b981',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { ticks: { color: '#64748b' }, grid: { display: false } },
                        y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }
    }

    function updateCharts(stats) {
        if (chartProto) {
            chartProto.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp, stats.other];
            chartProto.update();
        }

        const nowStr = new Date().toLocaleTimeString();
        ppsLabels.push(nowStr);
        ppsLabels.shift();

        ppsHistory.push(stats.pps || 0);
        ppsHistory.shift();

        bytesHistory.push(stats.total_bytes || 0);
        bytesHistory.shift();

        if (chartPps) {
            chartPps.data.labels = ppsLabels;
            chartPps.data.datasets[0].data = ppsHistory;
            chartPps.update();
        }

        if (chartTraffic) {
            chartTraffic.data.labels = ppsLabels;
            chartTraffic.data.datasets[0].data = bytesHistory;
            chartTraffic.update();
        }
    }

    // High-Tech Animated Network Topology Radar Map
    const canvas = document.getElementById('network-canvas');
    let ctx = canvas ? canvas.getContext('2d') : null;
    let particles = [];
    let nodePulseRadius = { src: 22, dst: 22 };

    function setupCanvas() {
        if (!canvas) return;
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
    }

    window.addEventListener('resize', setupCanvas);
    setupCanvas();

    function triggerNetworkTopologyParticle(packet) {
        if (!canvas || !ctx) return;

        const startX = 120;
        const startY = canvas.height / 2;
        const endX = canvas.width - 120;
        const endY = canvas.height / 2;

        const colorMap = { 'TCP': '#06b6d4', 'UDP': '#10b981', 'ICMP': '#f59e0b' };
        const color = colorMap[packet.protocol] || '#8b5cf6';

        particles.push({
            startX: startX,
            startY: startY,
            endX: endX,
            endY: endY,
            cpX: canvas.width / 2,
            cpY: canvas.height / 2 + (Math.random() * 120 - 60),
            progress: 0,
            speed: 0.015 + Math.random() * 0.02,
            color: color,
            size: 5 + Math.random() * 3
        });

        // Trigger Node Pulse
        nodePulseRadius.src = 35;
        nodePulseRadius.dst = 35;
    }

    function animateCanvas() {
        if (!canvas || !ctx) return;

        ctx.clearRect(0, 0, canvas.width, canvas.height);

        const leftX = 120, rightX = canvas.width - 120, centerY = canvas.height / 2;

        // Draw Curved Link Lines
        ctx.beginPath();
        ctx.moveTo(leftX, centerY);
        ctx.quadraticCurveTo(canvas.width / 2, centerY - 40, rightX, centerY);
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.2)';
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 6]);
        ctx.stroke();

        ctx.beginPath();
        ctx.moveTo(leftX, centerY);
        ctx.quadraticCurveTo(canvas.width / 2, centerY + 40, rightX, centerY);
        ctx.strokeStyle = 'rgba(16, 185, 129, 0.2)';
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.setLineDash([]);

        // Node Pulses
        if (nodePulseRadius.src > 22) nodePulseRadius.src -= 0.5;
        if (nodePulseRadius.dst > 22) nodePulseRadius.dst -= 0.5;

        // Source Node (Host / Machine)
        ctx.beginPath();
        ctx.arc(leftX, centerY, nodePulseRadius.src, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(leftX, centerY, 16, 0, Math.PI * 2);
        ctx.fillStyle = '#06b6d4';
        ctx.shadowColor = '#06b6d4';
        ctx.shadowBlur = 20;
        ctx.fill();

        ctx.fillStyle = '#f8fafc';
        ctx.font = '12px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText('SOURCE HOST', leftX, centerY + 35);

        // Destination Node (Gateway / Internet)
        ctx.beginPath();
        ctx.arc(rightX, centerY, nodePulseRadius.dst, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(16, 185, 129, 0.15)';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(rightX, centerY, 16, 0, Math.PI * 2);
        ctx.fillStyle = '#10b981';
        ctx.shadowColor = '#10b981';
        ctx.shadowBlur = 20;
        ctx.fill();
        ctx.shadowBlur = 0;

        ctx.fillStyle = '#f8fafc';
        ctx.fillText('DESTINATION', rightX, centerY + 35);

        // Animate Laser Curved Particles
        for (let i = particles.length - 1; i >= 0; i--) {
            const p = particles[i];
            p.progress += p.speed;

            const t = p.progress;
            const curX = (1 - t) * (1 - t) * p.startX + 2 * (1 - t) * t * p.cpX + t * t * p.endX;
            const curY = (1 - t) * (1 - t) * p.startY + 2 * (1 - t) * t * p.cpY + t * t * p.endY;

            ctx.beginPath();
            ctx.arc(curX, curY, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.color;
            ctx.shadowColor = p.color;
            ctx.shadowBlur = 12;
            ctx.fill();
            ctx.shadowBlur = 0;

            if (p.progress >= 1) {
                particles.splice(i, 1);
            }
        }

        requestAnimationFrame(animateCanvas);
    }

    initCharts();
    animateCanvas();
});

/**
 * AEGIS-SOC Cyber Kill-Chain Force-Directed Graph Engine
 * Features: MITRE 5-Stage Left-to-Right Flow, Directed Laser Pulses,
 * Forensic Hover HUD, and High-DPI Canvas Rendering.
 */
class AttackGraphVisualizer {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.nodes = [];
        this.links = [];
        this.dragNode = null;
        this.hoverNode = null;
        this.selectedNode = null;
        this.animFrameId = null;
        this.particles = [];

        this.initCanvasSize();
        window.addEventListener('resize', () => this.initCanvasSize());
        this.setupInteractions();
        this.startSimulation();
    }

    initCanvasSize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = rect.width;
        this.height = rect.height;
        this.canvas.width = this.width * window.devicePixelRatio;
        this.canvas.height = this.height * window.devicePixelRatio;
        this.ctx.setTransform(1, 0, 0, 1, 0, 0);
        this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

        if (this.nodes && this.nodes.length > 0) {
            const stageXPositions = {
                1: this.width * 0.08,
                2: this.width * 0.20,
                3: this.width * 0.44,
                4: this.width * 0.69,
                5: this.width * 0.91
            };
            this.nodes.forEach(n => {
                n.targetX = stageXPositions[n.stage || 3] || this.width * 0.5;
            });
        }
    }

    setData(graphData) {
        if (!graphData || !graphData.nodes) return;
        
        const existingMap = new Map(this.nodes.map(n => [n.id, n]));
        const stageXPositions = {
            1: this.width * 0.08,
            2: this.width * 0.20,
            3: this.width * 0.44,
            4: this.width * 0.69,
            5: this.width * 0.91
        };

        this.nodes = graphData.nodes.map((n, idx) => {
            const targetX = stageXPositions[n.stage || 3] || this.width * 0.5;
            const targetY = 70 + ((idx % 4) + 1) * ((this.height - 120) / 5);

            if (existingMap.has(n.id)) {
                const ex = existingMap.get(n.id);
                return { ...n, x: ex.x, y: ex.y, vx: ex.vx, vy: ex.vy, targetX, targetY, radius: this.getNodeRadius(n.type) };
            }
            return {
                ...n,
                x: targetX + (Math.random() - 0.5) * 40,
                y: targetY + (Math.random() - 0.5) * 40,
                vx: 0,
                vy: 0,
                targetX,
                targetY,
                radius: this.getNodeRadius(n.type)
            };
        });

        this.links = graphData.links || [];

        // Initialize animated flow particles
        this.particles = [];
        for (let i = 0; i < this.links.length * 2; i++) {
            this.particles.push({
                linkIdx: i % this.links.length,
                progress: Math.random(),
                speed: 0.006 + Math.random() * 0.008
            });
        }
    }

    getNodeRadius(type) {
        switch (type) {
            case 'soc': return 22;
            case 'host': return 20;
            case 'process': return 16;
            case 'action': return 15;
            case 'c2': return 18;
            default: return 14;
        }
    }

    startSimulation() {
        const step = () => {
            this.updatePhysics();
            this.draw();
            this.animFrameId = requestAnimationFrame(step);
        };
        step();
    }

    updatePhysics() {
        const damping = 0.82;

        // Stage X-attraction + Repulsion
        for (let i = 0; i < this.nodes.length; i++) {
            const n1 = this.nodes[i];
            
            // Soft pull toward assigned Kill-Chain Stage Column (X)
            if (n1.targetX) {
                n1.vx += (n1.targetX - n1.x) * 0.035;
            }

            // Gentle vertical centering
            if (n1.targetY) {
                n1.vy += (n1.targetY - n1.y) * 0.015;
            }

            // Node-to-node repulsion
            for (let j = i + 1; j < this.nodes.length; j++) {
                const n2 = this.nodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const dist = Math.sqrt(dx * dx + dy * dy) || 1;
                const minDist = n1.radius + n2.radius + 35;
                if (dist < minDist) {
                    const force = (minDist - dist) / dist * 0.12;
                    const fx = dx * force;
                    const fy = dy * force;
                    n1.vx -= fx;
                    n1.vy -= fy;
                    n2.vx += fx;
                    n2.vy += fy;
                }
            }
        }

        // Apply velocity & boundary clamping
        for (const n of this.nodes) {
            if (n === this.dragNode) continue;
            n.vx *= damping;
            n.vy *= damping;
            n.x += n.vx;
            n.y += n.vy;

            n.x = Math.max(n.radius + 15, Math.min(this.width - n.radius - 15, n.x));
            n.y = Math.max(n.radius + 50, Math.min(this.height - n.radius - 35, n.y));
        }

        // Advance flow particles
        for (const p of this.particles) {
            p.progress += p.speed;
            if (p.progress >= 1.0) p.progress = 0;
        }
    }

    draw() {
        this.ctx.clearRect(0, 0, this.width, this.height);

        // 1. Draw Kill-Chain Stage Column Headers & Guidelines
        this.drawStageColumns();

        const nodeMap = new Map(this.nodes.map(n => [n.id, n]));

        // 2. Draw Links & Animated Laser Pulses
        for (let i = 0; i < this.links.length; i++) {
            const link = this.links[i];
            const s = nodeMap.get(link.source);
            const t = nodeMap.get(link.target);
            if (s && t) {
                const isCrit = t.severity === 'CRITICAL' || s.severity === 'CRITICAL';
                
                // Link line
                this.ctx.beginPath();
                this.ctx.moveTo(s.x, s.y);
                this.ctx.lineTo(t.x, t.y);
                this.ctx.strokeStyle = isCrit ? 'rgba(239, 68, 68, 0.45)' : 'rgba(0, 242, 254, 0.22)';
                this.ctx.lineWidth = isCrit ? 2.0 : 1.5;
                this.ctx.setLineDash(isCrit ? [6, 4] : []);
                this.ctx.stroke();
                this.ctx.setLineDash([]);

                // Edge label
                if (link.label) {
                    const midX = (s.x + t.x) / 2;
                    const midY = (s.y + t.y) / 2;
                    this.ctx.fillStyle = 'rgba(148, 163, 184, 0.75)';
                    this.ctx.font = '9px JetBrains Mono';
                    this.ctx.textAlign = 'center';
                    this.ctx.fillText(link.label, midX, midY - 6);
                }
            }
        }

        // 3. Draw Traveling Laser Energy Particles
        for (const p of this.particles) {
            const link = this.links[p.linkIdx];
            if (!link) continue;
            const s = nodeMap.get(link.source);
            const t = nodeMap.get(link.target);
            if (s && t) {
                const px = s.x + (t.x - s.x) * p.progress;
                const py = s.y + (t.y - s.y) * p.progress;
                const isCrit = t.severity === 'CRITICAL';

                this.ctx.beginPath();
                this.ctx.arc(px, py, isCrit ? 3.5 : 2.5, 0, Math.PI * 2);
                this.ctx.fillStyle = isCrit ? '#ef4444' : '#00f2fe';
                this.ctx.shadowColor = isCrit ? 'rgba(239, 68, 68, 0.9)' : 'rgba(0, 242, 254, 0.9)';
                this.ctx.shadowBlur = 8;
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
            }
        }

        // 4. Draw Nodes
        const now = Date.now() / 1000;
        for (const n of this.nodes) {
            this.drawNode(n, now);
        }

        // 5. Draw Cyber HUD Tooltip for Hovered/Selected Node
        if (this.hoverNode || this.selectedNode) {
            this.drawNodeHUD(this.hoverNode || this.selectedNode);
        }
    }

    drawStageColumns() {
        const stages = [
            { num: 1, name: "STAGE 1: DEFENSE CORE", x: this.width * 0.08 },
            { num: 2, name: "STAGE 2: ENDPOINT HOST", x: this.width * 0.20 },
            { num: 3, name: "STAGE 3: PROCESS LINEAGE", x: this.width * 0.44 },
            { num: 4, name: "STAGE 4: MALICIOUS ACTION", x: this.width * 0.69 },
            { num: 5, name: "STAGE 5: ADVERSARY C2", x: this.width * 0.91 }
        ];

        this.ctx.save();
        for (const s of stages) {
            // Subtle column divider line
            this.ctx.beginPath();
            this.ctx.moveTo(s.x, 30);
            this.ctx.lineTo(s.x, this.height - 15);
            this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.035)';
            this.ctx.lineWidth = 1;
            this.ctx.setLineDash([4, 6]);
            this.ctx.stroke();

            // Stage header label
            this.ctx.fillStyle = 'rgba(0, 242, 254, 0.55)';
            this.ctx.font = '10px Chakra Petch';
            this.ctx.textAlign = 'center';
            this.ctx.fillText(s.name, s.x, 22);
        }
        this.ctx.restore();
    }

    drawNode(n, now) {
        this.ctx.save();

        let color = '#00f2fe';
        let glow = 'rgba(0, 242, 254, 0.4)';
        let glyph = '⚙️';

        if (n.type === 'soc') {
            color = '#00f2fe';
            glow = 'rgba(0, 242, 254, 0.6)';
            glyph = '🛡️';
        } else if (n.type === 'host') {
            color = '#38bdf8';
            glow = 'rgba(56, 189, 248, 0.5)';
            glyph = '💻';
        } else if (n.type === 'process') {
            color = n.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b';
            glow = n.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.7)' : 'rgba(245, 158, 11, 0.5)';
            glyph = '⚡';
        } else if (n.type === 'action') {
            color = n.severity === 'CRITICAL' ? '#ef4444' : '#a855f7';
            glow = 'rgba(168, 85, 247, 0.5)';
            glyph = '🔑';
        } else if (n.type === 'c2') {
            color = '#ef4444';
            glow = 'rgba(239, 68, 68, 0.8)';
            glyph = '💀';
        }

        // Critical Pulsating Outer Ring
        if (n.severity === 'CRITICAL') {
            const pulse = 4 + Math.sin(now * 5) * 5;
            this.ctx.beginPath();
            this.ctx.arc(n.x, n.y, n.radius + pulse, 0, Math.PI * 2);
            this.ctx.fillStyle = 'rgba(239, 68, 68, 0.18)';
            this.ctx.fill();
        }

        // Outer Glow Ring
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        this.ctx.fillStyle = '#080d18';
        this.ctx.fill();
        this.ctx.lineWidth = 2;
        this.ctx.strokeStyle = color;
        this.ctx.shadowColor = glow;
        this.ctx.shadowBlur = 14;
        this.ctx.stroke();
        this.ctx.shadowBlur = 0;

        // Inner Core Emoji Icon
        this.ctx.font = `${Math.floor(n.radius * 0.95)}px sans-serif`;
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'middle';
        this.ctx.fillText(glyph, n.x, n.y);

        // Stage Tag & Name Below
        this.ctx.fillStyle = '#f8fafc';
        this.ctx.font = '10px JetBrains Mono';
        this.ctx.textBaseline = 'top';
        this.ctx.fillText(n.label, n.x, n.y + n.radius + 6);

        this.ctx.restore();
    }

    drawNodeHUD(n) {
        const hudW = 240;
        const hudH = 110;
        let hudX = n.x + n.radius + 12;
        let hudY = n.y - 20;

        // Clamp inside canvas bounds
        if (hudX + hudW > this.width - 15) hudX = n.x - hudW - n.radius - 12;
        if (hudY + hudH > this.height - 15) hudY = this.height - hudH - 15;
        if (hudY < 15) hudY = 15;

        this.ctx.save();

        // Background Glass Box
        this.ctx.fillStyle = 'rgba(10, 15, 26, 0.92)';
        this.ctx.strokeStyle = n.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.6)' : 'rgba(0, 242, 254, 0.5)';
        this.ctx.lineWidth = 1.5;
        this.ctx.shadowColor = n.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(0, 242, 254, 0.3)';
        this.ctx.shadowBlur = 16;
        
        // Rounded rect
        this.ctx.beginPath();
        this.ctx.roundRect(hudX, hudY, hudW, hudH, 8);
        this.ctx.fill();
        this.ctx.stroke();
        this.ctx.shadowBlur = 0;

        // Stage Title
        this.ctx.fillStyle = '#00f2fe';
        this.ctx.font = '10px Chakra Petch';
        this.ctx.textAlign = 'left';
        this.ctx.fillText(n.stage_name || `STAGE ${n.stage}`, hudX + 12, hudY + 18);

        // Node Title
        this.ctx.fillStyle = '#ffffff';
        this.ctx.font = 'bold 12px JetBrains Mono';
        const labelText = n.label.length > 20 ? n.label.slice(0, 20) + '...' : n.label;
        this.ctx.fillText(labelText, hudX + 12, hudY + 36);

        // Severity Tag
        this.ctx.fillStyle = n.severity === 'CRITICAL' ? '#ef4444' : (n.severity === 'HIGH' ? '#f59e0b' : '#10b981');
        this.ctx.font = 'bold 10px JetBrains Mono';
        this.ctx.fillText(`SEVERITY: ${n.severity}`, hudX + 12, hudY + 54);

        // Description / Details
        this.ctx.fillStyle = '#94a3b8';
        this.ctx.font = '9px Outfit';
        const details = n.details || `Monitored entity on local system.`;
        const line1 = details.slice(0, 36);
        const line2 = details.length > 36 ? details.slice(36, 72) : '';
        this.ctx.fillText(line1, hudX + 12, hudY + 74);
        if (line2) this.ctx.fillText(line2, hudX + 12, hudY + 88);

        this.ctx.restore();
    }

    setupInteractions() {
        const getPos = (e) => {
            const rect = this.canvas.getBoundingClientRect();
            return {
                x: e.clientX - rect.left,
                y: e.clientY - rect.top
            };
        };

        const findNode = (pos) => {
            return this.nodes.find(n => {
                const dx = n.x - pos.x;
                const dy = n.y - pos.y;
                return Math.sqrt(dx * dx + dy * dy) <= n.radius + 8;
            });
        };

        this.canvas.addEventListener('mousedown', (e) => {
            const pos = getPos(e);
            const node = findNode(pos);
            if (node) {
                this.dragNode = node;
                this.selectedNode = node;
            } else {
                this.selectedNode = null;
            }
        });

        window.addEventListener('mousemove', (e) => {
            const pos = getPos(e);
            if (this.dragNode) {
                this.dragNode.x = pos.x;
                this.dragNode.y = pos.y;
                this.dragNode.vx = 0;
                this.dragNode.vy = 0;
            } else {
                this.hoverNode = findNode(pos);
                this.canvas.style.cursor = this.hoverNode ? 'pointer' : 'default';
            }
        });

        window.addEventListener('mouseup', () => {
            this.dragNode = null;
        });
    }
}

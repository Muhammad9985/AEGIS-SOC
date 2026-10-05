/**
 * AEGIS-SOC VALKYRIE AI Console & Copilot Chat Module
 */
class AIConsoleManager {
    constructor() {
        this.thoughtStream = document.getElementById('aiThoughtStream');
        this.chatMessages = document.getElementById('chatMessages');
        this.chatInput = document.getElementById('chatInput');
        this.btnSendChat = document.getElementById('btnSendChat');
        this.confidenceEl = document.getElementById('aiGlobalConfidence');

        this.setupEventListeners();
    }

    setupEventListeners() {
        if (this.btnSendChat) {
            this.btnSendChat.addEventListener('click', () => this.handleSendMessage());
        }
        if (this.chatInput) {
            this.chatInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.handleSendMessage();
            });
        }

        // Quick SOAR Buttons
        document.getElementById('btnActionIsolate')?.addEventListener('click', () => {
            this.executeSoarAction('ISOLATE_HOST', 'DESKTOP-WIN11-SEC');
        });
        document.getElementById('btnActionKill')?.addEventListener('click', () => {
            this.executeSoarAction('KILL_PID', '4812', 'update.exe', 4812);
        });
        document.getElementById('btnActionBlockIp')?.addEventListener('click', () => {
            this.executeSoarAction('BLOCK_IP', '194.26.29.112');
        });
        document.getElementById('btnActionQuarantine')?.addEventListener('click', () => {
            this.executeSoarAction('QUARANTINE_FILE', 'C:\\Users\\Public\\update.exe');
        });
    }

    addThought(title, text, type = 'cyan') {
        if (!this.thoughtStream) return;
        const line = document.createElement('div');
        line.className = 'thought-line';
        
        const now = new Date().toTimeString().split(' ')[0];
        const colorClass = type === 'red' ? 't-red' : (type === 'green' ? 't-green' : 't-cyan');
        
        line.innerHTML = `<span class="t-ts">[${now}]</span> <span class="${colorClass}">${title}:</span> ${text}`;
        this.thoughtStream.appendChild(line);
        this.thoughtStream.scrollTop = this.thoughtStream.scrollHeight;
    }

    setConfidence(score) {
        if (this.confidenceEl) {
            this.confidenceEl.textContent = `${(score * 100).toFixed(1)}%`;
        }
    }

    async handleSendMessage() {
        const text = this.chatInput.value.trim();
        if (!text) return;

        this.chatInput.value = '';
        this.appendMessage('user', text);

        try {
            const resp = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: text })
            });
            const data = await resp.json();
            this.appendMessage('ai', data.response);
        } catch (e) {
            this.appendMessage('ai', 'Error connecting to VALKYRIE neural core.');
        }
    }

    appendMessage(sender, text) {
        if (!this.chatMessages) return;
        const msgDiv = document.createElement('div');
        msgDiv.className = `chat-msg ${sender}`;

        const avatar = document.createElement('div');
        avatar.className = 'chat-avatar';
        avatar.innerHTML = sender === 'ai' ? '<i data-lucide="bot"></i>' : '<i data-lucide="user"></i>';

        const bubble = document.createElement('div');
        bubble.className = 'chat-bubble';
        // Format markdown bold
        bubble.innerHTML = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>').replace(/\n/g, '<br>');

        msgDiv.appendChild(avatar);
        msgDiv.appendChild(bubble);
        this.chatMessages.appendChild(msgDiv);
        this.chatMessages.scrollTop = this.chatMessages.scrollHeight;

        if (window.lucide) window.lucide.createIcons();
    }

    async executeSoarAction(action, target, processName = '', pid = 0) {
        try {
            this.addThought('SOAR Command', `Dispatching ${action} targeting [${target}]...`, 'cyan');
            const resp = await fetch('/api/soar/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: action,
                    target: target,
                    process_name: processName,
                    pid: pid
                })
            });
            const res = await resp.json();
            this.addThought('SOAR Executed', res.message, 'green');
            this.appendMessage('ai', `🛡️ **Autonomous SOAR Confirmation:**\n${res.message}`);
        } catch (e) {
            this.addThought('SOAR Failed', e.message, 'red');
        }
    }
}

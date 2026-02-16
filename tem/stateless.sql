/* ============================================================
   Tool name is ALWAYS the 3rd path segment after /opt/eaa/sessions/
   /opt/eaa/sessions/<timestamp>/<tool_name>/<tool_name>.<ext>
   ============================================================ */

/* 1) Extract tool_name + expose all rows (non-hidden) */




DROP VIEW IF EXISTS eaa_tool_content;
CREATE VIEW eaa_tool_content AS
SELECT
  sc.tenant_id,
  sc.session,
   substr(
    /* after_ts */
    substr(
      /* after_sessions */
      substr(
        sc.uri,
        instr(sc.uri, '/sessions/') + length('/sessions/')
      ),
      instr(
        substr(sc.uri, instr(sc.uri, '/sessions/') + length('/sessions/')),
        '/'
      ) + 1
    ),
    1,
    instr(
      substr(
        substr(
          sc.uri,
          instr(sc.uri, '/sessions/') + length('/sessions/')
        ),
        instr(
          substr(sc.uri, instr(sc.uri, '/sessions/') + length('/sessions/')),
          '/'
        ) + 1
      ),
      '/'
    ) - 1
  ) AS tool_name,
--   substr(... ) AS tool_name,
 sc.uri,
SUBSTR(CAST(sc.content AS TEXT), 1, 100000) AS result
FROM session_context sc
WHERE sc.uri LIKE '/opt/eaa/sessions/%/%/%'
AND sc.uri NOT LIKE '/opt/eaa/sessions/%/.session/%';


-- CREATE VIEW eaa_tool_content AS
-- WITH parsed AS (
--   SELECT
--     uri,
--     CAST(content AS TEXT) AS result,

--     -- get everything after "/sessions/"
--     substr(uri, instr(uri, '/sessions/') + length('/sessions/')) AS after_sessions
--   FROM uniform_resource 
--   WHERE uri LIKE '/opt/eaa/sessions/%/%/%'
--     AND uri NOT LIKE '%/.%'         -- exclude hidden files/dirs anywhere in path
-- ),
-- parsed2 AS (
--   SELECT
--     uri,
--     result,
--     -- strip "<timestamp>/" leaving "<tool_name>/<file>"
--     substr(after_sessions, instr(after_sessions, '/') + 1) AS after_ts
--   FROM parsed
-- )
-- SELECT
--   -- tool_name is the next segment before the next "/"
--   substr(after_ts, 1, instr(after_ts, '/') - 1) AS tool_name,
--   uri,
--   result
-- FROM parsed2
-- WHERE instr(after_ts, '/') > 0
--   AND substr(after_ts, 1, instr(after_ts, '/') - 1) <> ''
-- ;

/* 2) Optional: distinct tool list (for cards) */
-- DROP VIEW IF EXISTS eaa_tool_name;

-- CREATE VIEW eaa_tool_name AS
-- SELECT DISTINCT tool_name AS tool, NULL AS description
-- FROM eaa_tool_content;

/* 3) Optional: counts per tool (for cards) */
DROP VIEW IF EXISTS eaa_tool_result_count;

CREATE VIEW eaa_tool_result_count AS
SELECT
  r.tool_name,
  COUNT(*) AS row_count
FROM eaa_tool_results r
GROUP BY r.tool_name;

DROP VIEW IF EXISTS eaa_tool_result_count;

CREATE VIEW eaa_tool_result_count AS
SELECT
  tool_name AS tool,
  COUNT(*)  AS row_count
FROM eaa_tool_content
GROUP BY tool_name;



-- Ensure JSON functions are enabled (important fix)
-- If using older SQLite, ensure json1 is available. CAST all content as TEXT for safety.

-- Cleanup: Drop existing views before recreating them (in reverse dependency order)
DROP VIEW IF EXISTS nuclei_immediate_action_required;
DROP VIEW IF EXISTS nuclei_security_header_analysis;
DROP VIEW IF EXISTS nuclei_env_secret_detection;
DROP VIEW IF EXISTS nuclei_token_exposure_detection;
DROP VIEW IF EXISTS nuclei_exposed_admin_detection;
DROP VIEW IF EXISTS nuclei_default_credential;
DROP VIEW IF EXISTS nuclei_auth_bypass_detection;
DROP VIEW IF EXISTS nuclei_critical_cert_issue;
DROP VIEW IF EXISTS nuclei_certificate_vulnerability;
DROP VIEW IF EXISTS nuclei_remediation_priority;
DROP VIEW IF EXISTS nuclei_security_dashboard;
DROP VIEW IF EXISTS nuclei_evidence;
DROP VIEW IF EXISTS nuclei_reference;
DROP VIEW IF EXISTS nuclei_tag;
DROP VIEW IF EXISTS nuclei_scan_metadata;

-- Subzy
DROP VIEW IF EXISTS subzy_remediation_priority;
DROP VIEW IF EXISTS subzy_domain_risk_assessment;
DROP VIEW IF EXISTS subzy_aws_takeover;
DROP VIEW IF EXISTS subzy_github_takeover;
DROP VIEW IF EXISTS subzy_service_breakdown;
DROP VIEW IF EXISTS subzy_vulnerability_summary;
DROP VIEW IF EXISTS subzy_vulnerable_subdomain;
DROP VIEW IF EXISTS subzy_scan_result;

-- Test-SSL
DROP VIEW IF EXISTS test_ssl_summary;
DROP VIEW IF EXISTS test_ssl_vulnerable_finding;
DROP VIEW IF EXISTS test_ssl_scan_result;

-- Corsy
DROP VIEW IF EXISTS corsy_critical_severity;
DROP VIEW IF EXISTS corsy_high_severity;
DROP VIEW IF EXISTS corsy_medium_severity;
DROP VIEW IF EXISTS corsy_low_severity;
DROP VIEW IF EXISTS corsy_summary;
DROP VIEW IF EXISTS corsy_vulnerable_finding;
DROP VIEW IF EXISTS corsy_scan_result;

-- WPScan
DROP VIEW IF EXISTS wp_vulnerability;
DROP VIEW IF EXISTS wp_interesting_finding;
DROP VIEW IF EXISTS wp_user_identification;
DROP VIEW IF EXISTS wp_user;

-- SSLyze
DROP VIEW IF EXISTS sslyze_heartbleed_text;
DROP VIEW IF EXISTS sslyze_ccs_injection_text;
DROP VIEW IF EXISTS sslyze_robot_text;
DROP VIEW IF EXISTS sslyze_session_renegotiation_text;
DROP VIEW IF EXISTS sslyze_elliptic_curves_text;
DROP VIEW IF EXISTS sslyze_tls_compression_text;
DROP VIEW IF EXISTS sslyze_extended_master_secret_text;
DROP VIEW IF EXISTS sslyze_tls_fallback_scsv_text;

-- HTTPX-Toolkit
DROP VIEW IF EXISTS server_metadata;

-- WhatWeb
DROP VIEW IF EXISTS whatweb_tech_summary;

-- ===== Tasks (from Markdown in /backlog/tasks) =====
DROP VIEW IF EXISTS task_summary_full;

-- drop first (follow your repo pattern)
DROP VIEW IF EXISTS cdncheck_scan_result;
DROP VIEW IF EXISTS cdncheck_cloud_summary;
---------------------------------------------------------------------------
-- VirusTotal domain report views
---------------------------------------------------------------------------

-- Drop in reverse dependency order
DROP VIEW IF EXISTS virustotal_undetected_url;
DROP VIEW IF EXISTS virustotal_undetected_referrer_sample;
DROP VIEW IF EXISTS virustotal_subdomain;
DROP VIEW IF EXISTS virustotal_resolution;
DROP VIEW IF EXISTS virustotal_detected_communicating_sample;
DROP VIEW IF EXISTS virustotal_raw;

---------------------------------------------------------------------------
-- Dalfox
---------------------------------------------------------------------------
-- drop existing views (reverse dependency order)
DROP VIEW IF EXISTS dalfox_finding;

---------------------------------------------------------------------------
-- Commix
---------------------------------------------------------------------------
-- drop existing views (reverse dependency order)
DROP VIEW IF EXISTS commix_finding;

---------------------------------------------------------------------------
-- SQLMap
---------------------------------------------------------------------------

-- Drop the view if it exists
DROP VIEW IF EXISTS sqlmap_metadata;

---------------------------------------------------------------------------
-- Ghauri
---------------------------------------------------------------------------

-- Drop the view if it exists
DROP VIEW IF EXISTS ghauri_summary;

---------------------------------------------------------------------------
-- TRIVY
---------------------------------------------------------------------------

-- Clean start
DROP VIEW IF EXISTS trivy_report_summary_line;
DROP VIEW IF EXISTS trivy_vulnerability_line;
DROP VIEW IF EXISTS trivy_scan_result;

---------------------------------------------------------------------------
-- WAF Bypass
---------------------------------------------------------------------------

-- Drop existing views
DROP VIEW IF EXISTS waf_bypass_summary;
DROP VIEW IF EXISTS waf_bypass_scan_result;

---------------------------------------------------------------------------
-- MISCONFIG_MAPPER VIEWS  (append into stateless.sql)
---------------------------------------------------------------------------

DROP VIEW IF EXISTS misconfig_mapper_scan_result;

---------------------------------------------------------------------------
-- Vulnapi Bypass
---------------------------------------------------------------------------
DROP VIEW IF EXISTS vulnapi_cleaned_result;

---------------------------------------------------------------------------------
-- 1. nuclei_scan_metadata: Extracts all scalar and object-nested fields
---------------------------------------------------------------------------------
CREATE VIEW nuclei_scan_metadata AS
SELECT
    nt.uniform_resource_id,
    json_extract(CAST(nt.content AS TEXT), '$.template-id') AS template_id,
    json_extract(CAST(nt.content AS TEXT), '$.host') AS host,
    json_extract(CAST(nt.content AS TEXT), '$.ip') AS ip_address,
    json_extract(CAST(nt.content AS TEXT), '$.timestamp') AS timestamp,
    json_extract(CAST(nt.content AS TEXT), '$.matched-at') AS matched_url,
    json_extract(CAST(nt.content AS TEXT), '$.info.severity') AS severity,
    json_extract(CAST(nt.content AS TEXT), '$.info.name') AS template_name,
    json_extract(CAST(nt.content AS TEXT), '$.info.description') AS template_description,
    json_extract(CAST(nt.content AS TEXT), '$.info.author[0]') AS primary_author,
    json_extract(CAST(nt.content AS TEXT), '$.info.classification."cvss-score"') AS cvss_score,
    json_extract(CAST(nt.content AS TEXT), '$.info.classification."cvss-metrics"') AS cvss_metrics,
    json_extract(CAST(nt.content AS TEXT), '$.info.classification."cve-id"') AS cve_id,
    json_extract(CAST(nt.content AS TEXT), '$.info.classification."cwe-id"[0]') AS primary_cwe_id,
    json_extract(CAST(nt.content AS TEXT), '$.info.classification.cpe') AS cpe,
    json_extract(CAST(nt.content AS TEXT), '$.info.metadata.product') AS metadata_product,
    json_extract(CAST(nt.content AS TEXT), '$.info.metadata."shodan-query"') AS shodan_query,
    json_extract(CAST(nt.content AS TEXT), '$.info.metadata.vendor') AS metadata_vendor,
    json_extract(CAST(nt.content AS TEXT), '$.info.metadata.verified') AS verified
FROM uniform_resource nt
WHERE json_valid(CAST(nt.content AS TEXT));

---------------------------------------------------------------------------------
-- 2. nuclei_tag: Flattens the 'tags' array
---------------------------------------------------------------------------------
CREATE VIEW nuclei_tag AS
SELECT
    nt.uniform_resource_id,
    json_extract(CAST(nt.content AS TEXT), '$.template-id') AS template_id,
    json_extract(value) AS tag
FROM uniform_resource nt,
     json_each(CAST(nt.content AS TEXT), '$.info.tags')
WHERE json_valid(CAST(nt.content AS TEXT));

---------------------------------------------------------------------------------
-- 3. nuclei_reference: Flattens the 'reference' array
---------------------------------------------------------------------------------
CREATE VIEW nuclei_reference AS
SELECT
    nt.uniform_resource_id,
    json_extract(CAST(nt.content AS TEXT), '$.template-id') AS template_id,
    json_extract(value) AS reference_url
FROM uniform_resource nt,
     json_each(CAST(nt.content AS TEXT), '$.info.reference')
WHERE json_valid(CAST(nt.content AS TEXT));

---------------------------------------------------------------------------------
-- 4. nuclei_evidence: Flattens the 'extracted-results' array
---------------------------------------------------------------------------------
CREATE VIEW nuclei_evidence AS
SELECT
    nt.uniform_resource_id,
    json_extract(CAST(nt.content AS TEXT), '$.template-id') AS template_id,
    json_extract(CAST(nt.content AS TEXT), '$.host') AS host,
    json_extract(CAST(nt.content AS TEXT), '$.matched-at') AS matched_url,
    json_extract(value) AS evidence_value
FROM uniform_resource nt,
     json_each(CAST(nt.content AS TEXT), '$.extracted-results')
WHERE json_valid(CAST(nt.content AS TEXT));

---------------------------------------------------------------------------------
-- 5. nuclei_security_dashboard: High-level security summary
---------------------------------------------------------------------------------
CREATE VIEW nuclei_security_dashboard AS
SELECT 
    'Authentication Issues' as vulnerability_category,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count
FROM nuclei_scan_metadata
WHERE severity IN ('critical', 'high')
  AND (
        template_description LIKE '%authentication%bypass%' OR
        template_description LIKE '%auth%bypass%' OR
        template_description LIKE '%login%bypass%' OR
        template_description LIKE '%default%credential%' OR
        template_description LIKE '%default%password%'
  )

UNION ALL

SELECT 
    'Certificate Issues' as vulnerability_category,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count
FROM nuclei_scan_metadata
WHERE 
    template_name LIKE '%ssl%' OR
    template_name LIKE '%tls%' OR
    template_name LIKE '%certificate%'

UNION ALL

SELECT 
    'Missing Security Headers' as vulnerability_category,
    COUNT(*) as total_findings,
    COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'high' THEN 1 END) as high_count
FROM nuclei_scan_metadata
WHERE 
    template_name LIKE '%missing%header%' OR
    template_name LIKE '%security%header%';

---------------------------------------------------------------------------------
-- 6. nuclei_remediation_priority: Prioritized remediation queue
---------------------------------------------------------------------------------
CREATE VIEW nuclei_remediation_priority AS
SELECT 
    host,
    template_name,
    severity,
    cvss_score,
    cve_id,
    matched_url,
    template_description,
    uniform_resource_id,
    CASE 
        WHEN severity = 'critical' AND CAST(COALESCE(cvss_score, '0') AS REAL) >= 9.0 THEN 'P0 - Emergency'
        WHEN severity = 'critical' OR CAST(COALESCE(cvss_score, '0') AS REAL) >= 7.0 THEN 'P1 - High'
        WHEN severity = 'high' OR CAST(COALESCE(cvss_score, '0') AS REAL) >= 4.0 THEN 'P2 - Medium' 
        ELSE 'P3 - Low'
    END as priority_level,
    CASE 
        WHEN template_description LIKE '%authentication%' THEN 'Auth'
        WHEN template_description LIKE '%token%' OR template_description LIKE '%secret%' THEN 'Secrets'
        WHEN template_description LIKE '%certificate%' OR template_description LIKE '%ssl%' THEN 'Crypto'
        WHEN template_description LIKE '%injection%' THEN 'Injection'
        ELSE 'Other'
    END as vulnerability_type
FROM nuclei_scan_metadata
WHERE severity IN ('critical', 'high')
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        ELSE 3 
    END,
    CAST(COALESCE(cvss_score, '0') AS REAL) DESC;

---------------------------------------------------------------------------------
-- 7. nuclei_certificate_vulnerability: SSL/TLS certificate issues
---------------------------------------------------------------------------------
CREATE VIEW nuclei_certificate_vulnerability AS
SELECT 
    host,
    ip_address,
    matched_url,
    template_name,
    severity,
    template_description,
    cve_id,
    uniform_resource_id,
    CASE 
        WHEN template_name LIKE '%expired%cert%' THEN 'Expired Certificate'
        WHEN template_name LIKE '%self-signed%' THEN 'Self-Signed Certificate'
        WHEN template_name LIKE '%weak%cipher%' THEN 'Weak Cipher Suite'
        WHEN template_name LIKE '%ssl%v2%' OR template_name LIKE '%ssl%v3%' THEN 'Deprecated SSL Protocol'
        WHEN template_name LIKE '%tls%1.0%' OR template_name LIKE '%tls%1.1%' THEN 'Deprecated TLS Protocol'
        WHEN template_name LIKE '%certificate%mismatch%' THEN 'Certificate Name Mismatch'
        WHEN template_name LIKE '%untrusted%cert%' THEN 'Untrusted Certificate'
        ELSE 'Other Certificate Issue'
    END as certificate_issue_type
FROM nuclei_scan_metadata
WHERE 
    template_name LIKE '%ssl%' OR
    template_name LIKE '%tls%' OR
    template_name LIKE '%certificate%' OR
    template_description LIKE '%certificate%' OR
    template_description LIKE '%ssl%' OR
    template_description LIKE '%tls%' OR
    template_name LIKE '%cipher%' OR
    template_name LIKE '%crypto%';

---------------------------------------------------------------------------------
-- 8. nuclei_critical_cert_issue: Critical certificate issues requiring action
---------------------------------------------------------------------------------
CREATE VIEW nuclei_critical_cert_issue AS
SELECT 
    host,
    template_name,
    severity,
    certificate_issue_type,
    cve_id,
    matched_url,
    'Certificate Issue' as vulnerability_class,
    CASE 
        WHEN certificate_issue_type IN ('Expired Certificate', 'Self-Signed Certificate') THEN 'Immediate Action Required'
        WHEN certificate_issue_type IN ('Deprecated SSL Protocol', 'Deprecated TLS Protocol') THEN 'Security Risk'
        WHEN certificate_issue_type = 'Weak Cipher Suite' THEN 'Encryption Weakness'
        ELSE 'Monitor'
    END as remediation_urgency
FROM nuclei_certificate_vulnerability
WHERE severity IN ('critical', 'high');

---------------------------------------------------------------------------------
-- 9. nuclei_auth_bypass_detection: Authentication bypass vulnerabilities
---------------------------------------------------------------------------------
CREATE VIEW nuclei_auth_bypass_detection AS
SELECT 
    host,
    matched_url,
    template_name,
    severity,
    template_description,
    cve_id,
    cvss_score,
    'Authentication Bypass' as vulnerability_class
FROM nuclei_scan_metadata
WHERE 
    (
        template_description LIKE '%authentication%bypass%' OR
        template_description LIKE '%auth%bypass%' OR
        template_description LIKE '%login%bypass%' OR
        template_name LIKE '%bypass%auth%' OR
        template_description LIKE '%../admin%' OR
        template_description LIKE '%path%traversal%admin%' OR
        template_description LIKE '%sql%injection%login%' OR
        template_description LIKE '%sqli%auth%'
    )
    AND severity IN ('critical', 'high', 'medium');

---------------------------------------------------------------------------------
-- 10. nuclei_default_credential: Default credential vulnerabilities
---------------------------------------------------------------------------------
CREATE VIEW nuclei_default_credential AS
SELECT 
    host,
    matched_url,
    template_name,
    severity,
    template_description,
    'Default Credentials' as vulnerability_class
FROM nuclei_scan_metadata
WHERE 
    template_description LIKE '%default%credential%' OR
    template_description LIKE '%default%password%' OR
    template_description LIKE '%weak%credential%' OR
    template_name LIKE '%default%login%' OR
    template_name LIKE '%admin:admin%' OR
    template_name LIKE '%root:root%' OR
    template_description LIKE '%guest%account%';

---------------------------------------------------------------------------------
-- 11. nuclei_exposed_admin_detection: Exposed admin interfaces
---------------------------------------------------------------------------------
CREATE VIEW nuclei_exposed_admin_detection AS
SELECT 
    host,
    matched_url,
    template_name,
    severity,
    'Exposed Admin Interface' as vulnerability_class,
    CASE 
        WHEN matched_url LIKE '%/admin%' THEN 'Admin Panel'
        WHEN matched_url LIKE '%/wp-admin%' THEN 'WordPress Admin'
        WHEN matched_url LIKE '%/phpmyadmin%' THEN 'Database Admin'
        WHEN matched_url LIKE '%/administrator%' THEN 'Administrator Panel'
        WHEN matched_url LIKE '%/management%' THEN 'Management Interface'
        ELSE 'Other Admin Interface'
    END as admin_type
FROM nuclei_scan_metadata
WHERE 
    matched_url LIKE '%/admin%' OR
    matched_url LIKE '%/administrator%' OR
    matched_url LIKE '%/wp-admin%' OR
    matched_url LIKE '%/phpmyadmin%' OR
    matched_url LIKE '%/dashboard%' OR
    matched_url LIKE '%/panel%' OR
    matched_url LIKE '%/management%' OR
    template_name LIKE '%admin%panel%' OR
    template_name LIKE '%dashboard%exposed%';

---------------------------------------------------------------------------------
-- 12. nuclei_token_exposure_detection: Token and secret exposure
---------------------------------------------------------------------------------
CREATE VIEW nuclei_token_exposure_detection AS
SELECT 
    uniform_resource_id,
    json_extract(content, '$.host') AS host,
    json_extract(content, '$.matched-at') AS matched_url,
    json_extract(content, '$.info.name') AS template_name,
    json_extract(content, '$.info.severity') AS severity,
    'Token Exposure' as vulnerability_class
FROM uniform_resource
WHERE 
    json_valid(content) 
    AND content IS NOT NULL 
    AND (
        json_extract(content, '$.info.name') LIKE '%token%' OR
        json_extract(content, '$.info.name') LIKE '%secret%' OR
        json_extract(content, '$.info.name') LIKE '%key%exposed%' OR
        json_extract(content, '$.info.description') LIKE '%api%key%' OR
        json_extract(content, '$.info.description') LIKE '%token%'
    );

---------------------------------------------------------------------------------
-- 13. nuclei_env_secret_detection: Environment file exposure
---------------------------------------------------------------------------------
CREATE VIEW nuclei_env_secret_detection AS
SELECT 
    host,
    matched_url,
    template_name,
    severity,
    'Environment File Exposure' as vulnerability_class,
    CASE 
        WHEN matched_url LIKE '%.env%' THEN '.env file'
        WHEN matched_url LIKE '%/.aws/%' THEN 'AWS credentials'
        WHEN matched_url LIKE '%/.ssh/%' THEN 'SSH keys'
        WHEN matched_url LIKE '%config%' THEN 'Config file'
        ELSE 'Other secrets file'
    END as secret_file_type
FROM nuclei_scan_metadata
WHERE 
    matched_url LIKE '%.env%' OR
    matched_url LIKE '%/.env%' OR
    matched_url LIKE '%/.aws/%' OR
    matched_url LIKE '%/.ssh/%' OR
    matched_url LIKE '%/config%' OR
    matched_url LIKE '%/.config%' OR
    template_name LIKE '%environment%' OR
    template_name LIKE '%.env%' OR
    template_name LIKE '%secret%file%';

---------------------------------------------------------------------------------
-- 14. nuclei_security_header_analysis: Missing security headers
---------------------------------------------------------------------------------
CREATE VIEW nuclei_security_header_analysis AS
SELECT 
    host,
    template_name,
    severity,
    matched_url,
    CASE 
        WHEN template_name LIKE '%hsts%' THEN 'Missing HSTS'
        WHEN template_name LIKE '%content-security-policy%' THEN 'Missing CSP'
        WHEN template_name LIKE '%x-frame-options%' THEN 'Missing X-Frame-Options'
        WHEN template_name LIKE '%x-content-type%' THEN 'Missing X-Content-Type-Options'
        WHEN template_name LIKE '%referrer-policy%' THEN 'Missing Referrer-Policy'
        ELSE 'Other Security Header'
    END as missing_header_type,
    'Security Header Missing' as vulnerability_class
FROM nuclei_scan_metadata
WHERE 
    template_name LIKE '%missing%header%' OR
    template_name LIKE '%security%header%' OR
    template_name LIKE '%hsts%' OR
    template_name LIKE '%content-security-policy%' OR
    template_name LIKE '%x-frame-options%' OR
    template_name LIKE '%x-content-type%' OR
    template_name LIKE '%referrer-policy%';

---------------------------------------------------------------------------------
-- 15. nuclei_immediate_action_required: Critical issues requiring immediate attention
---------------------------------------------------------------------------------
CREATE VIEW nuclei_immediate_action_required AS
SELECT 
    host,
    vulnerability_class,
    template_name,
    severity,
    matched_url,
    'IMMEDIATE' as action_priority,
    CASE 
        WHEN vulnerability_class LIKE '%Token%' THEN 'Revoke and rotate immediately'
        WHEN vulnerability_class LIKE '%Auth%' THEN 'Disable access, patch system'
        WHEN vulnerability_class LIKE '%Certificate%' THEN 'Update certificate'
        ELSE 'Investigate and remediate'
    END as recommended_action
FROM (
    SELECT 
        host, 
        vulnerability_class, 
        template_name, 
        severity, 
        matched_url 
    FROM nuclei_auth_bypass_detection 
    WHERE severity = 'critical'
    
    UNION ALL
    
    SELECT 
        host, 
        vulnerability_class, 
        template_name, 
        severity, 
        matched_url 
    FROM nuclei_token_exposure_detection 
    WHERE severity IN ('critical', 'high')
    
    UNION ALL
    
    SELECT 
        host, 
        vulnerability_class, 
        template_name, 
        severity, 
        matched_url 
    FROM nuclei_critical_cert_issue 
    WHERE remediation_urgency = 'Immediate Action Required'
)
ORDER BY 
    CASE vulnerability_class 
        WHEN 'Token Exposure' THEN 1
        WHEN 'Authentication Bypass' THEN 2
        ELSE 3 
    END;

---------------------------------------------------------------------------------
-- SUBZY VIEWS 
---------------------------------------------------------------------------------

-- 1. Raw parse
CREATE VIEW subzy_scan_result AS
SELECT 
    uniform_resource_id,
    trim(value) AS result_block,
    CASE 
        WHEN trim(value) LIKE '%[ VULNERABLE ]%' THEN 'VULNERABLE'
        WHEN trim(value) LIKE '%[ NOT VULNERABLE ]%' THEN 'SAFE'
        WHEN trim(value) LIKE '%[ TIMEOUT ]%' THEN 'TIMEOUT'
        WHEN trim(value) LIKE '%[ ERROR ]%' THEN 'ERROR'
        ELSE 'UNKNOWN'
    END as vulnerability_status,
    CASE 
        WHEN trim(value) LIKE '%http%' THEN 
            substr(trim(value), 
                   instr(trim(value), 'http'), 
                   CASE 
                       WHEN instr(substr(trim(value), instr(trim(value), 'http')), ' ') > 0 
                       THEN instr(substr(trim(value), instr(trim(value), 'http')), ' ') - 1
                       ELSE length(substr(trim(value), instr(trim(value), 'http')))
                   END)
        ELSE NULL
    END as extracted_url
FROM uniform_resource,
     json_each('["' || replace(content, '-----------------', '","') || '"]')
WHERE uri LIKE '%subzy%'
  AND trim(value) != ''
  AND length(trim(value)) > 10;

-- 2. Vulnerable subdomain focus
CREATE VIEW subzy_vulnerable_subdomain AS
SELECT 
    uniform_resource_id,
    RawExtraction.vulnerable_evidence, 
    RawExtraction.vulnerable_subdomain,
    RawExtraction.Raw_Service_Extracted AS takeover_service, 
    'Subdomain Takeover' AS vulnerability_type,
    'HIGH' AS severity,
    NULL AS exploitation_difficulty, 
    NULL AS exploitation_method
FROM (
    SELECT
        t1.uniform_resource_id,
        t1.result_block AS vulnerable_evidence, 
        TRIM(SUBSTR(
            t1.result_block,
            INSTR(t1.result_block, ' - ') + 3,
            INSTR(t1.result_block, ' [') - (INSTR(t1.result_block, ' - ') + 3)
        )) AS vulnerable_subdomain,
        TRIM(SUBSTR(
             SUBSTR(t1.result_block, INSTR(t1.result_block, ' [') + 3), 
             1, 
             INSTR(SUBSTR(t1.result_block, INSTR(t1.result_block, ' [') + 3), ']') - 1
         )) AS Raw_Service_Extracted
    FROM subzy_scan_result AS t1 
    WHERE t1.vulnerability_status = 'VULNERABLE'
      AND t1.result_block IS NOT NULL
) AS RawExtraction;

-- 3. High-level summary
CREATE VIEW subzy_vulnerability_summary AS
SELECT 
    COUNT(*) as total_subdomains_tested,
    COUNT(CASE WHEN vulnerability_status = 'VULNERABLE' THEN 1 END) as vulnerable_count,
    COUNT(CASE WHEN vulnerability_status = 'SAFE' THEN 1 END) as safe_count,
    COUNT(CASE WHEN vulnerability_status = 'TIMEOUT' THEN 1 END) as timeout_count,
    COUNT(CASE WHEN vulnerability_status = 'ERROR' THEN 1 END) as error_count,
    ROUND(
        (COUNT(CASE WHEN vulnerability_status = 'VULNERABLE' THEN 1 END) * 100.0) / 
        COUNT(*), 2
    ) as vulnerability_percentage
FROM subzy_scan_result;

-- 4. Service breakdown
CREATE VIEW subzy_service_breakdown AS
SELECT 
    t1.takeover_service,
    COUNT(t1.vulnerable_subdomain) AS total_affected_count,
    GROUP_CONCAT(t1.vulnerable_subdomain) AS affected_subdomains_list,
    'Subdomain Takeover' AS vulnerability_type,
    'HIGH' AS severity_level
FROM subzy_vulnerable_subdomain AS t1
GROUP BY t1.takeover_service
ORDER BY total_affected_count DESC;

-- 5. GitHub Pages takeovers
CREATE VIEW subzy_github_takeover AS
SELECT 
    vulnerable_subdomain,
    vulnerable_evidence,
    'CNAME misconfiguration' AS exploitation_method, 
    'IMMEDIATE' as action_priority,
    'Create GitHub Pages repository to claim subdomain' as remediation_steps
FROM subzy_vulnerable_subdomain
WHERE takeover_service = 'GitHub Pages';

-- 6. AWS S3 takeovers
CREATE VIEW subzy_aws_takeover AS
SELECT 
    vulnerable_subdomain,
    vulnerable_evidence,
    'CNAME misconfiguration' AS exploitation_method,
    'IMMEDIATE' as action_priority,
    'Create S3 bucket with matching name to claim subdomain' as remediation_steps
FROM subzy_vulnerable_subdomain
WHERE takeover_service = 'AWS S3';

-- 7. Risk by domain
CREATE VIEW subzy_domain_risk_assessment AS
SELECT 
    REPLACE(
        REPLACE(
            REPLACE(
                REPLACE(vulnerable_subdomain, 'http://', ''),
            'https://', ''),
        'www.', ''),
    '/', '') AS domain,
    COUNT(*) AS vulnerable_subdomains,
    GROUP_CONCAT(DISTINCT takeover_service) AS vulnerable_services,
    GROUP_CONCAT(DISTINCT vulnerable_subdomain) AS vulnerable_urls,
    CASE 
        WHEN COUNT(*) >= 3 THEN 'CRITICAL - Multiple takeover opportunities'
        WHEN COUNT(*) = 2 THEN 'HIGH - Multiple vulnerabilities'
        WHEN COUNT(*) = 1 THEN 'MEDIUM - Single vulnerability'
        ELSE 'LOW'
    END AS domain_risk_level
FROM subzy_vulnerable_subdomain
GROUP BY domain
ORDER BY vulnerable_subdomains DESC;

-- 8. Remediation priority
CREATE VIEW subzy_remediation_priority AS
SELECT 
    vulnerable_subdomain,
    takeover_service,
    vulnerability_type,
    severity, 
    'HIGH' AS remediation_priority,
    'Review CNAME and update DNS immediately' AS recommended_action
FROM subzy_vulnerable_subdomain
ORDER BY remediation_priority ASC, vulnerable_subdomain;

---------------------------------------------------------------------------------
-- TEST-SSL VIEWS 
---------------------------------------------------------------------------------

-- 1. Raw parse
CREATE VIEW test_ssl_scan_result AS
SELECT 
    uniform_resource_id,
    content AS scan_evidence,
    substr(uri, instr(uri, '|') + 1) AS extracted_host,
    CASE
        WHEN content LIKE '%"id" : "overall_grade"%' THEN 
            trim(
                substr(
                    content, 
                    instr(content, '"id" : "overall_grade"') + 28,
                    2
                ), 
                '" '
            )
        ELSE 'UNKNOWN'
    END AS ssl_rating,
    CASE 
        WHEN content LIKE '%"id" : "expired_cert", "value" : "True"%' THEN 1
        WHEN content LIKE '%expired on%' THEN 1
        ELSE 0
    END AS is_expired_flag,
    CASE
        WHEN content LIKE '%"id" : "grade_cap_reason_1"%' THEN 
            trim(
                substr(
                    content, 
                    instr(content, '"id" : "grade_cap_reason_1"') + 31,
                    instr(substr(content, instr(content, '"id" : "grade_cap_reason_1"') + 31), '"') - 1
                ), 
                '" '
            )
        ELSE 'None specified'
    END AS primary_remediation_reason
FROM uniform_resource
WHERE uri LIKE '%testssl%'
  AND content LIKE '%"id" : "overall_grade"%';

-- 2. Vulnerable hosts
CREATE VIEW test_ssl_vulnerable_finding AS
SELECT
    uniform_resource_id,
    extracted_host AS vulnerable_host,
    ssl_rating,
    is_expired_flag,
    scan_evidence AS vulnerable_evidence,
    primary_remediation_reason,
    'SSL/TLS Misconfiguration' AS vulnerability_type,
    CASE 
        WHEN ssl_rating IN ('F', 'E', 'D', 'C') OR is_expired_flag = 1 THEN 'HIGH'
        WHEN ssl_rating = 'B' THEN 'MEDIUM'
        ELSE 'LOW'
    END AS severity,
    NULL AS remediation_plan
FROM test_ssl_scan_result
WHERE ssl_rating IN ('F', 'E', 'D', 'C', 'B') OR is_expired_flag = 1;

-- 3. Summary
CREATE VIEW test_ssl_summary AS
SELECT 
    COUNT(*) as total_hosts_scanned,
    COUNT(CASE WHEN ssl_rating IN ('A', 'A+') THEN 1 END) as good_rating_count,
    COUNT(CASE WHEN ssl_rating IN ('B', 'C', 'D', 'E', 'F') THEN 1 END) as poor_rating_count,
    COUNT(CASE WHEN is_expired_flag = 1 THEN 1 END) as expired_cert_count,
    ROUND(
        (COUNT(CASE WHEN ssl_rating IN ('F', 'E') OR is_expired_flag = 1 THEN 1 END) * 100.0) / 
        COUNT(*), 2
    ) as critical_risk_percentage,
    GROUP_CONCAT(DISTINCT ssl_rating) AS distinct_ratings_found
FROM test_ssl_scan_result;

---------------------------------------------------------------------------------
-- CORSY VIEWS
---------------------------------------------------------------------------------

-- 1. Raw parse
CREATE VIEW corsy_scan_result AS
SELECT 
    uniform_resource_id,
    trim(RawBlocks.block_text) AS result_block,
    CASE 
        WHEN trim(RawBlocks.block_text) LIKE '%http%' THEN 
            substr(trim(RawBlocks.block_text), 
                   instr(trim(RawBlocks.block_text), 'http'), 
                   CASE 
                       WHEN instr(substr(trim(RawBlocks.block_text), instr(trim(RawBlocks.block_text), ' ')), ' ') > 0 
                       THEN instr(substr(trim(RawBlocks.block_text), instr(trim(RawBlocks.block_text), ' ')), ' ') - 1
                       ELSE length(substr(trim(RawBlocks.block_text), instr(trim(RawBlocks.block_text), ' ')))
                   END)
        ELSE NULL
    END as extracted_url,
    CASE
        WHEN trim(RawBlocks.block_text) LIKE '%Severity: critical%' THEN 'CRITICAL'
        WHEN trim(RawBlocks.block_text) LIKE '%Severity: high%' THEN 'HIGH'
        WHEN trim(RawBlocks.block_text) LIKE '%Severity: medium%' THEN 'MEDIUM'
        WHEN trim(RawBlocks.block_text) LIKE '%Severity: low%' THEN 'LOW'
        ELSE 'UNKNOWN'
    END as severity_status
FROM (
    SELECT 
        uniform_resource_id,
        content,
        value AS block_text
    FROM uniform_resource,
         json_each('["' || replace(content, '[92m+[0m', '","') || '"]')
    WHERE uri LIKE '%corsy%'
) AS RawBlocks
WHERE trim(RawBlocks.block_text) != ''
  AND length(trim(RawBlocks.block_text)) > 10;

-- 2. Consolidated vulnerable findings
CREATE VIEW corsy_vulnerable_finding AS
SELECT
    uniform_resource_id,
    result_block AS vulnerable_evidence,
    extracted_url AS vulnerable_host,
    severity_status AS severity,
    'CORS Misconfiguration' AS vulnerability_type,
    NULL AS remediation_priority,
    NULL AS recommended_action
FROM corsy_scan_result
WHERE severity_status IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- 3. Summary
CREATE VIEW corsy_summary AS
SELECT 
    COUNT(*) as total_hosts_scanned,
    COUNT(CASE WHEN severity_status = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity_status = 'HIGH' THEN 1 END) as high_count,
    COUNT(CASE WHEN severity_status = 'MEDIUM' THEN 1 END) as medium_count,
    COUNT(CASE WHEN severity_status = 'LOW' THEN 1 END) as low_count,
    COUNT(CASE WHEN severity_status = 'UNKNOWN' THEN 1 END) as unclassified_count,
    ROUND(
        (COUNT(CASE WHEN severity_status IN ('CRITICAL', 'HIGH') THEN 1 END) * 100.0) / 
        COUNT(*), 2
    ) as high_risk_percentage
FROM corsy_scan_result;

-- 4–7. Simple severity filters
CREATE VIEW corsy_critical_severity AS
SELECT uniform_resource_id, vulnerable_evidence, vulnerable_host
FROM corsy_vulnerable_finding
WHERE severity = 'CRITICAL';

CREATE VIEW corsy_high_severity AS
SELECT uniform_resource_id, vulnerable_evidence, vulnerable_host
FROM corsy_vulnerable_finding
WHERE severity = 'HIGH';

CREATE VIEW corsy_medium_severity AS
SELECT uniform_resource_id, vulnerable_evidence, vulnerable_host
FROM corsy_vulnerable_finding
WHERE severity = 'MEDIUM';

CREATE VIEW corsy_low_severity AS
SELECT uniform_resource_id, vulnerable_evidence, vulnerable_host
FROM corsy_vulnerable_finding
WHERE severity = 'LOW';

---------------------------------------------------------------------------------
-- 1. wpscan - Vulnerability
---------------------------------------------------------------------------------
CREATE VIEW wp_vulnerability AS
SELECT 
    json_extract(content, '$.version.number') AS wp_version,
    json_extract(content, '$.version.vulnerabilities[0].title') AS vulnerability_title,
    json_extract(content, '$.version.vulnerabilities[0].fixed_in') AS fixed_in_version,
    json_extract(content, '$.version.vulnerabilities[0].references.cve[0]') AS cve_id,
    json_extract(content, '$.version.vulnerabilities[0].references.url[0]') AS reference_urls
FROM 
    uniform_resource
WHERE 
    content LIKE '%"vulnerabilities": [%';

---------------------------------------------------------------------------------
-- 2. wpscan - Interesting Finding
---------------------------------------------------------------------------------

CREATE VIEW wp_interesting_finding AS
SELECT 
    -- Extract the finding type (before the URL in the string)
    json_extract(findings.value, '$.to_s') AS finding_type,
    -- Extract the URL from the 'interesting_entries' list
    json_extract(findings.value, '$.interesting_entries[0]') AS details
FROM 
    uniform_resource,
    json_each(content, '$.interesting_findings') AS findings
WHERE 
    content LIKE '%"interesting_findings": [%'
    AND (
        findings.value LIKE '%Headers%' OR 
        findings.value LIKE '%robots.txt%' OR 
        findings.value LIKE '%XML-RPC%' OR 
        findings.value LIKE '%readme%' OR 
        findings.value LIKE '%debug.log%' OR 
        findings.value LIKE '%wp-cron%'
    );
    
---------------------------------------------------------------------------------
-- 3. wpscan - User Identification
---------------------------------------------------------------------------------

CREATE VIEW wp_user AS
SELECT 
    user.key AS username,
    json_extract(user.value, '$.found_by') AS found_by,
    json_extract(user.value, '$.confidence') AS confidence,
    json_extract(user.value, '$.interesting_entries') AS interesting_entries,
    json_extract(user.value, '$.confirmed_by') AS confirmed_by
FROM 
    uniform_resource,
    json_each(content, '$.users') AS user
WHERE 
    content LIKE '%"users": {%';

---------------------------------------------------------------------------------
-- SSLyze (plain-text views)
---------------------------------------------------------------------------------

-- Heartbleed
CREATE VIEW sslyze_heartbleed_text AS
SELECT
  CASE
    WHEN content LIKE '%"is_vulnerable_to_heartbleed": true%'  THEN 'Heartbleed: VULNERABLE'
    WHEN content LIKE '%"is_vulnerable_to_heartbleed": false%' THEN 'Heartbleed: not vulnerable'
    ELSE 'Heartbleed: unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- OpenSSL CCS Injection
CREATE VIEW sslyze_ccs_injection_text AS
SELECT
  CASE
    WHEN content LIKE '%"is_vulnerable_to_ccs_injection": true%'  THEN 'OpenSSL CCS Injection: VULNERABLE'
    WHEN content LIKE '%"is_vulnerable_to_ccs_injection": false%' THEN 'OpenSSL CCS Injection: not vulnerable'
    ELSE 'OpenSSL CCS Injection: unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- ROBOT
CREATE VIEW sslyze_robot_text AS
SELECT
  CASE
    WHEN content LIKE '%"robot_result"%NOT_VULNERABLE%' THEN 'ROBOT: not vulnerable'
    WHEN content LIKE '%"robot_result"%VULNERABLE%'     THEN 'ROBOT: VULNERABLE'
    ELSE 'ROBOT: unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- Session Renegotiation
CREATE VIEW sslyze_session_renegotiation_text AS
SELECT
  TRIM(
    (CASE
       WHEN content LIKE '%"supports_secure_renegotiation": true%'  THEN 'Secure renegotiation: supported'
       WHEN content LIKE '%"supports_secure_renegotiation": false%' THEN 'Secure renegotiation: NOT supported'
       ELSE 'Secure renegotiation: unknown'
     END)
    || ' | ' ||
    (CASE
       WHEN content LIKE '%"client_renegotiations_success_count": 0%' THEN 'Client renegotiation: none observed'
       WHEN content LIKE '%"client_renegotiations_success_count":%'    THEN 'Client renegotiation: possible'
       ELSE 'Client renegotiation: unknown'
     END)
  ) AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- Elliptic Curves / ECDH
CREATE VIEW sslyze_elliptic_curves_text AS
SELECT
  CASE
    WHEN content LIKE '%"supports_ecdh_key_exchange": true%'  THEN 'Elliptic-curve key exchange (ECDH): supported'
    WHEN content LIKE '%"supports_ecdh_key_exchange": false%' THEN 'Elliptic-curve key exchange (ECDH): NOT supported'
    ELSE 'Elliptic-curve key exchange (ECDH): unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- TLS Compression (Deflate)
CREATE VIEW sslyze_tls_compression_text AS
SELECT
  CASE
    WHEN content LIKE '%"supports_compression": true%'  OR content LIKE '%"DEFLATE"%' THEN 'TLS compression (DEFLATE): ENABLED'
    WHEN content LIKE '%"supports_compression": false%'                               THEN 'TLS compression (DEFLATE): disabled'
    ELSE 'TLS compression (DEFLATE): unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- Downgrade / Fallback SCSV
CREATE VIEW sslyze_tls_fallback_scsv_text AS
SELECT
  CASE
    WHEN content LIKE '%"supports_fallback_scsv": true%'  THEN 'TLS Fallback SCSV: present (downgrade protection)'
    WHEN content LIKE '%"supports_fallback_scsv": false%' THEN 'TLS Fallback SCSV: MISSING (potential downgrade risk)'
    ELSE 'TLS Fallback SCSV: unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

-- Extended Master Secret (EMS)
CREATE VIEW sslyze_extended_master_secret_text AS
SELECT
  CASE
    WHEN content LIKE '%supports_ems_extension": true%'  OR content LIKE '%extended_master_secret%' THEN 'Extended Master Secret (EMS): supported/reported'
    WHEN content LIKE '%supports_ems_extension": false%'                                           THEN 'Extended Master Secret (EMS): NOT supported'
    ELSE 'Extended Master Secret (EMS): unknown'
  END AS details
FROM uniform_resource
WHERE uri LIKE '%sslyze%';

---------------------------------------------------------------------------------
-- 1. HTTPX-Toolkit
---------------------------------------------------------------------------------

CREATE VIEW server_metadata AS
SELECT
    json_extract(content,'$.scheme')                          AS scheme,
    CAST(json_extract(content,'$.port') AS INTEGER)           AS port,
    json_extract(content,'$.url')                              AS url,
    COALESCE(json_extract(content,'$.input'), json_extract(content,'$.host')) AS domain,
    -- Cleaned webserver: only show nginx/Microsoft-IIS, ignore versions and extra info
    CASE
        WHEN ws LIKE 'nginx/%'         THEN 'nginx'
        WHEN ws LIKE 'Microsoft-IIS%'  THEN 'Microsoft-IIS'
    END                                                        AS server_family,
    -- Extract server version (first token after slash; trims at space or '(')
    TRIM(CASE
        WHEN ws LIKE 'nginx/%' THEN
            CASE
              WHEN instr(substr(ws,7),' ')>0 THEN substr(substr(ws,7),1,instr(substr(ws,7),' ')-1)
              WHEN instr(substr(ws,7),'(')>0 THEN substr(substr(ws,7),1,instr(substr(ws,7),'(')-1)
              ELSE substr(ws,7)

            END
        WHEN ws LIKE 'Microsoft-IIS/%' THEN substr(ws, length('Microsoft-IIS/')+1)
    END)                                                       AS server_version,
    json_extract(content,'$.host')                             AS host,
    CAST(json_extract(content,'$."status-code"') AS INTEGER)   AS status_code,
    json_extract(content,'$.method')                           AS method,
    json_extract(content,'$."response-time"')                  AS response_time,
    json_extract(content,'$.location')                         AS location,
    -- Flatten cnames (extract the first entry or display as a string)
    CASE
        WHEN json_extract(content, '$.cnames') IS NOT NULL
        THEN json_extract(content, '$.cnames[0]')
        ELSE NULL
    END                                                        AS cnames,
    -- Flatten ips_a (extract the first entry or display as a string)
    CASE
        WHEN json_extract(content, '$.a') IS NOT NULL
        THEN json_extract(content, '$.a[0]')
        ELSE NULL
    END                                                        AS ips_a,
    json_extract(content,'$.timestamp')                        AS timestamp
FROM (
    SELECT
        content,
        json_extract(content,'$.webserver') AS ws
    FROM uniform_resource
    WHERE json_valid(content)=1
) t
WHERE
    ws LIKE 'Microsoft-IIS%' -- include all IIS (version optional)
  OR (
        ws LIKE 'nginx/%'      -- include nginx only if version disclosed
        AND (
            CASE
                WHEN instr(substr(ws,8),' ')>0 THEN substr(substr(ws,8),1,instr(substr(ws,8),' ')-1)
                WHEN instr(substr(ws,8),'(')>0 THEN substr(substr(ws,8),1,instr(substr(ws,8),'(')-1)
                ELSE substr(ws,8)
            END
        ) GLOB '*[0-9]*'
    );


-- ===== WhatWeb =====

-- Combined WhatWeb results with technology information (CMS, OS, server, etc.)
CREATE VIEW whatweb_tech_summary AS
WITH rows AS (
  SELECT
    je.value AS obj
  FROM uniform_resource,
       json_each(content) AS je
  WHERE uri LIKE '%whatweb%'
)
SELECT
  json_extract(obj,'$.target')                        AS target,
  json_extract(obj,'$.http_status')                   AS http_status,
  json_extract(obj,'$.plugins.IP.string[0]')          AS ip,
  json_extract(obj,'$.plugins.HTTPServer.string[0]')  AS http_server,
  -- Common server/version plugins:
  json_extract(obj,'$.plugins."Microsoft-IIS".version[0]')      AS iis_version,
  json_extract(obj,'$.plugins."Microsoft-HTTPAPI".version[0]')  AS httpapi_version,
  COALESCE(
    json_extract(obj,'$.plugins.nginx.version[0]'),
    json_extract(obj,'$.plugins.Nginx.version[0]')
  ) AS nginx_version,
  -- OS:
  COALESCE(
    json_extract(obj,'$.plugins.HTTPServer.os[0]'),
    json_extract(obj,'$.plugins.OperatingSystem.string[0]'),
    json_extract(obj,'$.plugins.OS.string[0]')
  ) AS os,
  json_extract(obj,'$.plugins.RedirectLocation.string[0]')   AS redirect_to,
  json_extract(obj,'$.plugins."X-Powered-By".string[0]')     AS x_powered_by,
  -- Raw JSON for troubleshooting (optional)
  obj AS raw_obj
FROM rows;

-- ===== Interpretations (from Markdown in /backlog/tasks) =====

-- Create a task summary view to include all tasks (1 to 12)
CREATE VIEW task_summary_full AS
SELECT
  json_extract(content_fm_body_attrs, '$.attrs.id') AS task_id,
  json_extract(content_fm_body_attrs, '$.attrs.title') AS title,
  json_extract(content_fm_body_attrs, '$.attrs.status') AS status,
  upper(json_extract(content_fm_body_attrs, '$.attrs.priority')) AS priority,
  json_extract(content_fm_body_attrs, '$.attrs.created_date') AS created_date,
  json_extract(content_fm_body_attrs, '$.attrs.updated_date') AS updated_date,
  json_extract(content_fm_body_attrs, '$.attrs.assignee') AS assignee,
  json_extract(content_fm_body_attrs, '$.attrs.labels') AS labels,
  json_extract(content_fm_body_attrs, '$.body') AS body_md,
  
  REPLACE(
    REPLACE(
    REPLACE(
    REPLACE(
    REPLACE(
    REPLACE(
    REPLACE(
    REPLACE(
      json_extract(content_fm_body_attrs, '$.body'),
      '<!-- SECTION:DESCRIPTION:BEGIN -->', ''),
      '<!-- SECTION:DESCRIPTION:END -->', ''),
      '<!-- AC:BEGIN -->', ''),
      '<!-- AC:END -->', ''),
      '<!-- SECTION:PLAN:BEGIN -->', ''),
      '<!-- SECTION:PLAN:END -->', ''),
      '<!-- SECTION:NOTES:BEGIN -->', ''),
      '<!-- SECTION:NOTES:END -->', '') AS body_md_clean
FROM uniform_resource
WHERE content_fm_body_attrs IS NOT NULL
  AND uri LIKE '%task%';

-- CDNCheck views

-- 1. Raw / flat view: one row per json line
CREATE VIEW cdncheck_scan_result AS
SELECT
    ur.uniform_resource_id,
    json_extract(CAST(ur.content AS TEXT), '$.timestamp')          AS timestamp,
    json_extract(CAST(ur.content AS TEXT), '$.input')               AS input,
    CASE
        -- some lines have "" for ip; normalize that to NULL
        WHEN json_extract(CAST(ur.content AS TEXT), '$.ip') = '' THEN NULL
        ELSE json_extract(CAST(ur.content AS TEXT), '$.ip')
    END                                                             AS ip,
    -- json booleans come back as 0/1 from json_extract
    CASE
        WHEN json_extract(CAST(ur.content AS TEXT), '$.cloud') IN (1, 'true', 'TRUE') THEN 1
        ELSE 0
    END                                                             AS cloud,
    json_extract(CAST(ur.content AS TEXT), '$.cloud_name')          AS cloud_name
FROM uniform_resource ur
WHERE json_valid(CAST(ur.content AS TEXT))
  AND (ur.uri LIKE '%cdncheck.jsonl%' OR ur.uri LIKE '%cdncheck%');

-- 2. Helpful rollup: how many inputs per cloud
CREATE VIEW cdncheck_cloud_summary AS
SELECT
    cloud_name,
    COUNT(*)                                         AS total_entries,
    COUNT(DISTINCT input)                            AS distinct_inputs,
    COUNT(CASE WHEN ip IS NOT NULL THEN 1 END)       AS entries_with_ip
FROM cdncheck_scan_result
WHERE cloud = 1
GROUP BY cloud_name
ORDER BY total_entries DESC;



-- Base view: only valid VirusTotal JSON rows
CREATE VIEW virustotal_raw AS
SELECT
    uniform_resource_id,
    uri,
    CAST(content AS TEXT) AS json_content
FROM uniform_resource
WHERE uri LIKE '%virustotal%'
  AND json_valid(CAST(content AS TEXT));

---------------------------------------------------------------------------
-- VirusTotal domain report views
---------------------------------------------------------------------------

---------------------------------------------------------------------------
-- Detected communicating samples
-- Path: $.detected_communicating_samples[]
-- Fields: date, positives, total, sha256
---------------------------------------------------------------------------
CREATE VIEW virustotal_detected_communicating_sample AS
SELECT 
    ur.uniform_resource_id,
    json_extract(sample.value, '$.date')                       AS sample_date,
    CAST(json_extract(sample.value, '$.positives') AS INTEGER) AS positives,
    CAST(json_extract(sample.value, '$.total')     AS INTEGER) AS total,
    json_extract(sample.value, '$.sha256')                     AS sha256
FROM uniform_resource AS ur,
     json_each(CAST(ur.content AS TEXT), '$.detected_communicating_samples') AS sample
WHERE json_valid(CAST(ur.content AS TEXT))
  AND ur.uri LIKE '%virustotal%';

---------------------------------------------------------------------------
-- Resolutions
-- Path: $.resolutions[]
-- Fields: ip_address, last_resolved
---------------------------------------------------------------------------
CREATE VIEW virustotal_resolution AS
SELECT
    ur.uniform_resource_id,
    json_extract(res.value, '$.ip_address')    AS ip_address,
    json_extract(res.value, '$.last_resolved') AS last_resolved
FROM uniform_resource AS ur,
     json_each(CAST(ur.content AS TEXT), '$.resolutions') AS res
WHERE json_valid(CAST(ur.content AS TEXT))
  AND ur.uri LIKE '%virustotal%';

---------------------------------------------------------------------------
-- Subdomains
-- Path: $.subdomains[]  (array of strings)
-- IMPORTANT: value is already a plain string, so NO json_extract() here.
---------------------------------------------------------------------------
CREATE VIEW virustotal_subdomain AS
SELECT
    ur.uniform_resource_id,
    sd.value AS subdomain
FROM uniform_resource AS ur,
     json_each(CAST(ur.content AS TEXT), '$.subdomains') AS sd
WHERE json_valid(CAST(ur.content AS TEXT))
  AND ur.uri LIKE '%virustotal%';

---------------------------------------------------------------------------
-- Undetected referrer samples
-- Path: $.undetected_referrer_samples[]
-- Fields: date, positives, total, sha256
---------------------------------------------------------------------------
CREATE VIEW virustotal_undetected_referrer_sample AS
SELECT 
    ur.uniform_resource_id,
    json_extract(sample.value, '$.date')                       AS sample_date,
    CAST(json_extract(sample.value, '$.positives') AS INTEGER) AS positives,
    CAST(json_extract(sample.value, '$.total')     AS INTEGER) AS total,
    json_extract(sample.value, '$.sha256')                     AS sha256
FROM uniform_resource AS ur,
     json_each(CAST(ur.content AS TEXT), '$.undetected_referrer_samples') AS sample
WHERE json_valid(CAST(ur.content AS TEXT))
  AND ur.uri LIKE '%virustotal%';

---------------------------------------------------------------------------
-- Undetected URLs
-- Path: $.undetected_urls[]
-- Each item is an array:
--   [0] url
--   [1] sha256
--   [2] positives
--   [3] total
--   [4] scan_date
---------------------------------------------------------------------------
CREATE VIEW virustotal_undetected_url AS
SELECT
    ur.uniform_resource_id,
    json_extract(u.value, '$[0]')                   AS url,
    json_extract(u.value, '$[1]')                   AS sha256,
    CAST(json_extract(u.value, '$[2]') AS INTEGER)  AS positives,
    CAST(json_extract(u.value, '$[3]') AS INTEGER)  AS total,
    json_extract(u.value, '$[4]')                   AS scan_date
FROM uniform_resource AS ur,
     json_each(CAST(ur.content AS TEXT), '$.undetected_urls') AS u
WHERE json_valid(CAST(ur.content AS TEXT))
  AND ur.uri LIKE '%virustotal%';

---------------------------------------------------------------------------
-- Dalfox
---------------------------------------------------------------------------

-- Parsed/extracted view (only valid JSON rows)
CREATE VIEW dalfox_finding AS
SELECT
  src.uniform_resource_id,
  src.js,
  json_extract(src.js, '$.type')         AS type,
  json_extract(src.js, '$.inject_type')  AS inject_type,
  json_extract(src.js, '$.poc_type')     AS poc_type,
  json_extract(src.js, '$.method')       AS method,
  json_extract(src.js, '$.data')         AS data,
  json_extract(src.js, '$.param')        AS parameter,
  json_extract(src.js, '$.payload')      AS payload,
  json_extract(src.js, '$.evidence')     AS evidence,
  json_extract(src.js, '$.cwe')          AS cwe,
  json_extract(src.js, '$.severity')     AS severity,
  json_extract(src.js, '$.message_str')  AS message_str
FROM (
  SELECT
    uniform_resource_id,
    uri,
    substr(replace(content, '""', '"'),
           instr(replace(content, '""', '"'), '{')
          ) AS js
  FROM uniform_resource
) AS src
WHERE src.uri LIKE '%dalfox%'
  AND json_valid(src.js) = 1;




---------------------------------------------------------------------------
-- Commix
---------------------------------------------------------------------------

-- Parsed/extracted view (human-readable lines only)
CREATE VIEW commix_finding AS
WITH RECURSIVE lines AS (
  -- first line from commix.txt
  SELECT
    uri,
    1 AS line_no,
    substr(content, 1, instr(content, char(10)) - 1) AS line,
    substr(content, instr(content, char(10)) + 1)       AS rest
  FROM uniform_resource
  WHERE uri LIKE '%commix%'

  UNION ALL

  -- next lines
  SELECT
    uri,
    line_no + 1,
    substr(
      rest,
      1,
      CASE instr(rest, char(10))
        WHEN 0 THEN length(rest)
        ELSE instr(rest, char(10)) - 1
      END
    ) AS line,
    CASE instr(rest, char(10))
      WHEN 0 THEN ''
      ELSE substr(rest, instr(rest, char(10)) + 1)
    END AS rest
  FROM lines
  WHERE rest <> ''
),
filtered AS (
  -- pull out just the human-meaningful part of each line
  SELECT
    line_no,
    CASE
      WHEN line LIKE '%Fetching hostname%'      THEN substr(line, instr(line, 'Fetching hostname'))
      WHEN line LIKE '%Hostname:%'             THEN substr(line, instr(line, 'Hostname:'))
      WHEN line LIKE '%Fetching current user%' THEN substr(line, instr(line, 'Fetching current user'))
      WHEN line LIKE '%Current user:%'         THEN substr(line, instr(line, 'Current user:'))
    END AS msg_raw
  FROM lines
  WHERE line LIKE '%Fetching hostname%'
     OR line LIKE '%Hostname:%'
     OR line LIKE '%Fetching current user%'
     OR line LIKE '%Current user:%'
),
cleaned AS (
  -- strip trailing ANSI escape sequences (ESC + ...)
  SELECT
    line_no,
    CASE
      WHEN instr(msg_raw, char(27)) > 0
        THEN substr(msg_raw, 1, instr(msg_raw, char(27)) - 1)
      ELSE msg_raw
    END AS msg
  FROM filtered
)
SELECT
  line_no,
  msg
FROM cleaned;


---------------------------------------------------------------------------
-- SQLMap
---------------------------------------------------------------------------

-- SQL View to extract details from sqlmap logs
CREATE VIEW sqlmap_metadata AS
SELECT
    -- Injection type extraction
    CASE
        WHEN content LIKE '%time-based blind%' THEN 
            substr(
                content,
                instr(content, 'time-based blind'),
                instr(content, 'AND time-based blind (query SLEEP)') + 100 - instr(content, 'time-based blind')
            )
        ELSE NULL
    END AS injection_type,

    -- Payload extraction
    CASE
        WHEN content LIKE '%Payload%' THEN 
            substr(content, instr(content, 'Payload:') + 8, 200)
        ELSE NULL
    END AS payload,

    -- DBMS type extraction
    CASE
        WHEN content LIKE '%the back-end DBMS is MySQL%' THEN 
            substr(
                content,
                instr(content, 'the back-end DBMS is MySQL'),
                instr(content, 'web application technology:') - instr(content, 'the back-end DBMS is MySQL')
            )
        ELSE NULL
    END AS dbms_type,

    -- Current user extraction
    CASE
        WHEN content LIKE '%current user%' THEN 
            substr(
                content,
                instr(content, 'current user:') + 14,
                instr(content, 'current database:') - instr(content, 'current user:') - 14
            )
        ELSE NULL
    END AS current_user,

    -- Current database extraction
    CASE
        WHEN content LIKE '%current database%' THEN 
            trim(
                substr(
                    substr(content, instr(content, 'current database:') + 17), 
                    1,
                    instr(
                        substr(content, instr(content, 'current database:') + 17), 
                        '[INFO]'
                    ) - 1
                )
            )
        ELSE NULL
    END AS current_database
FROM uniform_resource
WHERE uri LIKE '%sqlmap%'
  AND (
    content LIKE '%time-based blind%'
    OR content LIKE '%Payload%'
    OR content LIKE '%the back-end DBMS is MySQL%'
    OR content LIKE '%current user%'
    OR content LIKE '%current database%'
  );

---------------------------------------------------------------------------
-- Ghauri
---------------------------------------------------------------------------

-- SQL View for extracting details from Ghauri logs (example)
CREATE VIEW ghauri_summary AS
SELECT
    -- Extracting the injection type for Ghauri tool
    CASE
        WHEN content LIKE '%MySQL >= 5.0.12 time-based blind (IF - comment)%' THEN 
            'GET parameter ''id'' appears to be ''MySQL >= 5.0.12 time-based blind (IF - comment)'' injectable'
        ELSE NULL
    END AS injection_type,

    -- Extracting the payload (unchanged from previous)
    CASE
        WHEN content LIKE '%Payload%' THEN 
            substr(content, instr(content, 'Payload:') + 8, 200)
        ELSE NULL
    END AS payload,

    -- Extracting the DBMS type for Ghauri tool
    CASE
        WHEN content LIKE '%the back-end DBMS is MySQL%' THEN 
            'back-end DBMS is ''MySQL'''
        ELSE NULL
    END AS dbms_type,

    -- Extracting the current user
    CASE
        WHEN content LIKE '%current user%' THEN 
            substr(
                content,
                instr(content, 'current user:') + 14,
                instr(content, 'current database:') - instr(content, 'current user:') - 14
            )
        ELSE NULL
    END AS current_user,

    -- Extracting the current database
    CASE
        WHEN content LIKE '%current database%' THEN 
            trim(
                substr(
                    substr(content, instr(content, 'current database:') + 17), 
                    1,
                    instr(
                        substr(content, instr(content, 'current database:') + 17), 
                        '[INFO]'
                    ) - 1
                )
            )
        ELSE NULL
    END AS current_database

FROM uniform_resource
WHERE uri LIKE '%ghauri%'
  AND (
    content LIKE '%MySQL >= 5.0.12 time-based blind (IF - comment)%'
    OR content LIKE '%Payload%'
    OR content LIKE '%the back-end DBMS is MySQL%'
    OR content LIKE '%current user%'
    OR content LIKE '%current database%'
  );


---------------------------------------------------------------------------
-- TRIVY
---------------------------------------------------------------------------

-- Base view: split Trivy report into summary table + vulnerability table
CREATE VIEW trivy_scan_result AS
SELECT
    uniform_resource_id,

    -- Report Summary (first table, including legend)
    trim(
        substr(
            content,
            instr(content, 'Report Summary'),
            instr(content, 'BackendServer/package-lock.json (npm)')
                - instr(content, 'Report Summary')
        )
    ) AS report_summary,

    -- Vulnerabilities table (second table, full block)
    trim(
        substr(
            content,
            instr(content, 'BackendServer/package-lock.json (npm)'),
            length(content) - instr(content, 'BackendServer/package-lock.json (npm)') + 1
        )
    ) AS vulnerabilities_block

FROM uniform_resource
WHERE uri LIKE '%trivy%'
  AND content LIKE '%Report Summary%'
  AND content LIKE '%BackendServer/package-lock.json (npm)%';

---------------------------------------------------------------------------
-- Report summary: one readable line per row
---------------------------------------------------------------------------

CREATE VIEW trivy_report_summary_line AS
WITH cleaned AS (
    SELECT
        uniform_resource_id,
        REPLACE(report_summary, '│', '|') AS report_summary_clean
    FROM trivy_scan_result
),
lines AS (
    SELECT
        uniform_resource_id,
        trim(value) AS line
    FROM cleaned,
         json_each(
           '["'
           || REPLACE(
                REPLACE(report_summary_clean, '"', '\"'),  -- escape quotes
                char(10), '","'                            -- split on newline
              )
           || '"]'
         )
)
SELECT
    uniform_resource_id,
    line AS report_summary_line
FROM lines
WHERE line LIKE '%|%'           -- has columns
  AND line NOT LIKE 'Legend:%'  -- skip legend text
  AND line <> '';               -- skip empty lines

---------------------------------------------------------------------------
-- Vulnerabilities: one vulnerability per row (no URLs, no borders)
---------------------------------------------------------------------------

CREATE VIEW trivy_vulnerability_line AS
WITH cleaned AS (
    SELECT
        uniform_resource_id,
        REPLACE(vulnerabilities_block, '│', '|') AS vuln_clean
    FROM trivy_scan_result
),
lines AS (
    SELECT
        uniform_resource_id,
        trim(value) AS line
    FROM cleaned,
         json_each(
           '["'
           || REPLACE(
                REPLACE(vuln_clean, '"', '\"'),   -- escape quotes
                char(10), '","'                  -- split on newline
              )
           || '"]'
         )
)
SELECT
    uniform_resource_id,
    line AS vulnerability_line
FROM lines
WHERE line LIKE '%CVE-%'              -- only real vuln rows
  AND line NOT LIKE '%https://%'      -- drop URL-only lines
  AND trim(substr(line, 2, 30)) <> '';-- ensure first column isn’t empty


---------------------------------------------------------------------------
-- WAF-BYPASS 
---------------------------------------------------------------------------

-- Base view: extract each ASCII table block per section
CREATE VIEW waf_bypass_scan_result AS
SELECT
    uniform_resource_id,
    'FALSE NEGATIVE TEST' AS section,
    trim(
        substr(
            content,
            instr(content, 'FALSE NEGATIVE TEST'),
            instr(content, 'FALSE POSITIVE TEST')
              - instr(content, 'FALSE NEGATIVE TEST')
        )
    ) AS raw_block
FROM uniform_resource
WHERE uri LIKE '%waf_bypass%'
  AND instr(content, 'FALSE NEGATIVE TEST') > 0
  AND instr(content, 'FALSE POSITIVE TEST') > 0

UNION ALL

SELECT
    uniform_resource_id,
    'FALSE POSITIVE TEST' AS section,
    trim(
        substr(
            content,
            instr(content, 'FALSE POSITIVE TEST'),
            instr(content, 'TOTAL SUMMARY')
              - instr(content, 'FALSE POSITIVE TEST')
        )
    ) AS raw_block
FROM uniform_resource
WHERE uri LIKE '%waf_bypass%'
  AND instr(content, 'FALSE POSITIVE TEST') > 0
  AND instr(content, 'TOTAL SUMMARY') > 0

UNION ALL

SELECT
    uniform_resource_id,
    'TOTAL SUMMARY' AS section,
    trim(
        substr(
            content,
            instr(content, 'TOTAL SUMMARY')
        )
    ) AS raw_block
FROM uniform_resource
WHERE uri LIKE '%waf_bypass%'
  AND instr(content, 'TOTAL SUMMARY') > 0;


-- One neat row per table line (like trivy_*_line views)
CREATE VIEW waf_bypass_summary AS
WITH cleaned AS (
    SELECT
        uniform_resource_id,
        section,
        -- normalize vertical borders to '|' for nicer display
        REPLACE(raw_block, '│', '|') AS block_clean
    FROM waf_bypass_scan_result
),
lines AS (
    SELECT
        uniform_resource_id,
        section,
        trim(value) AS line
    FROM cleaned,
         json_each(
           '["'
           || REPLACE(
                REPLACE(block_clean, '"', '\"'),   -- escape quotes
                char(10), '","'                    -- split on newline
              )
           || '"]'
         )
)
SELECT
    section,
    line AS details
FROM lines
WHERE line LIKE '%|%'      -- keep only real table/header rows
  AND line <> '';          -- drop empty lines


---------------------------------------------------------------------------
-- MISCONFIG_MAPPER VIEWS (append into stateless.sql)
---------------------------------------------------------------------------

DROP VIEW IF EXISTS misconfig_mapper_scan_result;

CREATE VIEW misconfig_mapper_scan_result AS
WITH RECURSIVE misconfig_lines (uri, entry_index, line, rest) AS (
    SELECT
        uri,
        1 AS entry_index,
        substr(content || char(10),
               1,
               instr(content || char(10), char(10)) - 1) AS line,
        substr(content || char(10),
               instr(content || char(10), char(10)) + 1) AS rest
    FROM uniform_resource
    WHERE uri LIKE '%misconfig_mapper%'

    UNION ALL

    SELECT
        uri,
        entry_index + 1,
        substr(rest, 1, instr(rest, char(10)) - 1) AS line,
        substr(rest, instr(rest, char(10)) + 1)    AS rest
    FROM misconfig_lines
    WHERE rest <> ''
)

SELECT
    -- Cleaned URL
    trim(
        replace(
            substr(
                line,
                instr(line, '"url":"') + length('"url":"'),
                instr(
                    substr(line,
                           instr(line, '"url":"') + length('"url":"')),
                    '"'
                ) - 1
            ),
            '"', ''  -- Remove the extra quotes
        )
    ) AS url,

    -- Cleaned request object
    trim(
        replace(
            substr(
                line,
                instr(line, '"request":{'),
                instr(line, ',"response":{') - instr(line, '"request":{')
            ),
            '"', ''  -- Remove quotes
        )
    ) AS request,

    -- Cleaned headers array
    trim(
        replace(
            substr(
                line,
                instr(line, '"headers":['),
                instr(line, '],"body"') - instr(line, '"headers":[') + 1
            ),
            '"', ''  -- Remove quotes
        )
    ) AS header,

    -- Cleaned body
    trim(
        replace(
            substr(
                line,
                instr(line, '"body":'),
                instr(line, ',"response":{') - instr(line, '"body":')
            ),
            '"', ''  -- Remove quotes
        )
    ) AS body,

    -- Cleaned response object
    trim(
        replace(
            substr(
                line,
                instr(line, '"response":{'),
                instr(line, ',"metadata":{') - instr(line, '"response":{')
            ),
            '"', ''  -- Remove quotes
        )
    ) AS response,

    -- Cleaned metadata object
    trim(
        replace(
            substr(
                line,
                instr(line, '"metadata":{'),
                length(line) - instr(line, '"metadata":{') + 1
            ),
            '"', ''  -- Remove quotes
        )
    ) AS metadata,

    -- Cleaned references array
    trim(
        replace(
            substr(
                line,
                instr(line, '"references":['),
                length(line) - instr(line, '"references":[') + 1
            ),
            '"', ''  -- Remove quotes
        )
    ) AS reference

FROM misconfig_lines
WHERE trim(line) <> '';


---------------------------------------------------------------------------
-- WAF Bypass
---------------------------------------------------------------------------

-- Create the view for cleaning and extracting data for vulnapi results
CREATE VIEW vulnapi_cleaned_result AS
SELECT 
    replace(
        replace(
            substr(content, 
                   instr(content, 'Language'), 
                   instr(content, 'Server') - instr(content, 'Language') + length('Server')
            ),
        '[0m', ''), 
    '[1m', '') AS cleaned_data
FROM uniform_resource
WHERE uri LIKE '%vulnapi%'

UNION ALL

SELECT 
    replace(
        replace(
            substr(content, 
                   instr(content, 'Errors:') + length('Errors:'),
                   length(content) - instr(content, 'Errors:') + 1
            ),
        '[0m', ''), 
    '[1m', '') AS cleaned_data
FROM uniform_resource
WHERE uri LIKE '%vulnapi%';


-- 1) Tool list (distinct tool names extracted from uniform_resource URIs)
DROP VIEW IF EXISTS eaa_tool_name;
CREATE VIEW eaa_tool_name AS
SELECT DISTINCT
  substr(
    uri,
    instr(uri, '/sessions/')
      + length('/sessions/')
      + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/'),
    instr(
      substr(
        uri,
        instr(uri, '/sessions/')
          + length('/sessions/')
          + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/')
      ),
      '/'
    ) - 1
  ) AS tool,
  td.description 
FROM uniform_resource ur
LEFT JOIN tool_description td
    ON td.tool = 
       substr(
         uri,
         instr(uri, '/sessions/')
           + length('/sessions/')
           + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/'),
         instr(
           substr(
             uri,
             instr(uri, '/sessions/')
               + length('/sessions/')
               + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/')
           ),
           '/'
         ) - 1
       )
WHERE uri LIKE '/opt/eaa/sessions/%/%/%'
  AND uri NOT LIKE '%/.%';   -- exclude hidden files/dirs

DROP VIEW IF EXISTS severity_issue_count;
CREATE VIEW severity_issue_count AS
SELECT
  tenant_id,
  session,
  severity,
  COUNT(*) AS total
FROM unified_tenant_finding_active
WHERE severity IS NOT NULL
GROUP BY tenant_id, session, severity;

--
DROP VIEW IF EXISTS uniform_resource_content;
CREATE VIEW uniform_resource_content AS
SELECT
    uniform_resource_id,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.template-id')
    END AS template_id,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.template-path')
    END AS template_path,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.info.name')
    END AS name,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.info.severity')
    END AS severity,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.host')
    END AS host,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.url')
    END AS url,
    CASE
      WHEN json_valid(content)
      THEN json_extract(content, '$.matched-at')
    END AS matched_at,
     substr(
      uri,
      instr(uri, '/sessions/')
        + length('/sessions/')
        + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/'),
      instr(
        substr(
          uri,
          instr(uri, '/sessions/')
            + length('/sessions/')
            + instr(substr(uri, instr(uri, '/sessions/') + length('/sessions/')), '/')
        ),
        '/'
      ) - 1
    ) AS tool_name,
    /* Markdown fields */
    TRIM(
    SUBSTR(
      content,
      INSTR(content, 'vulnerability_type:') + LENGTH('vulnerability_type:'),
      INSTR(
        SUBSTR(content, INSTR(content, 'vulnerability_type:') + LENGTH('vulnerability_type:')),
        CHAR(10)
      ) - 1
    )
    ) AS vulnerability_type,
    CASE
    WHEN NOT json_valid(content)
    AND content LIKE '%Severity:%'
    THEN
        TRIM(
        SUBSTR(
            content,
            INSTR(content, 'Severity:') + LENGTH('Severity:'),
            CASE
            WHEN INSTR(SUBSTR(content, INSTR(content, 'Severity:') + LENGTH('Severity:')), char(10)) > 0
            THEN
                INSTR(
                SUBSTR(content, INSTR(content, 'Severity:') + LENGTH('Severity:')),
                char(10)
                ) - 1
            ELSE
                LENGTH(content)
            END
        )
        )
    END AS severity_md,
        TRIM(
        SUBSTR(
        content,
        INSTR(content, 'asset:') + LENGTH('asset:'),
        INSTR(
            SUBSTR(content, INSTR(content, 'asset:') + LENGTH('asset:')),
            CHAR(10)
        ) - 1
        )
    ) AS asset,
     TRIM(
    SUBSTR(
      content,
      INSTR(content, 'asset_location:') + LENGTH('asset_location:'),
      INSTR(
        SUBSTR(content, INSTR(content, 'asset_location:') + LENGTH('asset_location:')),
        CHAR(10)
      ) - 1
    )
  ) AS asset_location,
    CASE
      WHEN NOT json_valid(content)
      THEN TRIM(
        SUBSTR(
          content,
          INSTR(content, '## HTTP Request') + LENGTH('## HTTP Request'),
          INSTR(
            SUBSTR(content, INSTR(content, '## HTTP Request') + 1),
            '##'
          ) - 1
        )
      )
    END AS http_request,

    CASE
      WHEN NOT json_valid(content)
      THEN TRIM(
        SUBSTR(
          content,
          INSTR(content, '## Proof of concept') + LENGTH('## Proof of concept'),
          INSTR(
            SUBSTR(content, INSTR(content, '## Proof of concept') + 1),
            '##'
          ) - 1
        )
      )
    END AS proof_of_concept,

    CASE
      WHEN NOT json_valid(content)
      THEN TRIM(
        SUBSTR(
          content,
          INSTR(content, '## Parameter Affected') + LENGTH('## Parameter Affected'),
          LENGTH(content)
        )
      )
    END AS affected_parameter,
    CASE
        WHEN json_valid(content) THEN 'json'
    ELSE 'markdown'
    END AS file_type
FROM uniform_resource;


DROP VIEW IF EXISTS tenant_session;
CREATE VIEW tenant_session AS
SELECT
    -- Session (derived from path)
    CASE
      WHEN uri LIKE '/opt/eaa/sessions/%' THEN
        substr(
          uri,
          instr(uri, '/opt/eaa/sessions/') + length('/opt/eaa/sessions/'),
          instr(
            substr(uri, instr(uri, '/opt/eaa/sessions/') + length('/opt/eaa/sessions/')),
            '/'
          ) - 1
        )
      WHEN uri LIKE '/results/%' THEN
        substr(
          uri,
          instr(uri, '/results/') + length('/results/'),
          instr(
            substr(uri, instr(uri, '/results/') + length('/results/')),
            '/'
          ) - 1
        )
    END AS session,

    -- Tenant Name
    MAX(
      CASE
        WHEN uri LIKE '%/.session/tenant_name.txt' THEN
          trim(replace(replace(CAST(content AS TEXT), char(10), ''), char(13), ''))
      END
    ) AS tenant,

    -- Tenant ID
    MAX(
      CASE
        WHEN uri LIKE '%/.session/tenant_id.txt' THEN
          trim(replace(replace(CAST(content AS TEXT), char(10), ''), char(13), ''))
      END
    ) AS tenant_id,

    -- Website (domains.txt)
    MAX(
      CASE
        WHEN uri LIKE '%/.session/domains.txt' THEN
          trim(replace(replace(CAST(content AS TEXT), char(10), ''), char(13), ''))
      END
    ) AS website

FROM uniform_resource
WHERE uri LIKE '%/.session/tenant_name.txt'
   OR uri LIKE '%/.session/tenant_id.txt'
   OR uri LIKE '%/.session/domains.txt'
GROUP BY session;

--

DROP VIEW IF EXISTS unified_tenant_finding;
CREATE VIEW unified_tenant_finding AS
SELECT
    x.uniform_resource_id,
    x.asset,

    /* Asset type */
    CASE
        WHEN x.asset GLOB '[0-9]*.[0-9]*.[0-9]*.[0-9]*' THEN 'ip'
        WHEN x.asset LIKE '%.%' THEN 'host'
        ELSE 'unknown'
    END AS asset_type,

    x.asset_location,
    x.vulnerability_type,
    x.severity,
    x.tool_name,
    x.tenant_id,
    x.session
FROM (
    SELECT
        b.uniform_resource_id,

        /* Asset = domain / host only */
        CASE
            WHEN b.asset_location LIKE 'https://%' THEN
                substr(substr(b.asset_location, 9), 1,
                       instr(substr(b.asset_location, 9), '/') - 1)

            WHEN b.asset_location LIKE 'http://%' THEN
                substr(substr(b.asset_location, 8), 1,
                       instr(substr(b.asset_location, 8), '/') - 1)

            ELSE b.asset_location
        END AS asset,

        b.asset_location,
        b.vulnerability_type,
        b.severity,
        b.tool_name,
        b.tenant_id,
        b.session
    FROM (
        SELECT
            ur.uniform_resource_id,
            ur.tenant_id,
            ur.session,

            /* =====================
               Asset location (FULL)
               ===================== */
            CASE
                WHEN json_valid(tc.result) THEN COALESCE(
                    json_extract(tc.result, '$.matched-at'),
                    json_extract(tc.result, '$.matched_url'),
                    json_extract(tc.result, '$.extracted_url'),
                    json_extract(tc.result, '$.endpoint'),
                    json_extract(tc.result, '$.url')
                )

                WHEN instr(lower(tc.result), 'https://') > 0 THEN
                    trim(
                        substr(
                            tc.result,
                            instr(lower(tc.result), 'https://'),
                            instr(substr(tc.result,
                                  instr(lower(tc.result), 'https://')),
                                  char(10)) - 1
                        )
                    )

                WHEN instr(lower(tc.result), 'http://') > 0 THEN
                    trim(
                        substr(
                            tc.result,
                            instr(lower(tc.result), 'http://'),
                            instr(substr(tc.result,
                                  instr(lower(tc.result), 'http://')),
                                  char(10)) - 1
                        )
                    )

                ELSE ur.uri
            END AS asset_location,

            /* Vulnerability type */
            CASE
                WHEN json_valid(tc.result) THEN COALESCE(
                    json_extract(tc.result, '$.vulnerability_type'),
                    json_extract(tc.result, '$.info.name'),
                    json_extract(tc.result, '$.template-id')
                )
                WHEN tc.result LIKE '#%' THEN
                    trim(
                        substr(
                            tc.result,
                            instr(tc.result, '#') + 1,
                            instr(substr(tc.result,
                                  instr(tc.result, '#') + 1),
                                  char(10)) - 1
                        )
                    )
                ELSE NULL
            END AS vulnerability_type,

            /* Severity */
            CASE
                WHEN json_valid(tc.result)
                     AND json_extract(tc.result, '$.info.severity') IS NOT NULL
                THEN lower(trim(json_extract(tc.result, '$.info.severity')))

                WHEN lower(tc.result) LIKE '%severity%' THEN
                    CASE
                        WHEN lower(tc.result) LIKE '%critical%' THEN 'critical'
                        WHEN lower(tc.result) LIKE '%high%'     THEN 'high'
                        WHEN lower(tc.result) LIKE '%medium%'   THEN 'medium'
                        WHEN lower(tc.result) LIKE '%low%'      THEN 'low'
                        ELSE NULL
                    END
                ELSE NULL
            END AS severity,

            tc.tool_name
        FROM eaa_tool_content tc
        JOIN session_context ur
          ON ur.uri = tc.uri
        LEFT JOIN tenant_session ts
          ON ts.session = ur.session
    ) b
) x;

DROP VIEW IF EXISTS session_context;
CREATE VIEW session_context AS
SELECT
  ts.tenant,
  ts.tenant_id,
  ts.session,
  ts.website,
  ur.uniform_resource_id,
  ur.uri,
  ur.content
FROM tenant_session ts
JOIN uniform_resource ur
  ON ur.uri LIKE '%/sessions/' || ts.session || '/%';

--
DROP TABLE IF EXISTS tool_description;

CREATE TABLE IF NOT EXISTS tool_description (
    tool TEXT PRIMARY KEY,
    description TEXT
);

INSERT INTO tool_description (tool, description) VALUES
('subfinder', 'This section summarizes subdomain enumeration results identified using Subfinder. It documents discovered subdomains associated with the target domains, helping map the organization’s external attack surface and identify potential entry points for further testing.'),

('dnsx', 'This section presents DNS resolution and validation results collected using DNSX. It verifies discovered subdomains, identifies live DNS records, and helps eliminate false positives during reconnaissance.'),

('naabu', 'This section summarizes open port discovery results generated using Naabu. It identifies exposed TCP ports across scanned hosts, helping security teams understand network exposure and prioritize deeper service-level scanning.'),

('nmap', 'This section provides detailed network and service enumeration results from Nmap. It includes open ports, detected services, service versions, operating system fingerprints, and script-based vulnerability findings that support accurate risk assessment.'),

('openssl', 'This section documents cryptographic and certificate analysis performed using OpenSSL. It includes certificate validation, protocol support checks, and cryptographic configuration details relevant to secure communications.'),

('katana', 'This section presents results from Katana web crawling and endpoint discovery. It identifies URLs, parameters, and application paths, helping expand coverage for subsequent vulnerability testing.'),

('dirsearch', 'This section summarizes directory and file enumeration results identified using Dirsearch. It highlights accessible directories, sensitive files, and exposed resources that may increase attack surface or enable further exploitation.'),

('wafw00f', 'This section reports Web Application Firewall detection results identified using Wafw00f. It identifies the presence and type of WAF protecting the target, helping tailor attack techniques and assess defensive coverage.'),

('nikto', 'This section summarizes web server vulnerabilities and misconfigurations identified using Nikto. It includes outdated software, insecure configurations, and exposed files that may pose immediate security risks.'),

('rustscan', 'This section presents high-speed port scanning results generated using RustScan. It identifies open ports quickly and feeds results into deeper scanning tools, improving reconnaissance efficiency.'),

('amass', 'This section presents comprehensive asset discovery results from Amass. It combines passive and active techniques to identify subdomains, DNS records, and infrastructure relationships, providing a broader view of the organization’s attack surface.'),

('dnsenum', 'This section documents DNS enumeration findings identified using DNSEnum. It includes DNS records, zone transfer attempts, and naming patterns that help assess DNS-level exposure.'),

('paramspider', 'This section summarizes URL and parameter discovery results identified using ParamSpider. It identifies parameters across historical and live endpoints, supporting targeted input validation and injection testing.'),

('ffuf', 'This section presents fuzzing results generated using FFUF. It documents discovered endpoints, parameters, and content through wordlist-based fuzzing, helping uncover hidden or undocumented functionality.'),

('smtp-user-enum', 'This section documents SMTP user enumeration results identified during testing. It highlights valid user accounts discovered via SMTP responses, which may increase the risk of brute-force or phishing attacks.'),

('fierce', 'This section presents DNS reconnaissance findings collected using Fierce. It includes discovered hosts, IP ranges, and DNS-related insights that contribute to understanding the external network footprint.'),

('vet', 'This section summarizes vulnerability exposure testing results identified using VET. It highlights potential weaknesses across assessed services and endpoints, supporting correlation with other automated and manual findings.'),

('nuclei', 'This section explains the security vulnerabilities that were identified by the Nuclei scanner across all the systems and domains that were tested during the assessment. For each detected issue, it clearly records the affected domain, the specific scanning template that triggered the finding, the severity level, the CVSS score, and any related CVE identifiers to establish the technical and risk context. It also includes the exact URLs where the vulnerability was observed, ensuring precise traceability for validation and remediation. In addition to basic identification details, each vulnerability is supported with a detailed technical explanation that describes the nature of the risk and how it can be exploited. To support effective risk management, every finding is further aligned with a predefined remediation priority. This prioritization enables security and engineering teams to concentrate first on the most critical threats that pose the highest risk to the organization.'),

('subzy', 'This section provides a concise summary of the findings from the Subzy subdomain takeover scan conducted during the assessment. It reports the total number of subdomains that were tested to evaluate their susceptibility to takeover attacks. The section clearly distinguishes between subdomains that were found to be vulnerable, those confirmed to be safe, and those that returned timeouts or errors during testing. It also explains how these different result categories contribute to understanding the overall exposure level of the organization’s subdomain infrastructure. This summary helps security teams quickly assess the severity of the risk and prioritize remediation efforts.'),

('testssl', 'This section provides a high-level overview of the SSL and TLS scan results to give a clear snapshot of the organization’s encryption posture. It highlights weak cipher suites, certificate issues, protocol support, and cryptographic misconfigurations that may weaken secure communications. The findings help identify urgent risks affecting data confidentiality and integrity.'),

('corsy', 'This section summarizes the results of the Corsy scan, offering an overview of Cross-Origin Resource Sharing (CORS) security across the tested hosts. It highlights insecure CORS configurations, affected endpoints, and the severity distribution of identified issues. These findings help assess the risk of unauthorized cross-origin access and data exposure.'),

('wpscan', 'This section summarizes the vulnerabilities identified in WordPress installations during the assessment. It includes WordPress core versions, vulnerable plugins or themes, fixed versions, and associated CVE identifiers. This information helps teams assess risk and prioritize patching and hardening efforts.'),

('sslyze', 'This section presents the results of SSL and TLS vulnerability tests conducted using SSLyze. It covers known cryptographic weaknesses such as Heartbleed, OpenSSL CCS Injection, and protocol-level issues. These findings help identify risks affecting encrypted communications and guide remediation.'),

('httpx-toolkit', 'This section summarizes web service and server information collected using HTTPX-Toolkit. It includes HTTP status codes, response times, server headers, and detected technologies. This information helps identify live endpoints, assess exposure, and prioritize targets for further testing.'),

('whatweb', 'This section summarizes the technologies detected using WhatWeb, providing visibility into the web application’s underlying technology stack. It identifies servers, frameworks, CMS platforms, and software versions in use. This helps detect outdated or potentially vulnerable components.'),

('cdncheck', 'This section summarizes the results of CDN and cloud infrastructure detection performed using cdncheck. It identifies CDN providers, cloud services, IP ranges, and routing details. These findings help assess dependency on third-party infrastructure and potential misconfigurations.'),

('virustotal', 'This section presents reputation and resolution data retrieved from VirusTotal. It includes IP associations, communication history, and detection metadata for analyzed artifacts. This information supports threat correlation and malware analysis.'),

('dalfox', 'This section presents parsed Cross-Site Scripting (XSS) findings identified using Dalfox. It includes vulnerable parameters, payloads used, injection types, and severity ratings. These results support validation and remediation of client-side injection risks.'),

('commix', 'This section presents command injection vulnerabilities identified using Commix. It documents exploited parameters, payloads, and execution behavior. These findings help assess the impact of server-side command execution risks.'),

('sqlmap', 'This section presents detailed SQL injection findings identified using SQLMap. It includes injection types, exploited parameters, payloads, detected database technologies, and access context. This information helps validate impact and guide remediation actions.'),

('ghauri', 'This section presents SQL injection findings identified using the Ghauri tool. It documents injection techniques, payloads, and detected database details. These results help assess database-level impact and exploitation risk.'),

('trivy', 'This section provides a concise summary of vulnerabilities identified using Trivy. It includes results from container images, filesystems, and dependencies. This information supports rapid triage and prioritization of high-risk components.'),

('waf-bypass', 'This section documents potential Web Application Firewall bypass techniques observed during testing. It explains evasion methods and affected endpoints, helping evaluate the effectiveness of existing WAF protections and guide tuning.'),

('vulnapi', 'This section presents vulnerabilities identified using the VulnAPI tool. It documents insecure API endpoints, exposed parameters, and potential authorization issues. These findings help assess API security risks and remediation priorities.'),

('misconfig-mapper', 'This section presents results generated by the Misconfig-Mapper tool, highlighting potential security misconfigurations in URLs, HTTP headers, and server responses. These findings help identify configuration-related weaknesses and guide corrective actions.'),

('burpsuite', 'This section presents findings identified using Burp Suite during manual and automated web application testing. It includes vulnerabilities related to authentication, authorization, session management, input validation, and business logic flaws. The results combine proxy-based traffic analysis, active scanning, and manual verification to provide accurate, high-confidence security findings that support effective remediation.');

CREATE TABLE IF NOT EXISTS interpretaion_task_master (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant TEXT,
    session TEXT,
    uniform_resource_id TEXT,
    title TEXT,
    description TEXT,
    status TEXT,
    priority TEXT,
    created_date TEXT,
    assignee TEXT,
    parameter_affected TEXT,
    steps_reproduced TEXT,
    bussiness_impact TEXT,
    recommentation TEXT,
    reference TEXT,
    dependencies TEXT,
    label TEXT,
    category TEXT,
    weakness TEXT
);
-- ALTER Table interpretaion_task_master ADD column owasp TEXT;
-- ALTER Table interpretaion_task_master ADD column cwe TEXT;
-- ALTER Table interpretaion_task_master ADD column cve TEXT;
-- ALTER Table interpretaion_task_master ADD column nist TEXT;
-- ALTER Table interpretaion_task_master ADD column mitre TEXT;

DROP VIEW IF EXISTS unified_tenant_finding_active;

CREATE VIEW unified_tenant_finding_active AS
SELECT f.*
FROM unified_tenant_finding f
LEFT JOIN interpretaion_task_master t
  ON t.uniform_resource_id = f.uniform_resource_id
 AND LOWER(t.status) = 'remediated'
WHERE t.uniform_resource_id IS NULL;

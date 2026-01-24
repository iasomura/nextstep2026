-- ドメイン形式の詳細調査

-- 1. jpcert_phishing_urlsの実際のドメイン形式を確認
SELECT domain FROM jpcert_phishing_urls 
WHERE status = 'SUCCESS' 
LIMIT 10;

-- 2. 部分一致で検索（jpcert）
SELECT 'jpcert' as tbl, domain FROM jpcert_phishing_urls 
WHERE domain LIKE '%komano%' OR domain LIKE '%ashleytevatia%' OR domain LIKE '%se-ce-holding%'
LIMIT 10;

-- 3. phishtank_entriesの実際のcert_domain形式を確認
SELECT cert_domain FROM phishtank_entries 
WHERE cert_status = 'SUCCESS' 
LIMIT 10;

-- 4. 部分一致で検索（phishtank）
SELECT 'phishtank' as tbl, cert_domain FROM phishtank_entries 
WHERE cert_domain LIKE '%hotmart%' OR cert_domain LIKE '%leroymerlin%'
LIMIT 10;

-- 5. 各テーブルの総件数（status=SUCCESS）
SELECT 'jpcert_phishing_urls' as tbl, COUNT(*) FROM jpcert_phishing_urls WHERE status = 'SUCCESS'
UNION ALL
SELECT 'certificates', COUNT(*) FROM certificates WHERE status = 'SUCCESS'
UNION ALL
SELECT 'phishtank_entries', COUNT(*) FROM phishtank_entries WHERE cert_status = 'SUCCESS'
UNION ALL
SELECT 'trusted_certificates', COUNT(*) FROM trusted_certificates WHERE status = 'SUCCESS';

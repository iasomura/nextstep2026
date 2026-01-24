-- ドメインのstatus確認SQL

-- 1. jpcertサンプルドメインの詳細
SELECT domain, status, cert_data IS NOT NULL as has_cert 
FROM jpcert_phishing_urls 
WHERE domain IN ('ashleytevatia.com', 'komano.co.jp', 'se-ce-holding.de');

-- 2. phishtankサンプルドメインの詳細
SELECT cert_domain, cert_status, cert_data IS NOT NULL as has_cert 
FROM phishtank_entries 
WHERE cert_domain IN ('pay.hotmart.com', 'ucc.leroymerlin.kz')
LIMIT 10;

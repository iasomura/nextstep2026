-- ドメインのstatus確認

-- jpcertドメインのstatus
SELECT domain, status FROM jpcert_phishing_urls 
WHERE domain IN ('ashleytevatia.com', 'komano.co.jp', 'se-ce-holding.de');

-- phishtankドメインのstatus
SELECT cert_domain, cert_status FROM phishtank_entries 
WHERE cert_domain = 'pay.hotmart.com'
LIMIT 5;

-- jpcert: statusなしで削除対象を再カウント
SELECT COUNT(*) as jpcert_count FROM jpcert_phishing_urls 
WHERE domain IN (
    'se-ce-holding.de', 'ashleytevatia.com', 'salmonriverfarm.com',
    'gs-breitenhagen.de', 'komano.co.jp', 'pramuangnue.com'
);

-- phishtank: cert_statusなしで削除対象を再カウント  
SELECT COUNT(*) as phishtank_count FROM phishtank_entries
WHERE cert_domain IN ('pay.hotmart.com', 'ucc.leroymerlin.kz');

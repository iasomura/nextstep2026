-- ============================================================================
-- Stage3 ラベルエラー削除SQL
-- 生成日時: 2026-01-22 11:48:06
-- 
-- 目的: Stage3 VT調査で発見したラベリングエラーをデータベースから削除
-- 
-- 削除対象:
--   FP (trusted → 実は悪意あり): 25件
--   FN jpcert (phishing → 実は正規): 16件
--   FN phishtank (phishing → 実は正規): 2件
--   FN certificates (phishing → 実は正規): 3件
--   合計: 46件
-- 
-- 検証方法: VirusTotal API調査
--   FP: VT malicious > 0 のドメイン
--   FN: VT harmless >= 60 かつ malicious = 0 のドメイン
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. trusted_certificates: 25件削除
--    理由: trustedとして登録されていたがVTでmalicious > 0
-- ============================================================================

DELETE FROM trusted_certificates
WHERE domain IN (
    'tk88.live',
    'dice-dental.asia',
    'anyday.cc',
    '2025-kra32.cc',
    'sportsentry.ne.jp',
    'gittttttttt.top',
    'clomiphene.shop',
    'rankway.pw',
    'vigilanciaweb.cl',
    'lfzjhg.com',
    'byteshort.xyz',
    'darknetonionmarkets.shop',
    'zxc3373.xyz',
    'palaugov.pw',
    'juhuadh.top',
    'bcgame.top',
    'thefreshfind.shop',
    'academy-students.info',
    '79kingg.me',
    'plumenetwork.xyz',
    'qs20k.com',
    'rentalsz.com',
    'kinguploadf2m15.xyz',
    'hydroxychloroquine.click',
    'kiyevlyanka.info'
);

-- ============================================================================
-- 2. jpcert_phishing_urls: 16件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
-- ============================================================================

DELETE FROM jpcert_phishing_urls
WHERE domain IN (
    'verdehalago.com',
    'elektrologos.net',
    'namastejapan.org',
    'apple-updateaddcard.com',
    'turutaya.com',
    'iafricafood.com',
    'japanliebe.com',
    'tjsytgg.com',
    'adikarta.net',
    'hs-supplies.co.za',
    'ironheartsecurity.com',
    'healthy-call.com',
    'rmptravelinternational.com',
    'enstp.cm',
    'studio-happyvalley.com',
    'dixielion.com'
);

-- ============================================================================
-- 3. phishtank_entries: 2件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
--    注意: このテーブルはcert_domainカラムを使用
-- ============================================================================

DELETE FROM phishtank_entries
WHERE cert_domain IN (
    'd.adroll.com',
    'businessfreedomspeakingacademy.com'
);

-- ============================================================================
-- 4. certificates: 3件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
-- ============================================================================

DELETE FROM certificates
WHERE domain IN (
    'haislife.com',
    'hvitstentimepieces.com',
    'trippleaaaclub.com'
);

COMMIT;

-- 削除確認用クエリ
-- SELECT 'trusted_certificates' as table_name, COUNT(*) as count FROM trusted_certificates;
-- SELECT 'jpcert_phishing_urls' as table_name, COUNT(*) as count FROM jpcert_phishing_urls;
-- SELECT 'phishtank_entries' as table_name, COUNT(*) as count FROM phishtank_entries;
-- SELECT 'certificates' as table_name, COUNT(*) as count FROM certificates;
-- ============================================================================
-- Stage3 ラベルエラー追加削除SQL (知識ベース拡張後)
-- 生成日時: 2026-01-24
--
-- 目的: Stage3 VT調査で発見した追加ラベリングエラーをデータベースから削除
--
-- 削除対象:
--   FN jpcert (phishing → 実は正規): 46件
--   FN certificates (phishing → 実は正規): 21件
--   FN phishtank_entries (phishing → 実は正規): 2件
--   FP trusted_certificates (正規 → 実はフィッシング): 18件
--   合計: 87件
--
-- 検証方法: VirusTotal API調査
--   FN: VT harmless >= 60 かつ malicious = 0 のドメイン
-- ============================================================================

BEGIN;

-- ============================================================================
-- 1. jpcert_phishing_urls: 46件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
-- ============================================================================

DELETE FROM jpcert_phishing_urls
WHERE domain IN (
    'aeon--jp.com',
    'apple-updateaddcard.com',
    'bethel.co.ke',
    'charlottevanloo.com',
    'ecsportstraining.com',
    'elektrologos.net',
    'enstp.cm',
    'fshanpusi.com.cn',
    'funfun-kids.com',
    'gabodevelop.net',
    'healthy-call.com',
    'hoahongden.icu',
    'hs-supplies.co.za',
    'iafricafood.com',
    'idealminer.com',
    'ijgmsp.org',
    'imars.dz',
    'ironheartsecurity.com',
    'kakujyu.com',
    'mdcaregiver.com',
    'movingmaniausa.com',
    'namastejapan.org',
    'napolincanto.com',
    'oil-rig-job.net',
    'pgcp.com.cn',
    'rmptravelinternational.com',
    'royandtammy.com',
    'saintex-sa.ch',
    'sarkariupdate.in',
    'setagaya-joho.com',
    'smbaconoha.com',
    'sofagarden.com',
    'sp-top.com',
    'studio-happyvalley.com',
    'taasl.lk',
    'tenpinpin.xsrv.jp',
    'tgv-intl.com',
    'tjsytgg.com',
    'traveldor.tn',
    'upas.club',
    'w-1.cn',
    'wrm2017.org',
    'www.letabernacle.fr',
    'www.so.com',
    'yojanadarpan.com',
    'ypzbags.com'
);

-- ============================================================================
-- 2. certificates: 21件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
-- ============================================================================

DELETE FROM certificates
WHERE domain IN (
    'ag-eco.com',
    'bkmufg.com',
    'bookmarkshades.com',
    'caitlinlassyyoga.com',
    'ccusoom.cn',
    'cekdelivery.com',
    'clivelonergan.com',
    'czgaoshun.com',
    'fsvacations.com',
    'gujuantong.com',
    'haislife.com',
    'hezehengxin.com',
    'huachuangzhuangshi.com',
    'jritpf.com',
    'mercraoi.com',
    'mjzhidai.com',
    'tepcoservuowes.com',
    'trippleaaaclub.com',
    'whzcsl.com',
    'xidianjia.com',
    'ynjfjc.com'
);

-- ============================================================================
-- 3. phishtank_entries: 2件削除
--    理由: phishingとして登録されていたがVTでharmless >= 60, malicious = 0
-- ============================================================================

DELETE FROM phishtank_entries
WHERE cert_domain IN (
    'd.adroll.com',
    'zweithaar-stachus.com'
);

-- ============================================================================
-- 4. trusted_certificates: 18件削除
--    理由: 正規として登録されていたがVTでmalicious > 0
-- ============================================================================

DELETE FROM trusted_certificates
WHERE domain IN (
    'bathing-ape.us',
    'hrctms.com',
    '606188.cc',
    'sldfgra.shop',
    'jdpsbk12.org',
    'hfengly.dk',
    'intstagram.com',
    'kinguploadf2m15.xyz',
    'baixaki.com.br',
    'sportsentry.ne.jp',
    'cytxgn.top',
    'picclick.co.uk',
    'hype-mission.buzz',
    '1337x.tw',
    'httpwg.org',
    'picclick.de',
    'canadagooseoutlet-stores.name',
    'rentalsz.com'
);

COMMIT;

-- 削除確認用クエリ
-- SELECT 'jpcert_phishing_urls' as table_name, COUNT(*) as count FROM jpcert_phishing_urls;
-- SELECT 'certificates' as table_name, COUNT(*) as count FROM certificates;
-- SELECT 'phishtank_entries' as table_name, COUNT(*) as count FROM phishtank_entries;
-- SELECT 'trusted_certificates' as table_name, COUNT(*) as count FROM trusted_certificates;

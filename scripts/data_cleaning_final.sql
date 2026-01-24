-- データクレンジング SQL（最終版）
-- 実行日: 2026-01-21
-- 目的: VirusTotal調査に基づくラベリングエラーの除去

-- ============================================================
-- 1. trusted_certificates から削除（29件）
-- 理由: VTでmalicious > 0（実際は悪意あり）
-- ============================================================

DELETE FROM trusted_certificates
WHERE domain IN (
    'talkwireless.info',
    'algopix.com',
    'mediananny.com',
    'aussie-pokies.club',
    'zigzagslot.wiki',
    '1fvpd.com',
    'sc66t.com',
    'picclick.fr',
    'xdmxw.com',
    'euchebnici.com',
    'oppa4d.sbs',
    'unique-casino-en-ligne.com',
    'zybls.com',
    'y2mate.com',
    'gjqwzzb.cn',
    'kra27s.cc',
    'subhd.tv',
    'physioneedsng.com',
    'bahiscasino491.com',
    'kralbet602.com',
    'xn--cksr0a.life',
    'bjxcykj.com',
    'bape-clothing.us',
    'america777.com',
    'yjxmfyw.com',
    'imandiri.id',
    'gooogles.site',
    'yeezy-450.com',
    'akaislot88.com'
);

-- ============================================================
-- 2. certificates から削除（26件）
-- 理由: VTでharmless>=60, malicious=0（実際は正規サイト）
-- ============================================================

DELETE FROM certificates
WHERE domain IN (
    'right-handgal.com',
    'czmv.net',
    'yizhongju.com',
    'hcolonial.com',
    'hacertech.com',
    'hpcc.org.cn',
    'gsredu.com',
    'cardscc.com',
    'divinajoias.com',
    'frenchkissmusic.com',
    'visamir.com',
    'jipiaoonline.com',
    'andreawales.com',
    'caronl.com',
    'irrisk.com.au',
    'mrw.so',
    'kaiguifs.com',
    'hroffline.com',
    'bdxhdl.com',
    'xajkhbj.com',
    'hljspys.com',
    'phanepal.org',
    'dorothygetscreative.com',
    'samedayme.com',
    'haoclass.com',
    'k-strategian.com'
);

-- ============================================================
-- 注記: jpcert_phishing_urls, phishtank_entries は該当データなし
-- ============================================================

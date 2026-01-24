-- certificatesテーブルからの削除
-- 対象: 26件

DELETE FROM certificates
WHERE status = 'SUCCESS' AND domain IN (
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

// CampusQuick Mihomo / Clash Verge Rev Override Script v2.1.0
// Prepends 47 ad-block rules for com.tmall.campus.and on every subscription update.

const CAMPUS_ADBLOCK_RULES = [
  "DOMAIN-SUFFIX,anythinktech.com,REJECT",
  "DOMAIN-SUFFIX,toponad.com,REJECT",
  "DOMAIN-SUFFIX,toponadss.com,REJECT",
  "DOMAIN-SUFFIX,beizi.biz,REJECT",
  "DOMAIN-SUFFIX,hubcloud.com.cn,REJECT",
  "DOMAIN-SUFFIX,csjplatform.com,REJECT",
  "DOMAIN-SUFFIX,ctobsnssdk.com,REJECT",
  "DOMAIN-SUFFIX,gdt.qq.com,REJECT",
  "DOMAIN-SUFFIX,ugdtimg.com,REJECT",
  "DOMAIN-SUFFIX,gdtimg.com,REJECT",
  "DOMAIN-SUFFIX,kuaishouzt.com,REJECT",
  "DOMAIN-SUFFIX,kwaizt.com,REJECT",
  "DOMAIN-SUFFIX,adkwai.com,REJECT",
  "DOMAIN-SUFFIX,adukwai.com,REJECT",
  "DOMAIN-SUFFIX,zhangyuyidong.cn,REJECT",
  "DOMAIN-SUFFIX,8ziben.com,REJECT",
  "DOMAIN-SUFFIX,adn-plus.com.cn,REJECT",
  "DOMAIN-SUFFIX,1rtb.net,REJECT",
  "DOMAIN-SUFFIX,xcultur.com,REJECT",
  "DOMAIN-SUFFIX,ndcjl.com,REJECT",
  "DOMAIN-SUFFIX,jomoxc.com,REJECT",
  "DOMAIN-SUFFIX,ubixioe.com,REJECT",
  "DOMAIN-SUFFIX,66mobi.com,REJECT",
  "DOMAIN-SUFFIX,adbiding.cn,REJECT",
  "DOMAIN-SUFFIX,sigmob.cn,REJECT",
  "DOMAIN-KEYWORD,pangolin-sdk-toutiao,REJECT",
  "DOMAIN-KEYWORD,pglstatp-toutiao,REJECT",
  "DOMAIN,log.zijieapi.com,REJECT",
  "DOMAIN,sdk.e.qq.com,REJECT",
  "DOMAIN,open.e.kuaishou.com,REJECT",
  "DOMAIN,g-api.kwai.com,REJECT",
  "DOMAIN,mobads.baidu.com,REJECT",
  "DOMAIN,mobads-logs.baidu.com,REJECT",
  "DOMAIN,nadvideo2.baidu.com,REJECT",
  "DOMAIN,wn.pos.baidu.com,REJECT",
  "DOMAIN,als.baidu.com,REJECT",
  "DOMAIN,cpro.baidustatic.com,REJECT",
  "DOMAIN,adx.ys7.com,REJECT",
  "DOMAIN,impdsp.meituan.com,REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,zijieapi.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,snssdk.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,douyin.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,bytedance.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,volces.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,bytescm.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,yximgs.com)),REJECT",
  "AND,((PROCESS-NAME,com.tmall.campus.and),(DOMAIN-SUFFIX,etoote.com)),REJECT"
];

function main(config) {
  const existing = Array.isArray(config.rules) ? config.rules : [];
  const seen = new Set(existing);
  const prefix = CAMPUS_ADBLOCK_RULES.filter((r) => !seen.has(r));
  config.rules = [...prefix, ...existing];
  return config;
}

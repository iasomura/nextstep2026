# Stage3 AI Agent Tuning Insights (2026-01-27)

## Current Performance (n=260, 1.7% of total)

| Metric | Value |
|--------|-------|
| F1 | 0.6038 |
| Recall | 0.6275 |
| Precision | 0.5818 |
| FN | 19 (7.3%) |
| FP | 23 (8.8%) |

### By Source
| Source | Total | TP | TN | FN | FP | Note |
|--------|-------|----|----|----|----|------|
| trusted | 209 | 0 | 186 | 0 | 23 | 11% FP rate - too aggressive |
| certificates | 15 | 12 | 0 | 3 | 0 | 20% miss rate |
| jpcert | 23 | 14 | 0 | 9 | 0 | 39% miss rate |
| phishtank | 13 | 6 | 0 | 7 | 0 | 54% miss rate |

---

## FP Analysis (Why False Positives)

### Pattern 1: Dangerous TLD Alone (6 cases)
- **Examples**: datasydney.icu, gorod24.online, japantour.xyz, suedtirol.info
- **Problem**: Legitimate sites on .icu, .online, .xyz, .info TLDs flagged
- **Current Behavior**: `dangerous_tld_combo` triggers when dangerous TLD + DV cert
- **Suggestion**: Dangerous TLD alone should not be sufficient; require additional signals

### Pattern 2: Random Pattern False Detection (8 cases)
- **Examples**: frmtr.com, hl-rmc.com, dsfl.hu, gjgwy.org, ztjsxy.com, rvp.cz
- **Problem**: Legitimate abbreviations/acronyms flagged as random patterns
- **Current Behavior**: Low vowel ratio (< 0.2) triggers `random_pattern`
- **Suggestion**:
  - Consider Tranco whitelist check before random pattern flag
  - ccTLD interpretation already added (rvp.cz = Czech Republic)
  - May need to relax vowel ratio threshold further

### Pattern 3: Brand Substring False Match (2 cases)
- **Examples**: asmetalwork.com.ua ("meta" detected), rinet.ru ("ekinet" fuzzy2)
- **Problem**: Common substrings or fuzzy matches on unrelated domains
- **Suggestion**: Increase minimum match quality for compound/fuzzy detection

### Pattern 4: High ML but No AI Signals (2 cases)
- **Examples**: fetisch-bdsm-kontakte.com, educationindex.com
- **Problem**: ML model gives high score but no structural/contextual risk signals
- **Note**: These are actually being caught by ML, which is correct behavior

---

## FN Analysis (Why Missed)

### Pattern 1: Low Signal Phishing (most cases)
- **Examples**: contcomexcontabilidade.com.br, vesinhgiare.com
- **Problem**: No brand, no random pattern, normal-looking domain
- **Characteristics**:
  - SAN=2 (benign indicator)
  - CRL DP present (benign indicator)
  - Free CA (weak signal)
  - Contextual score ~0.4-0.5 (below threshold)
- **Suggestion**: These may be inherently difficult to detect without URL/content analysis

### Pattern 2: ML Paradox but Still Missed
- **Examples**: mbnpk.cn, usbfsamkq.com
- **Problem**: Multiple risk signals detected but final score not high enough
- **Characteristics**:
  - Random pattern detected
  - Dangerous TLD detected
  - But SAN/CRL benign indicators cancel out risk
- **Suggestion**: When random + dangerous TLD, weight more heavily

### Pattern 3: Brand Detected but Not Flagged
- **Examples**: sitemaps.allegrolokalnie.pk ("allegro" compound)
- **Problem**: Brand detected but risk score not elevated enough
- **Suggestion**: Review brand detection → phishing logic

---

## Recommended Tuning Actions

### High Priority (FP Reduction)
1. **Relax dangerous TLD standalone trigger**
   - Current: dangerous_tld + DV cert = combo
   - Proposed: Require 2+ signals (dangerous_tld + random OR brand OR short)

2. **Improve Tranco whitelist coverage**
   - Check Tranco before random pattern detection
   - If Tranco Top 100K, suppress random_pattern flag

### Medium Priority (FN Reduction)
3. **Strengthen random + dangerous TLD combo**
   - When both present, override SAN/CRL benign indicators

4. **Review low_signal_phishing threshold**
   - Current may be too high for jpcert/phishtank sources

### Low Priority (Research)
5. **Analyze jpcert/phishtank FN patterns**
   - Why 39-54% miss rate?
   - Are these inherently harder phishing sites?

---

## Log Files for Analysis

- `fnfp_reasoning_full_20260127_005258.jsonl` - Detailed reasoning for 35 FN/FP cases
- `fnfp_logs/` - Continuous monitoring snapshots (when running)

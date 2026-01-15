# CHANGELOG - Phase 1: Configuration Externalization

**Date**: 2026-01-10
**Scope**: 02 series notebook only
**Objective**: Externalize configuration to enable automated experimentation while fixing critical issues identified in Phase 0

---

## Summary of Changes

### 1. Configuration Externalization

**Created**: `02_stage1_stage2/configs/default.yaml`
- Extracted all configuration settings from ipynb cells 0-2
- Organized into logical sections:
  - `experiment`: Visualization and evaluation knobs
  - `xgboost`: Stage1 hyperparameters
  - `route1`: Automatic threshold selection settings
  - `stage2`: Gate v2 segment_priority settings
  - `brand_keywords`: Brand extraction settings
  - `io`: Input/output paths

**Benefits**:
- Single source of truth for all settings
- Easy to create multiple configurations in `02_stage1_stage2/configs/`
- Version control friendly (human-readable YAML vs JSON diff)
- Enables automated parameter sweeps

---

### 2. Notebook Modifications

**File**: `02_main.ipynb` (located at project root)

**Changes**:

#### Cell 0 (NEW): YAML Configuration Loader
- Loads settings from `02_stage1_stage2/configs/default.yaml`
- Populates environment variables for backward compatibility
- Displays loaded settings for verification
- **Key feature**: Sets `STAGE2_SEG_INCLUDE_BRAND='1'` (was '0' in original)

#### Cell 1 (modified): Route1 Settings
- Original environment variable assignments commented out
- Now shows info message: "Route1 settings now managed by 02_stage1_stage2/configs/default.yaml"

#### Cell 2 (modified): GATEV2 Dictionary
- Original GATEV2 dictionary commented out
- Warning added: "Settings now loaded from 02_stage1_stage2/configs/default.yaml"
- Prevents duplicate/conflicting settings

#### Cell 43 (modified): Stage2 Output
- **NEW**: Explicit PENDING output generation
- Creates `results/stage2_pending_latest.csv`
- Contains all `stage2_decision == 'drop_to_auto'` samples
- Statistics display:
  - Total PENDING count
  - True Benign count (%)
  - True Phish count (%)
  - **WARNING message** about unprocessed phishing samples

---

### 3. Critical Fixes (from Phase 0 findings)

#### Fix #1: Brand Feature Enabled
**Issue**: `STAGE2_SEG_INCLUDE_BRAND='0'` causing `brand_hit=0` for all 54,672 candidates
**Fix**: Set `seg_include_brand: true` in `02_stage1_stage2/configs/default.yaml`
**Impact**: Brand keyword matching now active in Stage2 priority pool

#### Fix #2: PENDING Output Explicit
**Issue**: 49,672 PENDING samples (including 2,140 phish) had no explicit output file
**Fix**: New `stage2_pending_latest.csv` with statistics and warnings
**Impact**: Clear visibility into unprocessed samples requiring attention

---

## File Inventory

### Directory Structure (NEW)
```
nextstep/
├── 02_main.ipynb                              # Main notebook (at root)
├── 02_stage1_stage2/                          # 02 series dedicated folder
│   ├── configs/
│   │   └── default.yaml                       # Centralized configuration
│   ├── src/                                   # (Phase 2: Python modules)
│   ├── scripts/                               # (Phase 3: automation scripts)
│   └── README.md                              # Documentation
├── notebooks_archive/                         # Backup storage
│   ├── 02_*_backup_20260110.ipynb            # Original notebook backup
│   └── 02_yaml_loader_cell.py                # YAML loader reference
└── CHANGELOG_Phase1.md                        # This file
```

### New Files
- `02_main.ipynb` - Simplified notebook name at root (loads config from 02_stage1_stage2/configs/)
- `02_stage1_stage2/` - Dedicated folder for 02 series
- `02_stage1_stage2/configs/default.yaml` - Centralized configuration
- `02_stage1_stage2/README.md` - Documentation
- `notebooks_archive/` - Archive folder for backups
- `CHANGELOG_Phase1.md` - This file

### Archived Files
- `notebooks_archive/02_stage2_gatev2_..._backup_20260110.ipynb` - Original notebook backup
- `notebooks_archive/02_yaml_loader_cell.py` - YAML loader code (reference)

### Removed/Cleaned Up
- `02_config.yaml` - Moved to `02_stage1_stage2/configs/default.yaml`
- Long notebook filename - Simplified to `02_main.ipynb`

---

## Expected Output Changes (after re-run)

When the modified notebook is executed:

1. **Brand feature activation**:
   - `brand_hit` column in `gate_trace_candidates__*.csv` will have non-zero values
   - Priority pool size will increase (brand matches included)

2. **New PENDING file**:
   - `artifacts/<RUN_ID>/results/stage2_pending_latest.csv` created
   - Contains ~49,672 rows (candidates - handoff)
   - Statistics printed to console during execution

3. **Unchanged outputs** (for regression testing):
   - `stage1_decisions_latest.csv` (same)
   - `stage2_decisions_latest.csv` (same content, same structure)
   - `stage2_decisions_candidates_latest.csv` (same)
   - `handoff_candidates_latest.csv` (may change due to brand feature)
   - `route1_thresholds.json` (same)
   - `stage2_budget_eval.json` (may change due to brand feature)

---

## Backward Compatibility

✅ **Fully backward compatible**:
- All existing cell logic unchanged
- Environment variable mechanism preserved
- Original notebook backed up and functional

⚠️ **Breaking changes**:
- None for existing workflows
- If external scripts set environment variables, they will be overridden by `02_config.yaml`

---

## How to Use

### Option A: Use Modified Notebook Directly
```bash
cd /data/hdd/asomura/nextstep
jupyter notebook 02_main.ipynb
# Run all cells
```

### Option B: Modify Configuration
1. Edit `02_stage1_stage2/configs/default.yaml`
2. Change desired settings (e.g., `max_budget: 10000`)
3. Run `02_main.ipynb`
4. Compare results in `artifacts/<RUN_ID>/`

### Option C: Multiple Configurations (for sweeps)
```bash
# Create variants in configs folder
cp 02_stage1_stage2/configs/default.yaml 02_stage1_stage2/configs/budget_10k.yaml
# Edit budget_10k.yaml: change max_budget to 10000

# To use different config, edit Cell 0 in 02_main.ipynb:
# with open("02_stage1_stage2/configs/budget_10k.yaml", "r") as f:

# Or keep default and manually copy before each run:
cp 02_stage1_stage2/configs/budget_10k.yaml 02_stage1_stage2/configs/default.yaml
jupyter notebook 02_main.ipynb
# Results saved to artifacts/<RUN_ID>/
```

---

## Next Steps (Phase 2)

1. **Test execution**: Run modified notebook and verify:
   - Brand feature working (`brand_hit > 0`)
   - PENDING file created with correct statistics
   - No regressions in other outputs

2. **Budget sensitivity analysis**: Run with budgets [5k, 10k, 15k, 20k]
   - Compare PENDING Phish counts
   - Analyze cost-benefit tradeoff

3. **py化 (if approved)**: Extract core logic to Python modules for full automation

---

## Validation Checklist

Before using this configuration:

- [x] `02_stage1_stage2/configs/default.yaml` exists and is valid YAML
- [x] Original notebook backed up to `notebooks_archive/`
- [x] `02_main.ipynb` has 44 cells (original: 43)
- [x] Cell 0 contains YAML loader with correct path
- [x] Cell 1-2 have commented-out settings
- [x] Cell 43 has PENDING output code
- [x] Directory structure created (`02_stage1_stage2/`, `notebooks_archive/`)
- [ ] Ready to execute and compare with Phase 0 baseline

---

## Contact

For questions or issues with Phase 1 changes, refer to:
- Phase 0 analysis: `docs/sakusen/02_phase0.md`
- Original overview: `docs/00_overview.txt`
- System architecture: `docs/02_XGBoost_LR.txt`

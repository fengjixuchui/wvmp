#!/usr/bin/env bash
# MIT-541 水印溯源 v1 端到端验收（Git Bash 端）。
#
# 用法：scripts/watermark_e2e.sh <sample.exe>
#
# 回环断言：
#   A. protect 无水印基线（缺省零扰动路径）→ 行为一致
#   B. protect 带 [watermark]+issue_log → 行为一致 + scan 命中 Customer_A
#   C. 同水印不同 seed → scan 同 id、物理字节互异（多态语义）
#   D. 基线/原始样本 scan → 全未命中（rc=1，零误报）
#   E. 台账存在且 sha256_16 与产物吻合
#
# 退出码：0 通过；1 用法/断言失败；2 CLI 失败；3 CLI 未构建。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"

usage() { echo "usage: scripts/watermark_e2e.sh <sample.exe>" >&2; }

find_cli() {
    local d c
    d="${WVMP_BUILD_DIR:-}"
    if [[ -n "$d" && -f "$d/cli/wvmp_cli.exe" ]]; then echo "$d/cli/wvmp_cli.exe"; return 0; fi
    for c in "$repo/build/cli/wvmp_cli.exe"; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    c="$(find "$repo"/build* -type f -name wvmp_cli.exe 2>/dev/null | head -1)"
    [[ -n "$c" ]] && { echo "$c"; return 0; }
    return 1
}

die() { echo "[wm-e2e] $*" >&2; exit 1; }

[[ $# -eq 1 ]] || { usage; exit 1; }
sample="$1"
[[ -f "$sample" ]] || die "找不到样本文件: $sample"
cli="$(find_cli)" || die "未找到 wvmp_cli.exe（先构建）"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sample_win="$(cygpath -m "$sample" 2>/dev/null || echo "$sample")"
tmp_win="$(cygpath -m "$tmp" 2>/dev/null || echo "$tmp")"

wm_value="4D5A90??1A2B3C4D"
wm_id="E2E_Customer_A"

gen_cfg() { # $1=file $2=seed $3=watermark(0/1)
    cat > "$1" <<EOF
input  = "$sample_win"
output = "$tmp_win/$(basename "$1" .toml).exe"
seed   = $2

[[passes]]
name = "pe_loader"
[[passes]]
name = "marker_scan"
[[passes]]
name = "lifter"
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
    if [[ "$3" == "1" ]]; then
        cat >> "$1" <<EOF

[watermark]
id     = "$wm_id"
value  = "$wm_value"
copies = 3
issue_log = "$tmp_win/watermark_issues.tsv"
EOF
    fi
}

gen_cfg "$tmp/base.toml" 12345 0
gen_cfg "$tmp/wmA.toml" 12345 1
gen_cfg "$tmp/wmB.toml" 99999 1

cat > "$tmp/registry.toml" <<EOF
[[watermarks]]
id = "$wm_id"
value = "$wm_value"
[[watermarks]]
id = "Decoy_Customer"
value = "9F8E7D6C5B4A1122"
EOF

run_protect() { # $1=cfg
    local out rc
    out="$("$cli" protect --config "$1" 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "$out" >&2
        die "protect 失败 (rc=$rc): $1"
    fi
    echo "$out"
}

echo "[wm-e2e] CLI: $cli"
base_log="$(run_protect "$tmp/base.toml")"
wmA_log="$(run_protect "$tmp/wmA.toml")"
wmB_log="$(run_protect "$tmp/wmB.toml")"

echo "$wmA_log" | grep -q "水印 : id=$wm_id" \
    || die "protect 输出缺少水印摘要行"
echo "$wmA_log" | grep -q "水印已嵌入 padding 面 3 份 × 1 片" \
    || die "pe_writer 未披露水印嵌入 Note"

out_base="$tmp_win/base.exe"; out_a="$tmp_win/wmA.exe"; out_b="$tmp_win/wmB.exe"
[[ -f "$out_base" ]] || die "基线产物未生成"
[[ -f "$out_a" ]] || die "水印产物 A 未生成"
[[ -f "$out_b" ]] || die "水印产物 B 未生成"

# ---- scan 回环 ----
scan_out="$("$cli" scan --in "$tmp_win/wmA.exe" --registry "$tmp/registry.toml" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] || die "scan 水印副本 A 未命中 (rc=$rc): $scan_out"
echo "$scan_out" | grep -q "→ $wm_id" || die "scan A 未反查到 $wm_id: $scan_out"
echo "$scan_out" | grep -qv "Decoy" || true  # 诱饵命中与否都记录，下面只断言不误报场景

scan_b="$("$cli" scan --in "$tmp_win/wmB.exe" --registry "$tmp/registry.toml" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] || die "scan 水印副本 B 未命中 (rc=$rc): $scan_b"
echo "$scan_b" | grep -q "→ $wm_id" || die "scan B 未反查到 $wm_id: $scan_b"

scan_base="$("$cli" scan --in "$tmp_win/base.exe" --registry "$tmp/registry.toml" 2>&1)"; rc=$?
[[ $rc -eq 1 ]] || die "scan 基线副本应全未命中 rc=1 (rc=$rc): $scan_base"
echo "$scan_base" | grep -q "未命中" || die "scan 基线应报未命中: $scan_base"

scan_orig="$("$cli" scan --in "$sample_win" --registry "$tmp/registry.toml" 2>&1)"; rc=$?
[[ $rc -eq 1 ]] || die "scan 原始样本应全未命中 rc=1 (rc=$rc): $scan_orig"

# ---- 多态：同 id 不同 seed 物理字节互异 ----
cmp -s "$out_a" "$out_b" && die "不同 seed 的水印副本竟逐字节相同（通配位未随机化）"

# ---- 诱饵零误报：水印副本里不得命中 Decoy ----
if echo "$scan_out" | grep -q "Decoy"; then
    die "诱饵水印在 A 副本误命中（误匹配实证失败）"
fi

# ---- 行为一致（保护不改行为硬约束） ----
"$sample"   > "$tmp/exp.out" 2>/dev/null; exp_rc=$?
"$out_a"    > "$tmp/actA.out" 2>/dev/null; a_rc=$?
"$out_base" > "$tmp/actB.out" 2>/dev/null; b_rc=$?
cmp -s "$tmp/exp.out" "$tmp/actA.out" || die "水印副本 stdout 与原生不一致"
[[ $exp_rc == $a_rc ]] || die "水印副本退出码不一致: $exp_rc != $a_rc"
cmp -s "$tmp/exp.out" "$tmp/actB.out" || die "基线副本 stdout 与原生不一致"
[[ $exp_rc == $b_rc ]] || die "基线副本退出码不一致: $exp_rc != $b_rc"

# ---- 台账 ----
ledger="$tmp/watermark_issues.tsv"
[[ -f "$ledger" ]] || die "发行台账未生成"
[[ "$(wc -l < "$ledger")" -eq 3 ]] || die "台账应有 2 记录 + 1 表头，实得 $(wc -l < "$ledger")"
grep -q "$wm_id" "$ledger" || die "台账缺 $wm_id"
sha_a="$(sha256sum "$out_a" | cut -c1-16)"
grep -q "$sha_a" "$ledger" || die "台账缺产物 A 的 sha256_16（$sha_a）"

echo "[wm-e2e] PASS（嵌入/反查/多态/零误报/行为一致/台账 六面全过）"

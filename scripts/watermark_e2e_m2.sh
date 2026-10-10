#!/usr/bin/env bash
# MIT-541 M2 水印溯源端到端验收（Git Bash 端）：碎片分散 + junk 词流载体。
#
# 用法：scripts/watermark_e2e_m2.sh <sample.exe>
#
# 回环断言：
#   A. fragments=2 padding 碎片 → scan(同方案) 命中 + 行为一致
#   B. mode=junk（mutate 管道 + [[functions]] crypt=false 载体）→ protect
#      披露 junk 嵌入 Note → 行为一致 → scan(mode=junk) 命中
#   C. mode=both → scan 两条目（padding 碎片案/junk 案）均命中
#   D. 负例：mode=junk 无 crypt 豁免 → config 拒绝 rc=1
#
# 退出码：0 通过；1 断言失败；2 CLI 失败；3 CLI 未构建。

set -u

repo="$(cd "$(dirname "$0")/.." && pwd)"

usage() { echo "usage: scripts/watermark_e2e_m2.sh <sample.exe>" >&2; }

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

die() { echo "[wm2-e2e] $*" >&2; exit 1; }

[[ $# -eq 1 ]] || { usage; exit 1; }
sample="$1"
[[ -f "$sample" ]] || die "找不到样本文件: $sample"
cli="$(find_cli)" || die "未找到 wvmp_cli.exe（先构建）"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

sample_win="$(cygpath -m "$sample" 2>/dev/null || echo "$sample")"
tmp_win="$(cygpath -m "$tmp" 2>/dev/null || echo "$tmp")"

wm_frag_value="4D5A9011223344FF"     # 全固定：碎片两片各 8 hex 恰达下限
wm_junk_value="1122334455667788"     # 8B 全固定 → 2 块
wm_both_value="AABBCCDD00112233"

# $1=file $2=seed $3=watermark(0/1) $4=mode(-/padding/junk/both) $5=fragments $6=mutate(0/1) $7=exempt(0/1)
gen_cfg() {
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
EOF
    if [[ "$6" == "1" ]]; then
        echo '[[passes]]' >> "$1"
        echo 'name = "mutate"' >> "$1"
    fi
    cat >> "$1" <<EOF
[[passes]]
name = "virtualize"
[[passes]]
name = "stub_link"
[[passes]]
name = "pe_writer"
EOF
    if [[ "$7" == "1" ]]; then
        cat >> "$1" <<EOF

[[functions]]
name = "tick"
crypt = false
EOF
    fi
    if [[ "$3" == "1" ]]; then
        cat >> "$1" <<EOF

[watermark]
value  = "$5_value_placeholder"
mode   = "$4"
fragments = $5
EOF
    fi
}

# 值替换辅助：gen_cfg 的 [watermark].value 按 $8 注入
gen_cfg_v() { # $1=file $2=seed $3=wm $4=mode $5=fragments $6=mutate $7=exempt $8=value
    gen_cfg "$1" "$2" "$3" "$4" "$5" "$6" "$7"
    [[ -n "${8:-}" ]] && sed -i "s/$5_value_placeholder/$8/" "$1"
}

run_protect() {
    local out rc
    out="$("$cli" protect --config "$1" 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "$out" >&2
        die "protect 失败 (rc=$rc): $1"
    fi
    echo "$out"
}

echo "[wm2-e2e] CLI: $cli"

# ---- A. padding 碎片 ----
gen_cfg_v "$tmp/frag.toml" 12345 1 padding 2 0 0 "$wm_frag_value"
frag_log="$(run_protect "$tmp/frag.toml")"
echo "$frag_log" | grep -q "fragments=2" || die "摘要缺 fragments=2"
echo "$frag_log" | grep -q "水印已嵌入 padding 面 3 份 × 2 片" \
    || die "pe_writer 碎片嵌入 Note 缺失"
cat > "$tmp/reg_frag.toml" <<EOF
[[watermarks]]
id = "Frag_A"
value = "$wm_frag_value"
fragments = 2
EOF
scan="$("$cli" scan --in "$tmp_win/frag.exe" --registry "$tmp/reg_frag.toml" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] || die "A: 碎片副本 scan 未命中 (rc=$rc): $scan"
echo "$scan" | grep -q "Frag_A" || die "A: 未反查到 Frag_A"
"$sample" > "$tmp/a.exp" 2>/dev/null; arc=$?
"$tmp_win/frag.exe" > "$tmp/a.act" 2>/dev/null; aarc=$?
cmp -s "$tmp/a.exp" "$tmp/a.act" || die "A: 碎片副本 stdout 不一致"
[[ $arc == $aarc ]] || die "A: 碎片副本退出码不一致"
echo "[wm2-e2e] A. padding 碎片 PASS"

# ---- B. junk 词流载体 ----
gen_cfg_v "$tmp/junk.toml" 12345 1 junk 1 1 1 "$wm_junk_value"
junk_log="$(run_protect "$tmp/junk.toml")"
echo "$junk_log" | grep -q "mode=junk" || die "B: 摘要缺 mode=junk"
echo "$junk_log" | grep -q "junk 水印已嵌入 2 块" \
    || die "B: mutate junk 嵌入 Note 缺失"
cat > "$tmp/reg_junk.toml" <<EOF
[[watermarks]]
id = "Junk_A"
value = "$wm_junk_value"
mode = "junk"
EOF
scan="$("$cli" scan --in "$tmp_win/junk.exe" --registry "$tmp/reg_junk.toml" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] || die "B: junk 副本 scan 未命中 (rc=$rc): $scan"
echo "$scan" | grep -q "Junk_A" || die "B: 未反查到 Junk_A"
# 行为一致（junk imm 是死寄存器写，语义由 liveness 背书——真机实证）
"$tmp_win/junk.exe" > "$tmp/b.act" 2>/dev/null; barc=$?
cmp -s "$tmp/a.exp" "$tmp/b.act" || die "B: junk 副本 stdout 不一致"
[[ $arc == $barc ]] || die "B: junk 副本退出码不一致"
echo "[wm2-e2e] B. junk 词流载体 PASS"

# ---- C. both 双面 ----
gen_cfg_v "$tmp/both.toml" 12345 1 both 2 1 1 "$wm_both_value"
both_log="$(run_protect "$tmp/both.toml")"
echo "$both_log" | grep -q "mode=both" || die "C: 摘要缺 mode=both"
cat > "$tmp/reg_both.toml" <<EOF
[[watermarks]]
id = "Both_A"
value = "$wm_both_value"
mode = "both"
fragments = 2
EOF
scan="$("$cli" scan --in "$tmp_win/both.exe" --registry "$tmp/reg_both.toml" 2>&1)"; rc=$?
[[ $rc -eq 0 ]] || die "C: both 副本 scan 未命中 (rc=$rc): $scan"
echo "$scan" | grep -q "Both_A" || die "C: 未反查到 Both_A"
"$tmp_win/both.exe" > "$tmp/c.act" 2>/dev/null; carc=$?
cmp -s "$tmp/a.exp" "$tmp/c.act" || die "C: both 副本 stdout 不一致"
[[ $arc == $carc ]] || die "C: both 副本退出码不一致"
echo "[wm2-e2e] C. both 双面 PASS"

# ---- D. 负例：mode=junk 无豁免 → config 拒绝 ----
gen_cfg_v "$tmp/neg.toml" 12345 1 junk 1 1 0 "$wm_junk_value"
neg_out="$("$cli" protect --config "$tmp/neg.toml" 2>&1)"; rc=$?
[[ $rc -eq 1 ]] || die "D: 无豁免 junk 应 rc=1 (rc=$rc): $neg_out"
echo "$neg_out" | grep -q "crypt=false" || die "D: 拒绝信息未点名 crypt 豁免"
echo "[wm2-e2e] D. junk 无豁免 fail-closed PASS"

echo "[wm2-e2e] PASS（碎片/junk/both/负例 四面全过）"

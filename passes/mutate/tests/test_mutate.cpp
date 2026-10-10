// MIT-459 (mutate-v1)：mutate pass 单测——确定性、异 seed 差异、插入面
// 不变量（v1 只发 Nop：kEnableJunkMov=false 收口裁定，junk-Mov 挂账 GAPS；
// 本文件的甄别/复算机制按通用面编写，junk-Mov 翻案时直接可用）。

#include "wvmp/passes/mutate/mutate_pass.hpp"

#include "wvmp/framework/context.hpp"
#include "wvmp/framework/keys.hpp"
#include "wvmp/framework/protect_levels.hpp"
#include "wvmp/ir/insn.hpp"
#include "wvmp/ir/operand.hpp"
#include "wvmp/ir/region.hpp"
#include "wvmp/passes/pe_loader/pe_image.hpp"
#include "wvmp/wm/watermark.hpp"

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

namespace {

using wvmp::ir::BasicBlock;
using wvmp::ir::FunctionRegion;
using wvmp::ir::Insn;
using wvmp::ir::Operand;
using wvmp::ir::Reg;
using wvmp::ir::Size;
using wvmp::i64;

Insn mov_rr(Reg d, Reg s) {
    Insn i;
    i.op = wvmp::ir::Op::Mov;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::reg_(s);
    return i;
}
Insn mov_ri(Reg d, i64 imm) {
    Insn i;
    i.op = wvmp::ir::Op::Mov;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::imm_(imm);
    return i;
}
Insn add_rr(Reg d, Reg s) {
    Insn i;
    i.op = wvmp::ir::Op::Add;
    i.size = Size::S64;
    i.dst = Operand::reg_(d);
    i.src = Operand::reg_(s);
    i.updates_flags = true;
    return i;
}

FunctionRegion make_fn(const std::string& name, const std::vector<Insn>& insns,
                       wvmp::u64 base) {
    FunctionRegion fn;
    fn.name = name;
    fn.arch = wvmp::ir::Arch::X64;
    fn.begin_rva = base;
    fn.end_rva = base + 0x100;
    BasicBlock b;
    b.addr = base;
    wvmp::u64 addr = base;
    for (const Insn& i : insns) {
        Insn copy = i;
        copy.addr = addr;
        addr += 4;
        b.insns.push_back(std::move(copy));
    }
    fn.blocks.push_back(std::move(b));
    return fn;
}

// 确定性测试程序：寄存器活性链（每条读前一条的写），N 个边界。
std::vector<Insn> chain_program(int n) {
    std::vector<Insn> out;
    out.push_back(mov_ri(Reg::Rax, 1));
    for (int i = 0; i < n; ++i) {
        const Reg d = static_cast<Reg>(1 + (i % 6));  // rcx..rdi 轮转
        const Reg s = i == 0 ? Reg::Rax : static_cast<Reg>(1 + ((i - 1) % 6));
        if (i % 2 == 0)
            out.push_back(add_rr(d, s));
        else
            out.push_back(mov_rr(d, s));
    }
    return out;
}

// 序列化 IR 供比对（op/size/dst/src 粗粒度指纹）。
std::string fingerprint(const FunctionRegion& fn) {
    std::string out;
    for (const auto& b : fn.blocks)
        for (const auto& i : b.insns) {
            out += static_cast<char>(i.op);
            out += static_cast<char>(i.size);
            out += static_cast<char>(i.dst.kind);
            out += static_cast<char>(i.src.kind);
            out += static_cast<char>(i.dst.reg);
            if (i.src.kind == wvmp::ir::Operand::Kind::Imm)
                out += std::to_string(i.src.imm) + ";";
        }
    return out;
}

} // namespace

TEST(MutatePass, DeterministicSameSeed) {
    const auto prog = chain_program(20);
    wvmp::ProtectionContext a, b;
    a.seed = b.seed = 12345;
    a.functions.push_back(make_fn("f", prog, 0x1000));
    b.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pa, pb;
    pa.run(a);
    pb.run(b);
    EXPECT_EQ(fingerprint(a.functions[0]), fingerprint(b.functions[0]));
}

TEST(MutatePass, DifferentSeedDifferentMutation) {
    // 概率性断言：41 边界 × P(nop)=0.10，两 seed 同时零插入的概率
    // ≈ 0.9^80 ≈ 0.03%（确定性固定——若换密度常数后偶发相等，换种子对）。
    const auto prog = chain_program(40);
    wvmp::ProtectionContext a, b;
    a.seed = 1;
    b.seed = 99999;
    a.functions.push_back(make_fn("f", prog, 0x1000));
    b.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pa, pb;
    pa.run(a);
    pb.run(b);
    EXPECT_NE(fingerprint(a.functions[0]), fingerprint(b.functions[0]));
}

TEST(MutatePass, InsertionSurfaceInvariant) {
    // 插入面不变量（对通用插入物成立；v1 实际只产 Nop）：
    //   - 原始序列双指针匹配 = 原序完整保留（零语义删改）；
    //   - 插入物 updates_flags=false、dst ≠ rsp；
    //   - 插入 Mov 的 dst 在其边界处（仅按真实指令计算）活性为 0。
    const auto prog = chain_program(40);
    wvmp::ProtectionContext ctx;
    ctx.seed = 777;
    std::vector<Insn> orig = prog;
    {
        wvmp::u64 a = 0x1000;
        for (auto& i : orig) {
            i.addr = a;
            a += 4;
        }
    }
    ctx.functions.push_back(make_fn("f", prog, 0x1000));
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    const auto& block = ctx.functions[0].blocks[0];
    ASSERT_GT(block.insns.size(), orig.size());  // 确实插入了垃圾

    // 前向双指针：匹配原始指令（op/addr/操作数全比），不匹配者 = 插入物。
    std::vector<char> is_junk(block.insns.size(), 0);
    {
        size_t j = 0;
        for (size_t i = 0; i < block.insns.size(); ++i) {
            const Insn& m = block.insns[i];
            const bool matches =
                j < orig.size() && m.op == orig[j].op && m.addr == orig[j].addr &&
                m.dst.kind == orig[j].dst.kind && m.dst.reg == orig[j].dst.reg &&
                m.src.kind == orig[j].src.kind &&
                (m.src.kind != wvmp::ir::Operand::Kind::Imm || m.src.imm == orig[j].src.imm);
            if (matches)
                ++j;
            else
                is_junk[i] = 1;
        }
        EXPECT_EQ(j, orig.size());  // 原始序列原序完整保留
    }

    // MIT-478 (T6)：块内前向健全性——junk Mov 注入后到块尾之间，dst 不得
    // 在任何重定义之前被读（读集 = Reg 源/mem 基变址/RMW 目的 + 隐式读面
    // Call 参数与 Ret/Div/Idiv/Mul/Cmpxchg/Cdq 的 Rax）。跨块可见性由
    // pass 内区域级 CFG 反向活跃度保证（此处单块程序 = 单块，无后继）。
    {
        static const wvmp::ir::Op kRaxReaders[] = {
            wvmp::ir::Op::Call, wvmp::ir::Op::Ret, wvmp::ir::Op::Div,
            wvmp::ir::Op::Idiv, wvmp::ir::Op::Mul, wvmp::ir::Op::Cmpxchg,
            wvmp::ir::Op::Cdq};
        const auto reads = [&](const Insn& i, Reg r) {
            if (r == Reg::Flags || r == Reg::Rip) return false;
            bool rd = false;
            if (i.src.kind == wvmp::ir::Operand::Kind::Reg && i.src.reg == r) rd = true;
            if (i.src2.kind == wvmp::ir::Operand::Kind::Reg && i.src2.reg == r) rd = true;
            if (i.dst.kind == wvmp::ir::Operand::Kind::Reg && i.dst.reg == r &&
                i.updates_flags)
                rd = true;
            if (i.dst.kind == wvmp::ir::Operand::Kind::Mem) {
                if (i.dst.mem.base == r || i.dst.mem.index == r) rd = true;
            }
            if (i.src.kind == wvmp::ir::Operand::Kind::Mem) {
                if (i.src.mem.base == r || i.src.mem.index == r) rd = true;
            }
            for (auto op : kRaxReaders)
                if (i.op == op && r == Reg::Rax) rd = true;
            if (i.op == wvmp::ir::Op::Call && r == Reg::Rcx) rd = true;
            return rd;
        };
        const auto defines = [&](const Insn& i, Reg r) {
            return i.dst.kind == wvmp::ir::Operand::Kind::Reg && i.dst.reg == r &&
                   !i.updates_flags && i.op == wvmp::ir::Op::Mov;
        };
        for (size_t idx = 0; idx < block.insns.size(); ++idx) {
            const Insn& j = block.insns[idx];
            if (!is_junk[idx] || j.op != wvmp::ir::Op::Mov) continue;
            EXPECT_FALSE(j.updates_flags);
            ASSERT_EQ(j.src.kind, wvmp::ir::Operand::Kind::Imm);
            EXPECT_NE(j.dst.reg, Reg::Rsp);
            for (size_t k = idx + 1; k < block.insns.size(); ++k) {
                if (reads(block.insns[k], j.dst.reg))
                    ADD_FAILURE() << "junk dst 在块内重定义前被读 (slot "
                                  << static_cast<int>(j.dst.reg) << " @ insn " << k << ")";
                if (defines(block.insns[k], j.dst.reg)) break;
            }
        }
    }
}

// MIT-482 (T6.4)：纯定义杀/use 序回归专测——目的与自身 mem 变址重叠的
// 纯写指令（`movzx ecx, [rdx+rcx]` 实录），边界 i（该指令之前）绝不能把
// 变址槽判死。buggy 序（先 use 后 kill）曾把 rcx 误杀 → junk 注入紧邻
// 读者指令前 → VM 词流 Load 读 junk 槽作变址 → kern.md5 野指针 segfault。
TEST(MutateLiveness, PureDefKillMustNotEraseMemOperandUse) {
    Insn mov_rdx;
    mov_rdx.op = wvmp::ir::Op::Mov;
    mov_rdx.size = Size::S64;
    mov_rdx.dst = Operand::reg_(Reg::Rdx);
    mov_rdx.src = Operand::imm_(0x40);

    Insn mov_rcx;
    mov_rcx.op = wvmp::ir::Op::Mov;
    mov_rcx.size = Size::S64;
    mov_rcx.dst = Operand::reg_(Reg::Rcx);
    mov_rcx.src = Operand::imm_(3);

    // movzx ecx, byte ptr [rdx + rcx]：dst=Cx（纯写）+ 变址=Cx（读）。
    Insn load;
    load.op = wvmp::ir::Op::Load;
    load.size = Size::S8;
    load.dst = Operand::reg_(Reg::Rcx);
    wvmp::ir::MemOperand m;
    m.base = Reg::Rdx;
    m.index = Reg::Rcx;
    load.src = Operand::mem_(m);

    auto fn = make_fn("kill_order", {mov_rdx, mov_rcx, load}, 0x1000);
    const auto& block = fn.blocks[0];
    const std::vector<char> live_out(static_cast<size_t>(Reg::Count), 0);
    const std::vector<wvmp::ir::Reg> candidates = {Reg::Rcx, Reg::Rdx};
    const auto dead = wvmp::passes::dead_at_boundaries_for_test(
        block, candidates, wvmp::ir::Arch::X64, live_out);

    const auto has = [&](size_t boundary, Reg r) {
        for (wvmp::ir::Reg x : dead[boundary])
            if (x == r) return true;
        return false;
    };
    // 边界 2（Load 之前）：变址槽 Cx 与基址槽 Rdx 均被本指令读取 → 恒活。
    EXPECT_FALSE(has(2, Reg::Rcx)) << "变址槽被同指令 def-kill 误杀（MIT-482）";
    EXPECT_FALSE(has(2, Reg::Rdx));
    // 边界 1（mov rcx 之前）：rcx 由 insn1 紧邻重定义、Load 读的是新值
    // → 判死合法（junk 写入会被 insn1 覆盖，读者看到的是 insn1 的结果）。
    EXPECT_TRUE(has(1, Reg::Rcx));
    EXPECT_FALSE(has(1, Reg::Rdx));
}

TEST(MutatePass, LevelNoneSkipped) {
    // 档位 none 的函数不变异；默认档函数正常变异（30 边界 × 0.10 ≈ 确定性
    // 至少 1 插入；若密度调整后偶发为零，增大程序规模）。
    const auto prog_a = chain_program(80);
    const auto prog_b = chain_program(80);
    wvmp::ProtectionContext ctx;
    ctx.seed = 314;
    ctx.functions.push_back(make_fn("off", prog_a, 0x1000));
    ctx.functions.push_back(make_fn("on", prog_b, 0x2000));
    wvmp::ProtectRules rules;
    wvmp::FunctionProtectRule rule;
    rule.has_rva = true;
    rule.rva = 0x1000;
    rule.level = wvmp::ProtectLevel::None;
    rules.functions.push_back(rule);
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = rules;

    const std::string before_off = fingerprint(ctx.functions[0]);
    const std::string before_on = fingerprint(ctx.functions[1]);
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    EXPECT_EQ(fingerprint(ctx.functions[0]), before_off);  // none → 原样
    EXPECT_NE(fingerprint(ctx.functions[1]), before_on);   // 默认档 → 变异
}

TEST(MutatePass, EmptyBlocksNoop) {
    wvmp::ProtectionContext ctx;
    FunctionRegion fn = make_fn("empty", {}, 0x1000);
    ctx.functions.push_back(std::move(fn));
    wvmp::passes::MutatePass pass;
    pass.run(ctx);
    // 空块不插任何指令、零 Error。
    ASSERT_FALSE(ctx.functions[0].blocks.empty());
    EXPECT_TRUE(ctx.functions[0].blocks[0].insns.empty());
    EXPECT_FALSE(ctx.diag.has_errors());
}

// —— MIT-541 M2：junk-Mov 水印载体 ——————————————————————————————

namespace {

// 载体规则：name="wm_fn" crypt=false（其余默认全加密）。
wvmp::ProtectRules carrier_rules(bool exempt) {
    wvmp::ProtectRules r;
    if (exempt) {
        wvmp::FunctionProtectRule rule;
        rule.has_name = true;
        rule.name = "wm_fn";
        rule.has_crypt = true;
        rule.crypt = false;
        r.functions.push_back(rule);
    }
    // junk 100% / nop 0%：每个死边界必发一个 junk-Mov（r8..r15 全程死）。
    r.has_mutate_junk_density = true;
    r.mutate_junk_density = 100;
    r.has_mutate_density = true;
    r.mutate_density = 0;
    return r;
}

wvmp::wm::WatermarkPlan junk_plan() {
    wvmp::wm::WatermarkPlan p;
    p.watermark.id = "T";
    p.watermark.value = "4D5A9011223344FF";  // 8B → 2 块
    p.watermark.compile();
    p.mode = wvmp::wm::WatermarkMode::Junk;
    p.copies = 3;
    return p;
}

// 块值打包（与 mutate 的 wm_materialize 同构：dump[0] = imm 低字节）。
wvmp::u32 chunk_word(const wvmp::wm::Fragment& f) {
    wvmp::u32 v = 0;
    for (int b = 0; b < 4; ++b)
        v |= wvmp::u32(f.dump[size_t(b)]) << (8 * b);
    return v;
}
wvmp::u32 chunk_mask_word(const wvmp::wm::Fragment& f) {
    wvmp::u32 v = 0;
    for (int b = 0; b < 4; ++b)
        v |= wvmp::u32(f.mask[size_t(b)]) << (8 * b);
    return v;
}

} // namespace

TEST(MutateWatermark, JunkChunksCarriedInExemptFunction) {
    const auto prog = chain_program(20);
    wvmp::ProtectionContext ctx;
    ctx.seed = 12345;
    ctx.functions.push_back(make_fn("wm_fn", prog, 0x1000));
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = carrier_rules(true);
    const wvmp::wm::WatermarkPlan plan = junk_plan();
    ctx.slot<wvmp::wm::WatermarkPlan>(wvmp::kWatermark) = plan;

    wvmp::passes::MutatePass pass;
    ASSERT_NO_THROW(pass.run(ctx));

    const auto chunks = wvmp::wm::split_fragments(
        plan.watermark, plan.watermark.dump.size() / 4, 4);
    ASSERT_EQ(chunks.size(), 2u);
    // 每块至少 1 份：存在掩码匹配的 junk imm。
    for (const auto& f : chunks) {
        bool found = false;
        for (const auto& b : ctx.functions[0].blocks)
            for (const auto& i : b.insns)
                if (i.op == wvmp::ir::Op::Mov &&
                    i.src.kind == wvmp::ir::Operand::Kind::Imm &&
                    (wvmp::u32(i.src.imm) & chunk_mask_word(f)) ==
                        (chunk_word(f) & chunk_mask_word(f)))
                    found = true;
        EXPECT_TRUE(found) << "块 " << f.src_off << " 未被任何 junk imm 携带";
    }
}

TEST(MutateWatermark, NoExemptFunctionFailsClosed) {
    const auto prog = chain_program(20);
    wvmp::ProtectionContext ctx;
    ctx.seed = 12345;
    ctx.functions.push_back(make_fn("wm_fn", prog, 0x1000));
    // 无 crypt=false 豁免 → 无载体 → 全块未嵌 → fail-closed。
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = carrier_rules(false);
    ctx.slot<wvmp::wm::WatermarkPlan>(wvmp::kWatermark) = junk_plan();

    wvmp::passes::MutatePass pass;
    EXPECT_THROW(pass.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}

TEST(MutateWatermark, RngOrderUnchangedWithSlot) {
    // 同 seed：水印开/关，junk Mov 的位置与数量完全一致（rng 消费序不变
    // 的单元级实证）；仅被携带的 imm 值不同。
    const auto prog = chain_program(20);
    wvmp::ProtectionContext off, on;
    for (wvmp::ProtectionContext* c : {&off, &on}) {
        c->seed = 777;
        c->functions.push_back(make_fn("wm_fn", prog, 0x1000));
        c->slot<wvmp::ProtectRules>(wvmp::kProtectRules) = carrier_rules(true);
    }
    on.slot<wvmp::wm::WatermarkPlan>(wvmp::kWatermark) = junk_plan();
    wvmp::passes::MutatePass pass;
    off.functions[0] = make_fn("wm_fn", prog, 0x1000);
    on.functions[0] = make_fn("wm_fn", prog, 0x1000);
    pass.run(off);
    pass.run(on);

    std::vector<std::pair<size_t, Reg>> junk_off, junk_on;
    auto collect = [](const wvmp::ProtectionContext& c,
                      std::vector<std::pair<size_t, Reg>>* out) {
        size_t pos = 0;
        for (const auto& b : c.functions[0].blocks)
            for (const auto& i : b.insns) {
                if (i.op == wvmp::ir::Op::Mov &&
                    i.src.kind == wvmp::ir::Operand::Kind::Imm &&
                    i.dst.kind == wvmp::ir::Operand::Kind::Reg)
                    out->push_back({pos, i.dst.reg});
                ++pos;
            }
    };
    collect(off, &junk_off);
    collect(on, &junk_on);
    EXPECT_EQ(junk_off.size(), junk_on.size());
    for (size_t i = 0; i < junk_off.size() && i < junk_on.size(); ++i)
        EXPECT_EQ(junk_off[i], junk_on[i]) << "junk 位置/寄存器漂移 @ " << i;
}

TEST(MutateWatermark, WindowCollidingChunkFailsClosed) {
    // 撞映像窗口的固定块值 = 永不可携带（translate_mov 会把窗口内 imm 折
    // 条成 Mov(RVA)+LeaRva，chunk 字节不进词流 aux）。image_base=0x1000、
    // extent 缺省 2^32 → 窗口 [0x1000, 0x100001000)。值 "0000105011223344"：
    // 块 0 = 0x00001050 恒撞窗 → 零份 → fail-closed 抛错（拒绝产出不可见
    // 水印）。通配版（"0000??50…"）由 rng 填充多数槽在窗外、顺延可嵌，
    // 其语义由 RngOrderUnchanged + E2E 覆盖。
    wvmp::ProtectionContext ctx;
    ctx.seed = 12345;
    ctx.functions.push_back(make_fn("wm_fn", chain_program(20), 0x1000));
    ctx.slot<wvmp::ProtectRules>(wvmp::kProtectRules) = carrier_rules(true);
    wvmp::wm::WatermarkPlan plan = junk_plan();
    plan.watermark.value = "0000105011223344";
    plan.watermark.compile();
    ctx.slot<wvmp::wm::WatermarkPlan>(wvmp::kWatermark) = plan;
    wvmp::passes::PeImage img;
    img.image_base = 0x1000;
    ctx.slot<wvmp::passes::PeImage>(wvmp::passes::kImageMeta) = img;

    wvmp::passes::MutatePass pass;
    EXPECT_THROW(pass.run(ctx), std::runtime_error);
    EXPECT_TRUE(ctx.diag.has_errors());
}

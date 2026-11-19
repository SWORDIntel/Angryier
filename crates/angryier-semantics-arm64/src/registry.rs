//! Semantic registry for the handwritten A64 corpus.

use crate::*;
use angryier_arch_arm64::forms;
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ResolutionKind, SemanticError, SemanticRegistry, SemanticResolution,
};
use angryier_types::{SemanticRuleId, SemanticVersion};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Resolves a decoded A64 form to exactly one authoritative provider.
/// Registration order is not priority: every form maps to exactly one provider.
pub struct Arm64CorpusRegistry {
    providers: Vec<(u32, Arc<dyn angryier_semantics::SemanticProvider>)>,
    form_index: BTreeMap<u32, usize>,
}

impl Arm64CorpusRegistry {
    pub fn new() -> Self {
        let mut providers: Vec<(u32, Arc<dyn angryier_semantics::SemanticProvider>)> = Vec::new();
        let mut next_rule: u64 = 0;

        macro_rules! register {
            ($form:expr => $provider:expr) => {{
                let provider = $provider;
                providers.push(($form, Arc::new(provider)));
                next_rule += 1;
            }};
        }
        macro_rules! rule {
            () => {
                next_rule
            };
        }

        // Branches.
        register!(forms::B => BranchImmProvider { form: forms::B, rule: rule!(), link: false });
        register!(forms::BL => BranchImmProvider { form: forms::BL, rule: rule!(), link: true });
        for cond in 0u8..14 {
            register!(forms::B_COND_BASE + u32::from(cond) => BCondProvider { cond, rule: rule!() });
        }
        register!(forms::CBZ_W => CbzProvider { form: forms::CBZ_W, rule: rule!(), nonzero: false });
        register!(forms::CBZ_X => CbzProvider { form: forms::CBZ_X, rule: rule!(), nonzero: false });
        register!(forms::CBNZ_W => CbzProvider { form: forms::CBNZ_W, rule: rule!(), nonzero: true });
        register!(forms::CBNZ_X => CbzProvider { form: forms::CBNZ_X, rule: rule!(), nonzero: true });
        register!(forms::TBZ => TbzProvider { form: forms::TBZ, rule: rule!(), nonzero: false });
        register!(forms::TBNZ => TbzProvider { form: forms::TBNZ, rule: rule!(), nonzero: true });
        register!(forms::BR => IndirectBranchProvider { form: forms::BR, rule: rule!(), link: false });
        register!(forms::BLR => IndirectBranchProvider { form: forms::BLR, rule: rule!(), link: true });
        register!(forms::RET => IndirectBranchProvider { form: forms::RET, rule: rule!(), link: false });

        // PC-relative + wide immediates.
        register!(forms::ADR => AdrProvider { form: forms::ADR, rule: rule!(), page: false });
        register!(forms::ADRP => AdrProvider { form: forms::ADRP, rule: rule!(), page: true });
        register!(forms::MOVZ_W => WideImmProvider { form: forms::MOVZ_W, rule: rule!(), kind: 0 });
        register!(forms::MOVZ_X => WideImmProvider { form: forms::MOVZ_X, rule: rule!(), kind: 0 });
        register!(forms::MOVN_W => WideImmProvider { form: forms::MOVN_W, rule: rule!(), kind: 1 });
        register!(forms::MOVN_X => WideImmProvider { form: forms::MOVN_X, rule: rule!(), kind: 1 });
        register!(forms::MOVK_W => WideImmProvider { form: forms::MOVK_W, rule: rule!(), kind: 2 });
        register!(forms::MOVK_X => WideImmProvider { form: forms::MOVK_X, rule: rule!(), kind: 2 });

        // ALU families.
        macro_rules! alu_family {
            ($w_imm_plain:expr, $w_imm_flags:expr, $x_imm_plain:expr, $x_imm_flags:expr,
             $w_reg_plain:expr, $w_reg_flags:expr, $x_reg_plain:expr, $x_reg_flags:expr,
             $op:expr, $subtract:expr) => {{
                let family = AluFamily {
                    forms_w_imm: [$w_imm_plain, $w_imm_flags],
                    forms_x_imm: [$x_imm_plain, $x_imm_flags],
                    forms_w_reg: [$w_reg_plain, $w_reg_flags],
                    forms_x_reg: [$x_reg_plain, $x_reg_flags],
                    op: $op,
                };
                for imm in [true, false] {
                    for width in [32u64, 64u64] {
                        for flags in [false, true] {
                            let form = alu_form(&family, imm, width, flags);
                            register!(form => AluProvider {
                                form,
                                rule: rule!(),
                                op: $op,
                                flags,
                                subtract: $subtract,
                                imm,
                            });
                        }
                    }
                }
            }};
        }
        alu_family!(
            forms::ADD_W_IMM,
            forms::ADDS_W_IMM,
            forms::ADD_X_IMM,
            forms::ADDS_X_IMM,
            forms::ADD_W_REG,
            forms::ADDS_W_REG,
            forms::ADD_X_REG,
            forms::ADDS_X_REG,
            PrimitiveOp::Add,
            false
        );
        alu_family!(
            forms::SUB_W_IMM,
            forms::SUBS_W_IMM,
            forms::SUB_X_IMM,
            forms::SUBS_X_IMM,
            forms::SUB_W_REG,
            forms::SUBS_W_REG,
            forms::SUB_X_REG,
            forms::SUBS_X_REG,
            PrimitiveOp::Sub,
            true
        );

        macro_rules! logical_family {
            ($w_imm:expr, $x_imm:expr, $w_reg:expr, $x_reg:expr, $op:expr) => {{
                for (imm, form_pair) in [(true, ($w_imm, $x_imm)), (false, ($w_reg, $x_reg))] {
                    for width in [32u64, 64u64] {
                        let base_form = if width == 32 { form_pair.0 } else { form_pair.1 };
                        for flags in [false, true] {
                            if flags && !matches!($op, PrimitiveOp::And) {
                                continue;
                            }
                            let form = if flags { base_form + 2 } else { base_form };
                            register!(form => LogicalProvider {
                                form,
                                rule: rule!(),
                                op: $op,
                                flags,
                                imm,
                            });
                        }
                    }
                }
            }};
        }
        logical_family!(
            forms::AND_W_IMM,
            forms::AND_X_IMM,
            forms::AND_W_REG,
            forms::AND_X_REG,
            PrimitiveOp::And
        );
        logical_family!(
            forms::ORR_W_IMM,
            forms::ORR_X_IMM,
            forms::ORR_W_REG,
            forms::ORR_X_REG,
            PrimitiveOp::Or
        );
        logical_family!(
            forms::EOR_W_IMM,
            forms::EOR_X_IMM,
            forms::EOR_W_REG,
            forms::EOR_X_REG,
            PrimitiveOp::Xor
        );

        // Conditional select.
        for kind in 0u8..4 {
            let (w_form, x_form) = match kind {
                0 => (forms::CSEL_W, forms::CSEL_X),
                1 => (forms::CSINC_W, forms::CSINC_X),
                2 => (forms::CSINV_W, forms::CSINV_X),
                _ => (forms::CSNEG_W, forms::CSNEG_X),
            };
            register!(w_form => CselProvider { form: w_form, rule: rule!(), kind });
            register!(x_form => CselProvider { form: x_form, rule: rule!(), kind });
        }

        // Multiply-accumulate.
        register!(forms::MADD_W => MaddProvider { form: forms::MADD_W, rule: rule!(), subtract: false });
        register!(forms::MADD_X => MaddProvider { form: forms::MADD_X, rule: rule!(), subtract: false });
        register!(forms::MSUB_W => MaddProvider { form: forms::MSUB_W, rule: rule!(), subtract: true });
        register!(forms::MSUB_X => MaddProvider { form: forms::MSUB_X, rule: rule!(), subtract: true });

        // Bitfield.
        register!(forms::UBFM_W => BfmProvider { form: forms::UBFM_W, rule: rule!(), signed: false });
        register!(forms::UBFM_X => BfmProvider { form: forms::UBFM_X, rule: rule!(), signed: false });
        register!(forms::SBFM_W => BfmProvider { form: forms::SBFM_W, rule: rule!(), signed: true });
        register!(forms::SBFM_X => BfmProvider { form: forms::SBFM_X, rule: rule!(), signed: true });

        // Loads/stores (scaled, unscaled, register-offset, pairs).
        macro_rules! load_store {
            (load $form:expr, $width:expr, $sign:expr) => {
                register!($form => LoadProvider { form: $form, rule: rule!(), width: $width, sign_extend: $sign });
            };
            (load $form:expr, $width:expr) => {
                register!($form => LoadProvider { form: $form, rule: rule!(), width: $width, sign_extend: false });
            };
            (store $form:expr, $width:expr) => {
                register!($form => StoreProvider { form: $form, rule: rule!(), width: $width });
            };
        }
        load_store!(load forms::LDR_B, 8);
        load_store!(load forms::LDR_H, 16);
        load_store!(load forms::LDR_W, 32);
        load_store!(load forms::LDR_X, 64);
        load_store!(load forms::LDRSW, 32, true);
        load_store!(store forms::STR_B, 8);
        load_store!(store forms::STR_H, 16);
        load_store!(store forms::STR_W, 32);
        load_store!(store forms::STR_X, 64);
        load_store!(load forms::LDUR_B, 8);
        load_store!(load forms::LDUR_H, 16);
        load_store!(load forms::LDUR_W, 32);
        load_store!(load forms::LDUR_X, 64);
        load_store!(store forms::STUR_B, 8);
        load_store!(store forms::STUR_H, 16);
        load_store!(store forms::STUR_W, 32);
        load_store!(store forms::STUR_X, 64);
        load_store!(load forms::LDR_B_REG, 8);
        load_store!(load forms::LDR_H_REG, 16);
        load_store!(load forms::LDR_W_REG, 32);
        load_store!(load forms::LDR_X_REG, 64);
        load_store!(store forms::STR_B_REG, 8);
        load_store!(store forms::STR_H_REG, 16);
        load_store!(store forms::STR_W_REG, 32);
        load_store!(store forms::STR_X_REG, 64);
        register!(forms::LDP_W => LoadPairProvider { form: forms::LDP_W, rule: rule!(), width: 32 });
        register!(forms::LDP_X => LoadPairProvider { form: forms::LDP_X, rule: rule!(), width: 64 });
        register!(forms::STP_W => StorePairProvider { form: forms::STP_W, rule: rule!(), width: 32 });
        register!(forms::STP_X => StorePairProvider { form: forms::STP_X, rule: rule!(), width: 64 });

        // Add/subtract with carry, conditional compare, divide, multiply-long,
        // indexed loads/stores, sign-extending unscaled loads.
        for (form, subtract, flags) in [
            (forms::ADC_W, false, false),
            (forms::ADC_X, false, false),
            (forms::ADCS_W, false, true),
            (forms::ADCS_X, false, true),
            (forms::SBC_W, true, false),
            (forms::SBC_X, true, false),
            (forms::SBCS_W, true, true),
            (forms::SBCS_X, true, true),
        ] {
            register!(form => AdcProvider { form, rule: rule!(), subtract, flags });
        }
        for (form, add) in [
            (forms::CCMN_W, true),
            (forms::CCMN_X, true),
            (forms::CCMP_W, false),
            (forms::CCMP_X, false),
        ] {
            register!(form => CcProvider { form, rule: rule!(), add });
        }
        for (form, signed) in [
            (forms::UDIV_W, false),
            (forms::UDIV_X, false),
            (forms::SDIV_W, true),
            (forms::SDIV_X, true),
        ] {
            register!(form => DivProvider { form, rule: rule!(), signed });
        }
        for (form, signed, accumulate) in [
            (forms::UMULL_X, false, None),
            (forms::SMULL_X, true, None),
            (forms::UMADDL_X, false, Some(true)),
            (forms::UMSUBL_X, false, Some(false)),
            (forms::SMADDL_X, true, Some(true)),
            (forms::SMSUBL_X, true, Some(false)),
        ] {
            register!(form => MulLongProvider { form, rule: rule!(), signed, accumulate });
        }
        for (form, width, load, pre_index) in [
            (forms::LDR_B_POST, 8, true, false),
            (forms::LDR_H_POST, 16, true, false),
            (forms::LDR_W_POST, 32, true, false),
            (forms::LDR_X_POST, 64, true, false),
            (forms::STR_B_POST, 8, false, false),
            (forms::STR_H_POST, 16, false, false),
            (forms::STR_W_POST, 32, false, false),
            (forms::STR_X_POST, 64, false, false),
            (forms::LDR_W_PRE, 32, true, true),
            (forms::LDR_X_PRE, 64, true, true),
            (forms::STR_W_PRE, 32, false, true),
            (forms::STR_X_PRE, 64, false, true),
            (forms::LDR_B_PRE, 8, true, true),
            (forms::LDR_H_PRE, 16, true, true),
            (forms::STR_B_PRE, 8, false, true),
            (forms::STR_H_PRE, 16, false, true),
        ] {
            register!(form => IndexedLoadStoreProvider { form, rule: rule!(), width, load, pre_index });
        }
        for (form, width) in [
            (forms::LDURSB_W, 8),
            (forms::LDURSB_X, 8),
            (forms::LDURSH_W, 16),
            (forms::LDURSH_X, 16),
            (forms::LDURSW, 32),
        ] {
            register!(form => SignExtUnscaledLoadProvider { form, rule: rule!(), width });
        }

        // NOP/HINT/SVC.
        register!(forms::NOP => NoopProvider { form: forms::NOP, rule: rule!() });
        register!(forms::HINT => NoopProvider { form: forms::HINT, rule: rule!() });
        register!(forms::SVC => SvcProvider);

        // Extension groups (variable shifts, scalar FP, FP/SIMD memory).
        crate::registry_ext::register_all(&mut providers, &mut next_rule);

        // The final counter increment has no reader; keep the counter alive
        // so future registrations continue the rule-id sequence.
        let _ = next_rule;
        let form_index = providers
            .iter()
            .enumerate()
            .map(|(index, (form, _))| (*form, index))
            .collect::<BTreeMap<_, _>>();
        Self { providers, form_index }
    }

    pub fn provider_for(&self, form: u32) -> Option<Arc<dyn angryier_semantics::SemanticProvider>> {
        self.form_index.get(&form).map(|&index| self.providers[index].1.clone())
    }
}

impl Default for Arm64CorpusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticRegistry for Arm64CorpusRegistry {
    fn resolve(
        &self,
        insn: &dyn DecodedInstructionView,
        _version: SemanticVersion,
    ) -> Result<SemanticResolution, SemanticError> {
        if let Some(&index) = self.form_index.get(&insn.form_id()) {
            return Ok(SemanticResolution {
                kind: ResolutionKind::Override,
                rule_id: SemanticRuleId(self.providers[index].1.rule_id().0),
                semantic_version: SemanticVersion(1),
            });
        }
        Err(SemanticError::UnsupportedForm(insn.form_id()))
    }
}

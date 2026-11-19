//! Registry contributions from the extension groups. Each parallel work
//! stream registers its providers through its own module function.

use angryier_semantics::SemanticProvider;
use std::sync::Arc;

/// Registers all extension providers into `providers` and advances
/// `next_rule` for every registration.
pub(crate) fn register_all(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    crate::providers_ext::shifts::register(providers, next_rule);
    crate::providers_ext::fp::register(providers, next_rule);
    crate::providers_ext::simd::register(providers, next_rule);
    // Append new waves so existing forms retain their receipt rule identities.
    crate::providers_ext::fp::register_scvtf(providers, next_rule);
    crate::providers_ext::simd::register_dup(providers, next_rule);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_copy_and_conversion_providers_preserve_existing_receipt_ids() {
        let mut old = Vec::new();
        let mut next = 0;
        crate::providers_ext::shifts::register(&mut old, &mut next);
        crate::providers_ext::fp::register(&mut old, &mut next);
        crate::providers_ext::simd::register(&mut old, &mut next);
        let mut all = Vec::new();
        register_all(&mut all, &mut 0);
        assert_eq!(all.len(), old.len() + 15);
        for (expected, actual) in old.iter().zip(&all) {
            assert_eq!(expected.0, actual.0);
            assert_eq!(expected.1.rule_id(), actual.1.rule_id());
        }
        let mut forms: std::collections::HashSet<_> = old.iter().map(|entry| entry.0).collect();
        let mut rules: std::collections::HashSet<_> = old.iter().map(|entry| entry.1.rule_id()).collect();
        for (form, provider) in &all[old.len()..] {
            assert!(forms.insert(*form), "form collision");
            assert!(rules.insert(provider.rule_id()), "receipt collision");
        }
    }
}

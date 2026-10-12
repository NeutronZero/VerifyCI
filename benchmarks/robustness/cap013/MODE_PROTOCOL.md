# CAP-013 Protocol: Differential, Property-Based, and Mutation Benchmark (FROZEN)

**Experiment ID**: CAP-013  
**Default Seed**: 42  
**Critical Mutations**: 5 declared security/provenance fault injectors  
**Equivalent Mutations**: 1 declared benign refactoring  

## Invariants & Gates (P1-5)
1. **100% Critical Mutation Kill Rate**: Every non-equivalent critical fault injector must be detected and killed by VerifyCI verification checks.
2. **Zero Incorrect PASS**: Security and provenance invariants must never permit an unverified bypass.
3. **Deterministic Fuzz Execution**: Identical random seeds produce identical properties, diff suites, and metrics.
4. **Isolated Sandboxing**: Every mutation executes in a standalone temporary filesystem without altering repository state.

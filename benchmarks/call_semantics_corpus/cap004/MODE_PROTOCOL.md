# CAP-004 Protocol: Argument-Value / Call-Semantics Verification (FROZEN)

**Experiment ID**: CAP-004  
**Corpus SHA-256**: `305da66ef4282c7537d9d0366f5d6726acb2b5557114823298e053dbf038c064`  
**Label SHA-256**: `1733902248e7bc4dcad51c01ffe6e10e362f1a34e899317f958aa4d04d95ab59`  
**Total Cases**: 36  

## Category & Slice Distribution
- Total Cases: 36
- Verified (Positive): 13
- Fail (Rejection): 13
- Inconclusive (Dynamic/Ungrounded/Unmodeled): 10

### Slices
{
  "keyword_argument_values": 5,
  "positional_argument_values": 5,
  "argument_order_swap": 4,
  "dynamic_expression_args": 5,
  "kwargs_unpacking": 4,
  "default_arg_reliance": 4,
  "overload_receiver_context": 4,
  "call_routing_mutation": 5
}

## Core Invariants
1. **Absence of Proof is Not Proof of Compliance**:
   Dynamic runtime expressions (`os.environ.get`, `session.method()`, variable `**kwargs` / `*args`, unmodeled signatures) must route to `INCONCLUSIVE` (`established=False`), never `VERIFIED` and never false `PASS`.
2. **Call Semantics Over Graph Topology**:
   A graph edge `CALLS(caller, callee)` is necessary but not sufficient. When a contract governs argument values (e.g. `strict=True`, `verify=True`, `shell=False`), violating argument values must route to `FAIL`.
3. **Positional and Keyword Mapping**:
   Arguments must be resolved against parameter signatures. Positional arguments map to parameter indices; keyword arguments map to parameter names; default parameter values are consulted when arguments are omitted.
4. **Adversarial Argument Mutation (CAP-002 N-S4 Falsifier Resolution)**:
   Diffs modifying existing call arguments (e.g. `send_email("a")` -> `send_email("b")`, role escalation `"viewer"` -> `"admin"`) without authorization must be detected and routed to `FAIL` (or review escalation), eliminating the argument-blindness failure mode of legacy systems.
5. **Anti-Circularity**:
   Gold labels are sealed before C1 redesign implementation. No case may be altered or reclassified after observing results.

# CAP-011 Protocol: Held-Out Secret Detection (FROZEN)

**Experiment ID**: CAP-011  
**Corpus SHA-256**: `72865e81db5bbd975ec8cb1710940b5203347ca39f12334a26c7cc339bd0c57f`  
**Label SHA-256**: `9e3bbc98a9ca549f981db3f25d280663c42d2c855e556e29ae6569da2d8572b7`  
**Total Cases**: 50 (30 positive, 20 negative)  

## Slice Distribution
{
  "name_independent": 10,
  "provider_structured": 5,
  "encoded": 5,
  "connection_strings": 5,
  "private_keys": 5,
  "negatives_placeholders": 10,
  "negatives_test_fixtures": 10
}

## Gates & Invariants
1. **P0-3 Redaction Boundary**: Zero raw secret leakage into logs, reports, or results.json. cases.jsonl is the only authorized location for synthetic credentials.
2. **Name-Independent Recall >= 0.90**: Neutral variable names (x, val, temp) detected via entropy & structural patterns.
3. **Precision >= 0.99**: Negatives (documentation placeholders, UUIDs, test fixture hashes) strictly rejected.
4. **Overall Recall >= 0.95**: Comprehensive coverage of providers, encoded secrets, and private keys.

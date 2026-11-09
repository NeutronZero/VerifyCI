# verifyci.index

## Overview
The `verifyci.index` package provides fact extraction, symbol indexing, and cryptographic content-addressable storage (CAS) caching for VerifyCI per § 14. It enables demand-driven analysis, cached AST fact reuse, and fast reverse symbol lookups while enforcing cryptographic integrity over cache entries via HMAC authentication.

## Interface
- `[cache.py:validate_key_schema]`: Validates CAS key schemas to ensure tier requirements and bounded scopes.
- `[cache.py:should_sample]`: Implements the release-pinned 5/100 cache audit sampling strategy (§ 14.3).
- `[cache.py:entry_digest_and_bytes]`: Computes canonical serialized bytes and SHA-256 digest for cache entries.
- `[cache.py:entry_digest]`: Computes the SHA-256 digest of a cache entry.
- `[cache.py:compute_hmac]`: Computes HMAC-SHA256 signatures for authenticating cached artifacts.
- `[cache.py:CacheStore]`: Cryptographically authenticated content-addressable cache store supporting `get` and `put`.
- `[facts.py:FileFacts]`: Dataclass containing extracted definitions, imports, exports, and call sites for a source file.
- `[provider.py:CacheIntegrityMismatch]`: Exception raised when a cached entry fails digest or HMAC verification.
- `[provider.py:FactProvider]`: Demand-driven fact provider querying language frontends and managing cached fact lookups.
- `[symbol_index.py:SymbolIndex]`: In-memory index supporting symbol resolution, entity lookup, and reverse call graph queries.

## Invariants
- `[cache.py:CacheStore]`: Verifies both HMAC signatures and payload content hashes before returning cached facts; tampered entries raise `CacheIntegrityMismatch`.
- `[cache.py:validate_key_schema]`: Rejects unbounded or improperly scoped cache key patterns.

## Side Effects
- `[cache.py:CacheStore]`: Reads and writes cache artifacts on the local filesystem under the configured cache directory.

## Verification
- Run: `pytest`

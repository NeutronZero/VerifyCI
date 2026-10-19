from __future__ import annotations

import msgspec
import heapq
import math
import re
import math
import struct
from typing import Any, Sequence

from verifyci_v2.store.model2vec_embed import StaticModel2VecEmbedder

_WORD_RE = re.compile(r"[A-Za-z0-9_]+")


class RaBitQVectorEntry(msgspec.Struct, frozen=True, kw_only=True):
    """
    Stores a 1-bit quantized representation of a D-dimensional unit vector v in {-1/sqrt(D), +1/sqrt(D)}^D
    packed into a Python arbitrary-precision int bitset, along with the exact alignment factor <v, v_bar>
    and residual norm sqrt(1 - <v, v_bar>^2) for analytical upper-bound pruning.
    """

    node_uid: str
    qualified_name: str
    packed_bits: int
    dimension: int
    alignment_factor: float  # <v, v_bar> in (0, 1]
    residual_norm: float  # sqrt(max(0, 1 - <v, v_bar>^2))
    coverage_weight: float
    exact_vector: tuple[float, ...]


class RaBitQSearchResult(msgspec.Struct, frozen=True, kw_only=True):
    node_uid: str
    qualified_name: str
    estimated_ip: float
    error_bound: float
    exact_score: float
    hybrid_rrf_score: float
    was_pruned_from_rerank: bool


class RaBitQQueryStats(msgspec.Struct, frozen=True, kw_only=True):
    results: tuple[RaBitQSearchResult, ...]
    total_candidates: int
    pruned_by_error_bound: int
    evaluated_exact_count: int
    scan_mode: str = "linear_bitwise_scan"
    quantized_bytes: int = 0
    exact_float_bytes: int = 0


def pack_rabitq_sign_bits(vec: Sequence[float]) -> tuple[bytes, int]:
    """Canonical little-endian 64-bit RaBitQ sign-bit packing shared by all stores."""
    dim = len(vec)
    if dim <= 0:
        raise ValueError("RaBitQ vector dimension must be >= 1")
    if any(not math.isfinite(float(value)) for value in vec):
        raise ValueError("RaBitQ vector values must be finite")
    num_words = (dim + 63) // 64
    words = [0] * num_words
    for idx, value in enumerate(vec):
        if value >= 0.0:
            words[idx // 64] |= 1 << (idx % 64)
    packed_bytes = struct.pack(f"<{num_words}Q", *words)
    return packed_bytes, int.from_bytes(packed_bytes, "little")


def quantize_unit_vector_rabitq(
    node_uid: str,
    qualified_name: str,
    unit_vec: Sequence[float],
    *,
    coverage_weight: float = 1.0,
    retain_exact: bool = True,
) -> RaBitQVectorEntry:
    """
    Quantizes a normalized D-dimensional vector into a 1-bit RaBitQ representation
    and precomputes its projection alignment factor and theoretical error bound parameters.
    """
    dim = len(unit_vec)
    if dim <= 0:
        raise ValueError("RaBitQ vector dimension must be >= 1")
    _packed_bytes, packed = pack_rabitq_sign_bits(unit_vec)
    inv_sqrt_d = 1.0 / math.sqrt(dim)
    dot_v_vbar = 0.0

    for idx, val in enumerate(unit_vec):
        if val >= 0.0:
            dot_v_vbar += val * inv_sqrt_d
        else:
            dot_v_vbar -= val * inv_sqrt_d

    # Clamp alignment factor to avoid numerical drift
    alignment = max(1e-6, min(1.0, dot_v_vbar))
    residual = math.sqrt(max(0.0, 1.0 - alignment * alignment))
    return RaBitQVectorEntry(
        node_uid=node_uid,
        qualified_name=qualified_name,
        packed_bits=packed,
        dimension=dim,
        alignment_factor=alignment,
        residual_norm=residual,
        coverage_weight=coverage_weight,
        exact_vector=tuple(unit_vec) if retain_exact else (),
    )


class RaBitQHybridIndex:
    """
    Layer 4 Vector & Lexical Retrieval Index combining:
    1. 1-Bit RaBitQ inner-product estimation via bitwise XOR + bit_count() (POPCNT).
    2. Analytical error-bound pruning that skips exact reranking when s_hat + epsilon < S_k*.
    3. BM25 lexical inverted index + dynamic coverage weighting.
    """

    def __init__(
        self,
        embedder: StaticModel2VecEmbedder | None = None,
        retain_exact_vectors: bool = True,
        cpg_store: Any | None = None,
    ) -> None:
        self.embedder = embedder or StaticModel2VecEmbedder(dimension=128)
        self.retain_exact_vectors = retain_exact_vectors
        self.cpg_store = cpg_store
        self._entries: dict[str, RaBitQVectorEntry] = {}
        self._doc_tokens: dict[str, dict[str, int]] = {}
        self._doc_lengths: dict[str, int] = {}
        self._doc_freqs: dict[str, int] = {}
        self._postings: dict[str, list[tuple[str, int]]] = {}
        self._avg_dl: float = 1.0
        # Corpus statistics are rebuilt lazily: recomputing them on every
        # upsert makes bulk indexing quadratic in the document count.
        self._globals_dirty: bool = False
        self._quantized_bytes: int = 0
        self._exact_float_bytes: int = 0

    def upsert_document(
        self,
        node_uid: str,
        qualified_name: str,
        enriched_text: str,
        *,
        coverage_hit_freq: float = 0.0,
    ) -> RaBitQVectorEntry:
        unit_vec = self.embedder.embed_one(enriched_text)
        if self.cpg_store is not None:
            self.cpg_store.upsert_rabitq_embedding(node_uid, qualified_name, unit_vec)
        cov_weight = 1.0 + math.log1p(max(0.0, coverage_hit_freq))
        entry = quantize_unit_vector_rabitq(
            node_uid=node_uid,
            qualified_name=qualified_name,
            unit_vec=unit_vec,
            coverage_weight=cov_weight,
            retain_exact=self.retain_exact_vectors,
        )
        old_entry = self._entries.get(node_uid)
        if old_entry is not None:
            self._quantized_bytes -= (((old_entry.dimension + 63) // 64) * 8) + 16
            self._exact_float_bytes -= len(old_entry.exact_vector) * 8

        self._entries[node_uid] = entry
        self._quantized_bytes += (((entry.dimension + 63) // 64) * 8) + 16
        self._exact_float_bytes += len(entry.exact_vector) * 8

        # Update BM25 token statistics
        tokens = [w.lower() for w in _WORD_RE.findall(enriched_text)]
        tf_map: dict[str, int] = {}
        for t in tokens:
            tf_map[t] = tf_map.get(t, 0) + 1
        self._doc_tokens[node_uid] = tf_map
        self._doc_lengths[node_uid] = max(1, len(tokens))
        self._globals_dirty = True
        return entry

    def _recompute_bm25_globals(self) -> None:
        self._doc_freqs.clear()
        self._postings.clear()
        total_len = 0
        for uid, tf_map in self._doc_tokens.items():
            total_len += self._doc_lengths[uid]
            for term, tf in tf_map.items():
                self._doc_freqs[term] = self._doc_freqs.get(term, 0) + 1
                if term not in self._postings:
                    self._postings[term] = []
                self._postings[term].append((uid, tf))
        n_docs = len(self._doc_tokens)
        self._avg_dl = (total_len / n_docs) if n_docs > 0 else 1.0
        self._globals_dirty = False

    def _ensure_globals(self) -> None:
        if self._globals_dirty:
            self._recompute_bm25_globals()

    def _bm25_score(self, query_terms: list[str], node_uid: str) -> float:
        self._ensure_globals()
        tf_map = self._doc_tokens.get(node_uid, {})
        if not tf_map:
            return 0.0
        n_docs = len(self._doc_tokens)
        dl = self._doc_lengths[node_uid]
        k1 = 1.5
        b = 0.75
        score = 0.0
        for term in query_terms:
            tf = tf_map.get(term, 0)
            if tf == 0:
                continue
            df = self._doc_freqs.get(term, 0)
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            denom = tf + k1 * (1.0 - b + b * (dl / self._avg_dl))
            score += idf * ((tf * (k1 + 1.0)) / denom)
        return score

    def search(
        self,
        query_text: str,
        *,
        top_k: int = 5,
        confidence_z: float = 3.89,  # >99.99% normal concentration bound
    ) -> RaBitQQueryStats:
        q_bytes = self._quantized_bytes
        f_bytes = self._exact_float_bytes

        if not self._entries:
            return RaBitQQueryStats(
                results=(),
                total_candidates=0,
                pruned_by_error_bound=0,
                evaluated_exact_count=0,
                scan_mode="linear_bitwise_scan",
                quantized_bytes=q_bytes,
                exact_float_bytes=f_bytes,
            )

        q_vec = self.embedder.embed_one(query_text)
        q_entry = quantize_unit_vector_rabitq("query", "query", q_vec)
        dim = self.embedder.dimension
        inv_sqrt_d = 1.0 / math.sqrt(dim)

        # Pass 1: Fast 1-bit XOR + POPCNT inner product estimation & error bound computation
        estimates: list[tuple[RaBitQVectorEntry, float, float]] = []
        for entry in self._entries.values():
            xor_bits = q_entry.packed_bits ^ entry.packed_bits
            hamming_dist = xor_bits.bit_count()
            # <q_bar, v_bar> = (D - 2 * HammingDist(q_bar, v_bar)) / D
            bar_dot = (dim - 2 * hamming_dist) / float(dim)
            # Unbiased RaBitQ estimator s_hat = <q_bar, v_bar> / (alignment_q * alignment_v)
            denom = max(1e-4, q_entry.alignment_factor * entry.alignment_factor)
            s_hat = max(-1.0, min(1.0, bar_dot / denom))
            # Analytical concentration error bound epsilon(q, v)
            eps = (
                confidence_z
                * inv_sqrt_d
                * (entry.residual_norm / entry.alignment_factor)
            )
            estimates.append((entry, s_hat, eps))

        # Sort by upper bound (s_hat + eps) descending
        estimates.sort(key=lambda item: item[1] + item[2], reverse=True)

        # Pass 2: Error-bounded exact reranking
        top_exact_heap: list[float] = []
        pruned_count = 0
        evaluated_exact = 0
        dense_results: list[tuple[RaBitQVectorEntry, float, float, float, bool]] = []

        for entry, s_hat, eps in estimates:
            kth_best = top_exact_heap[0] if len(top_exact_heap) >= top_k else -2.0
            if len(top_exact_heap) >= top_k and (s_hat + eps) < kth_best:
                pruned_count += 1
                dense_results.append((entry, s_hat, eps, s_hat, True))
                continue

            evaluated_exact += 1
            if entry.exact_vector:
                exact_ip = sum(a * b for a, b in zip(q_vec, entry.exact_vector))
            else:
                exact_ip = s_hat

            if len(top_exact_heap) < top_k:
                heapq.heappush(top_exact_heap, exact_ip)
            elif exact_ip > top_exact_heap[0]:
                heapq.heapreplace(top_exact_heap, exact_ip)
            dense_results.append((entry, s_hat, eps, exact_ip, False))

        # Pass 3: Fuse with BM25 lexical rankings and coverage weights via Weighted RRF
        self._ensure_globals()
        q_terms = [w.lower() for w in _WORD_RE.findall(query_text)]
        n_docs = max(1, len(self._entries))
        k1 = 1.5
        b = 0.75
        bm25_scores: dict[str, float] = {}

        for term in set(q_terms):
            df = self._doc_freqs.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
            for uid, tf in self._postings.get(term, ()):
                dl = self._doc_lengths[uid]
                denom = tf + k1 * (1.0 - b + b * (dl / self._avg_dl))
                bm25_scores[uid] = bm25_scores.get(uid, 0.0) + idf * ((tf * (k1 + 1.0)) / denom)

        bm25_ranked = sorted(
            bm25_scores.keys(), key=lambda u: bm25_scores[u], reverse=True
        )
        bm25_rank_map = {uid: rank + 1 for rank, uid in enumerate(bm25_ranked)}

        dense_results_sorted = sorted(dense_results, key=lambda x: x[3], reverse=True)
        candidates: list[tuple[float, float, RaBitQVectorEntry, float, float, bool]] = []
        rrf_k = 60.0

        for dense_rank_idx, (entry, s_hat, eps, exact_ip, was_pruned) in enumerate(
            dense_results_sorted
        ):
            d_rank = dense_rank_idx + 1
            b_rank = bm25_rank_map.get(entry.node_uid, len(self._entries))
            rrf = entry.coverage_weight * (
                (0.65 / (rrf_k + d_rank)) + (0.35 / (rrf_k + b_rank))
            )
            candidates.append(
                (round(rrf, 6), round(exact_ip, 6), entry, s_hat, eps, was_pruned)
            )

        if top_k < len(candidates):
            top_candidates = heapq.nlargest(
                top_k, candidates, key=lambda c: (c[0], c[1])
            )
        else:
            top_candidates = sorted(
                candidates, key=lambda c: (c[0], c[1]), reverse=True
            )

        results = tuple(
            RaBitQSearchResult(
                node_uid=entry.node_uid,
                qualified_name=entry.qualified_name,
                estimated_ip=round(s_hat, 6),
                error_bound=round(eps, 6),
                exact_score=exact_score,
                hybrid_rrf_score=rrf_score,
                was_pruned_from_rerank=was_pruned,
            )
            for rrf_score, exact_score, entry, s_hat, eps, was_pruned in top_candidates
        )
        return RaBitQQueryStats(
            results=results,
            total_candidates=len(self._entries),
            pruned_by_error_bound=pruned_count,
            evaluated_exact_count=evaluated_exact,
            scan_mode="linear_bitwise_scan",
            quantized_bytes=q_bytes,
            exact_float_bytes=f_bytes,
        )


RetrievalStats = RaBitQQueryStats

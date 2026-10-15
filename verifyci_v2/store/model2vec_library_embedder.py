from __future__ import annotations

try:
    import model2vec as _model2vec_lib  # type: ignore[import-not-found]
    _HAS_MODEL2VEC_LIBRARY = True
except Exception:  # pragma: no cover
    _model2vec_lib = None
    _HAS_MODEL2VEC_LIBRARY = False

"""Optional Model2Vec-library embedder (wraps ``model2vec.StaticModel``).

Offline-safe: construction requires an explicit local checkpoint path (or a
cached model id that resolves from disk). When the library or checkpoint is
unavailable, callers fall back to :class:`StaticModel2VecEmbedder`.
"""


class Model2VecLibraryEmbedder:
    """Embedder backed by the ``model2vec`` library when a checkpoint is on disk.

    Does not download weights. Pass ``model_name_or_path`` pointing to a local
    directory or cached Hugging Face repo id that resolves offline.
    """

    def __init__(
        self,
        dimension: int = 128,
        model_name_or_path: str = "minishlab/potion-base-8M",
    ) -> None:
        if dimension <= 0:
            raise ValueError("Embedding dimension must be positive")
        if not _HAS_MODEL2VEC_LIBRARY:
            raise RuntimeError("model2vec library is not installed")
        assert _model2vec_lib is not None
        self._model = _model2vec_lib.StaticModel.from_pretrained(
            model_name_or_path, local_files_only=True
        )
        self._dimension = dimension

    def embed_one(self, text: str) -> tuple[float, ...]:
        vectors = self._model.encode([text])
        vec = vectors[0]
        values = [float(x) for x in list(vec)]
        if len(values) > self._dimension:
            values = values[: self._dimension]
        while len(values) < self._dimension:
            values.append(0.0)
        # Unit normalise (matches StaticModel2VecEmbedder semantics).
        norm = sum(v * v for v in values) ** 0.5 or 1.0
        return tuple(v / norm for v in values)

    has_library = staticmethod(lambda: bool(_HAS_MODEL2VEC_LIBRARY))

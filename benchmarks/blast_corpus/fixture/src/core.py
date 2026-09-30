"""Core call graph. Ground-truth edges (caller -> callee):
  hub  -> mid1, mid2
  mid1 -> leaf
  mid2 -> leaf
  far  -> hub
  isolated -> (nothing)
"""


def leaf(x):
    return x


def mid1(x):
    return leaf(x)


def mid2(x):
    return leaf(x) + 1


def hub(x):
    return mid1(x) + mid2(x)


def far(x):
    return hub(x) * 2


def isolated(x):
    return x

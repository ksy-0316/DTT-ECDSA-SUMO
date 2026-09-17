"""Strict exhaustive subset search used by Protocol 4 (Trace Signature).

The tracer must find the subset ``C subseteq [n]``, ``|C| = t``, satisfying

    sum_{i in C} pk_i + Theta == Vp        (Theorem 1, equation (2))

which is equivalent to

    sum_{i in C} pk_i == Q,   with   Q = Vp - Theta.

This module performs the **strict exhaustive** enumeration demanded by
Protocol 4: every one of the ``C(n, t)`` candidate subsets is really formed and
really tested.  No meet-in-the-middle decomposition, no pruning, no
probabilistic filtering and no early abort on a partial sum is used, so the
tracing result is exactly the one specified by the protocol and
``subsets_tested`` always reaches ``C(n, t)`` when the search fails.

Only the *cost of one individual test* is optimised, which never changes the
set of subsets visited:

1. Subsets are generated in lexicographic order by an iterative depth-first
   walk, so the partial sum of a prefix ``i_1 < ... < i_{s-1}`` is computed once
   (a single mixed Jacobian addition) and shared by all of its completions.
2. For the last element the test ``prefix + pk_j == Q`` is rewritten as
   ``prefix == Q - pk_j``, with the n points ``Q - pk_j`` precomputed once.  The
   innermost loop therefore costs one modular multiplication in the common
   non-matching case and never needs a modular inversion.
3. When ``t > n/2`` the walk enumerates the *complements* of the candidate
   subsets instead of the subsets themselves, using
   ``sum_{i in C} pk_i = sum_{i in [n]} pk_i - sum_{i notin C} pk_i``.  Since
   ``C -> [n]\\C`` is a bijection between the ``C(n, t)`` subsets of size t and
   the ``C(n, n-t)`` subsets of size ``n-t``, exactly the same candidates are
   examined; only the shape of the search tree changes.
"""

from __future__ import annotations

from math import comb

from .curve import P, JAC_INF, jac_double, point_sub, point_sum


def search_space(n: int, t: int) -> int:
    """C(n, t): the number of candidate subsets Protocol 4 has to enumerate."""
    if t < 0 or t > n:
        return 0
    return comb(n, t)


def exhaustive_subset_search(pks, target, t):
    """Return ``(indices, subsets_tested)``; ``indices`` is ``None`` on failure.

    ``pks``   : list of n affine public keys, in registration order
    ``target``: affine point Q = Vp - Theta
    ``t``     : subset cardinality (the threshold recovered from T2)
    """
    n = len(pks)
    if t < 0 or t > n:
        return None, 0

    # enumerate whichever of {C, complement of C} is the smaller family
    if n - t < t:
        size = n - t
        goal = point_sub(point_sum(pks), target)
        use_complement = True
    else:
        size = t
        goal = target
        use_complement = False

    found, tested = _walk(pks, goal, size)
    if found is None:
        return None, tested
    if use_complement:
        excluded = set(found)
        found = [i for i in range(n) if i not in excluded]
    return found, tested


# --------------------------------------------------------------------------- #
# Iterative depth-first enumeration of every size-``s`` subset of [n]
# --------------------------------------------------------------------------- #
def _walk(pks, target, s):
    n = len(pks)

    # |C| = 0 : the empty subset is the only candidate
    if s == 0:
        return ([], 1) if target is None else (None, 1)

    # |C| = 1 : compare each public key directly
    if s == 1:
        for i in range(n):
            if pks[i] == target:
                return [i], i + 1
        return None, n

    # Q - pk_j for every registered vehicle, precomputed once.
    raw = [point_sub(target, pk) for pk in pks]
    # A None entry means Q == pk_j, i.e. the prefix would have to be the point
    # at infinity; (P, P) is a sentinel that can never match a finite prefix.
    residual = [r if r is not None else (P, P) for r in raw]
    has_null = any(r is None for r in raw)

    p = P
    tested = 0
    depth_max = s - 2            # depth at which the innermost loop runs
    limit = n - s                # at depth d the largest admissible index
    cur = [-1] * (s - 1)         # index currently chosen at each prefix depth
    jac = [JAC_INF] * s          # jac[d] = partial sum of depths 0..d-1

    d = 0
    cur[0] = -1
    while d >= 0:
        cur[d] += 1
        i = cur[d]
        if i > limit + d:
            d -= 1
            continue

        # ---- prefix update: jac[d+1] = jac[d] + pks[i]  (mixed Jacobian) ----
        X1, Y1, Z1 = jac[d]
        x2, y2 = pks[i]
        if Z1 == 0:
            node = (x2, y2, 1)
        else:
            ZZ = Z1 * Z1 % p
            U2 = x2 * ZZ % p
            S2 = y2 * Z1 % p * ZZ % p
            H = (U2 - X1) % p
            r = (S2 - Y1) % p
            if H == 0:
                node = jac_double(jac[d]) if r == 0 else JAC_INF
            else:
                HH = H * H % p
                HHH = H * HH % p
                V = X1 * HH % p
                X3 = (r * r - HHH - 2 * V) % p
                Y3 = (r * (V - X3) - Y1 * HHH) % p
                node = (X3, Y3, Z1 * H % p)
        jac[d + 1] = node

        if d < depth_max:
            d += 1
            cur[d] = i           # next depth starts at i + 1
            continue

        # ---- innermost level: every j > i completes one distinct subset ----
        X, Y, Z = node
        hit = -1
        if Z == 0 or has_null:
            for j in range(i + 1, n):
                tested += 1
                rj = raw[j]
                if Z == 0:
                    if rj is None:
                        hit = j
                        break
                    continue
                if rj is None:
                    continue
                ZZ = Z * Z % p
                if rj[0] * ZZ % p == X and rj[1] * ZZ % p * Z % p == Y:
                    hit = j
                    break
        else:
            Z2 = Z * Z % p
            Z3 = Z2 * Z % p
            for j in range(i + 1, n):
                rj = residual[j]
                if rj[0] * Z2 % p == X and rj[1] * Z3 % p == Y:
                    hit = j
                    break
            tested += (hit - i) if hit >= 0 else (n - 1 - i)

        if hit >= 0:
            return cur[:d + 1] + [hit], tested

    return None, tested

import time
import numpy as np
import hashlib
from numba import njit, prange
from entropy_watchdog import ThermodynamicWatchdog

CHARSET_SIZE = 95
PASS_LEN = 6

@njit(parallel=True, fastmath=True)
def generate_batch_2d_numba(cdf_matrix, first_char_cdf, num_candidates=60000, seed=42):
    num_workers = 24
    chunk_size = num_candidates // num_workers
    results = np.zeros((num_workers, chunk_size, PASS_LEN), dtype=np.int32)

    for w in prange(num_workers):
        rng_state = (seed ^ (w * 1664525 + 1013904223)) & 0xFFFFFFFF
        if rng_state == 0:
            rng_state = 1337

        for i in range(chunk_size):
            rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
            rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            rand_val0 = float(rng_state & 0xFFFFFF) / float(0x1000000)

            low = 0
            high = CHARSET_SIZE - 1
            while low < high:
                mid = (low + high) >> 1
                if rand_val0 <= first_char_cdf[mid]:
                    high = mid
                else:
                    low = mid + 1
            curr_char = low
            results[w, i, 0] = curr_char

            for pos in range(1, PASS_LEN):
                rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
                rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rand_val = float(rng_state & 0xFFFFFF) / float(0x1000000)

                low = 0
                high = CHARSET_SIZE - 1
                while low < high:
                    mid = (low + high) >> 1
                    if rand_val <= cdf_matrix[curr_char, mid]:
                        high = mid
                    else:
                        low = mid + 1
                results[w, i, pos] = low
                curr_char = low

    return results.reshape(num_candidates, PASS_LEN)

@njit(parallel=True, fastmath=True)
def generate_batch_3d_numba(cdf_tensor, first_char_cdf, num_candidates=60000, seed=42):
    """
    V4 Positional 3D Tensor Generator: samples from cdf_tensor[pos - 1, curr_char, :]
    so transitions are strictly conditioned on character position!
    """
    num_workers = 24
    chunk_size = num_candidates // num_workers
    results = np.zeros((num_workers, chunk_size, PASS_LEN), dtype=np.int32)

    for w in prange(num_workers):
        rng_state = (seed ^ (w * 1664525 + 1013904223)) & 0xFFFFFFFF
        if rng_state == 0:
            rng_state = 1337

        for i in range(chunk_size):
            rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
            rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            rand_val0 = float(rng_state & 0xFFFFFF) / float(0x1000000)

            low = 0
            high = CHARSET_SIZE - 1
            while low < high:
                mid = (low + high) >> 1
                if rand_val0 <= first_char_cdf[mid]:
                    high = mid
                else:
                    low = mid + 1
            curr_char = low
            results[w, i, 0] = curr_char

            for pos in range(1, PASS_LEN):
                rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
                rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rand_val = float(rng_state & 0xFFFFFF) / float(0x1000000)

                low = 0
                high = CHARSET_SIZE - 1
                while low < high:
                    mid = (low + high) >> 1
                    if rand_val <= cdf_tensor[pos - 1, curr_char, mid]:
                        high = mid
                    else:
                        low = mid + 1
                results[w, i, pos] = low
                curr_char = low

    return results.reshape(num_candidates, PASS_LEN)

def decode_candidates(int_matrix):
    ascii_chars = int_matrix + 32
    return ["".join(chr(c) for c in row) for row in ascii_chars]

def reinforce_2d(weights, first_char, int_row):
    first_char[int_row[0]] = min(15.0, first_char[int_row[0]] + 4.0)
    for i in range(len(int_row) - 1):
        r, c = int_row[i], int_row[i+1]
        weights[r, c] = min(45.0, weights[r, c] + 12.0)
        if 16 <= c <= 25:
            weights[r, 16:26] += 3.0
            if 16 <= r <= 25:
                weights[16:26, 16:26] += 2.0

def reinforce_3d_positional(tensor, first_char, int_row):
    """
    Reinforces exact positional slice tensor[pos, r, c] and diffuses
    sympathetic digit weight ONLY at the exact suffix position!
    """
    first_char[int_row[0]] = min(15.0, first_char[int_row[0]] + 4.0)
    for pos in range(len(int_row) - 1):
        r, c = int_row[pos], int_row[pos + 1]
        tensor[pos, r, c] = min(45.0, tensor[pos, r, c] + 14.0)
        if 16 <= c <= 25:
            tensor[pos, r, 16:26] += 3.5
            if 16 <= r <= 25:
                tensor[pos, 16:26, 16:26] += 2.5

def build_seeds():
    seed_corpus = [
        "planet", "rocket", "silver", "golden", "forest", "winter", "summer",
        "spring", "autumn", "coffee", "guitar", "window", "bridge", "castle",
        "pirate", "viking", "velvet", "marble", "copper", "cobalt", "quartz",
        "canyon", "island", "desert", "jungle", "falcon", "condor", "badger",
        "rabbit", "turtle", "salmon", "pepper", "butter", "cheese", "orange",
        "drag12", "shad12", "admi12", "mana34", "secu34", "netw34"
    ]
    w2d = np.full((CHARSET_SIZE, CHARSET_SIZE), 0.02, dtype=np.float32)
    w3d = np.full((PASS_LEN - 1, CHARSET_SIZE, CHARSET_SIZE), 0.02, dtype=np.float32)
    first_char = np.full(CHARSET_SIZE, 0.02, dtype=np.float32)

    for word in seed_corpus:
        first_char[ord(word[0]) - 32] += 3.0
        for pos in range(len(word) - 1):
            r = ord(word[pos]) - 32
            c = ord(word[pos + 1]) - 32
            w2d[r, c] += 3.0
            w3d[pos, r, c] += 3.0

    return w2d, w3d, first_char

def run_fair_benchmark():
    print("=================================================================")
    print("   BENCHMARK V4: STATIC vs. V3 (2D FLAT) vs. V4 (3D POSITIONAL)")
    print("=================================================================")

    target_plaintexts = [
        "drag11", "drag12", "drag21", "drag22",
        "shad11", "shad12", "shad21", "shad22",
        "admi11", "admi12", "admi21", "admi22"
    ]
    total_targets = len(target_plaintexts)
    target_hashes = {hashlib.sha256(p.encode()).hexdigest(): p for p in target_plaintexts}
    print(f"[+] Loaded {total_targets} SHA-256 targets across 3 structural families.")

    w2d_init, w3d_init, f_init = build_seeds()
    _ = generate_batch_2d_numba(w2d_init, f_init, num_candidates=2400, seed=1)
    _ = generate_batch_3d_numba(w3d_init, f_init, num_candidates=2400, seed=1)

    max_duration = 20.0

    # ==========================================
    # FIGHTER A: STATIC 2D BASELINE
    # ==========================================
    print("\n[---] Running Fighter A: Static Markov Baseline...")
    static_w2d, _, static_first = build_seeds()
    static_cdf = np.cumsum(static_w2d / static_w2d.sum(axis=1, keepdims=True), axis=1, dtype=np.float32)
    static_first_cdf = np.cumsum(static_first / static_first.sum(), dtype=np.float32)

    static_eval = 0
    static_hits = {}
    t0 = time.time()
    seed_counter = 500

    while (time.time() - t0) < max_duration and len(static_hits) < total_targets:
        seed_counter += 1
        raw_batch = generate_batch_2d_numba(static_cdf, static_first_cdf, num_candidates=60000, seed=seed_counter)
        candidates = decode_candidates(raw_batch)

        for cand in candidates:
            static_eval += 1
            h = hashlib.sha256(cand.encode()).hexdigest()
            if h in target_hashes and cand not in static_hits:
                static_hits[cand] = round(time.time() - t0, 3)
                print(f"    [Static Hit #{len(static_hits):02d}] Cracked '{cand}' at {static_hits[cand]}s")
                if len(static_hits) == total_targets:
                    break

    static_elapsed = time.time() - t0
    static_rate = static_eval / max(static_elapsed, 1e-6)

    # ==========================================
    # FIGHTER B: V3 ORGANISM (2D FLAT LATTICE)
    # ==========================================
    print("\n[---] Running Fighter B: V3 Organism (2D Flat Lattice)...")
    org2d, _, org_first2d = build_seeds()
    base2d, _, base_first = build_seeds()
    watchdog2d = ThermodynamicWatchdog(charset_size=CHARSET_SIZE, target_entropy_min=1.6)

    v3_eval = 0
    v3_hits = {}
    t0 = time.time()
    seed_counter = 500

    while (time.time() - t0) < max_duration and len(v3_hits) < total_targets:
        seed_counter += 1
        cdf = np.cumsum(org2d / org2d.sum(axis=1, keepdims=True), axis=1, dtype=np.float32)
        first_cdf = np.cumsum(org_first2d / org_first2d.sum(), dtype=np.float32)

        raw_batch = generate_batch_2d_numba(cdf, first_cdf, num_candidates=60000, seed=seed_counter)
        candidates = decode_candidates(raw_batch)
        batch_new_hits = 0

        for int_row, cand in zip(raw_batch, candidates):
            v3_eval += 1
            h = hashlib.sha256(cand.encode()).hexdigest()
            if h in target_hashes and cand not in v3_hits:
                v3_hits[cand] = round(time.time() - t0, 3)
                batch_new_hits += 1
                print(f"    🔥 [V3 Hit #{len(v3_hits):02d}] Cracked '{cand}' at {v3_hits[cand]}s")
                reinforce_2d(org2d, org_first2d, int_row)
                if len(v3_hits) == total_targets:
                    break

        if len(v3_hits) < total_targets and len(v3_hits) > 0:
            org2d = (org2d * 0.96) + (base2d * 0.04)
            org_first2d = (org_first2d * 0.95) + (base_first * 0.05)
            org2d, _ = watchdog2d.regulate_homeostasis(org2d, batch_new_hits)

    v3_elapsed = time.time() - t0
    v3_rate = v3_eval / max(v3_elapsed, 1e-6)

    # ==========================================
    # FIGHTER C: V4 ORGANISM (3D POSITIONAL TENSOR)
    # ==========================================
    print("\n[---] Running Fighter C: V4 Organism (3D Positional Tensor [5x95x95])...")
    _, org3d, org_first3d = build_seeds()
    _, base3d, _ = build_seeds()
    watchdog3d = ThermodynamicWatchdog(charset_size=CHARSET_SIZE, target_entropy_min=1.6)

    v4_eval = 0
    v4_hits = {}
    t0 = time.time()
    seed_counter = 500

    while (time.time() - t0) < max_duration and len(v4_hits) < total_targets:
        seed_counter += 1
        probs3d = org3d / org3d.sum(axis=2, keepdims=True)
        cdf3d = np.cumsum(probs3d, axis=2, dtype=np.float32)
        first_cdf = np.cumsum(org_first3d / org_first3d.sum(), dtype=np.float32)

        raw_batch = generate_batch_3d_numba(cdf3d, first_cdf, num_candidates=60000, seed=seed_counter)
        candidates = decode_candidates(raw_batch)
        batch_new_hits = 0

        for int_row, cand in zip(raw_batch, candidates):
            v4_eval += 1
            h = hashlib.sha256(cand.encode()).hexdigest()
            if h in target_hashes and cand not in v4_hits:
                v4_hits[cand] = round(time.time() - t0, 3)
                batch_new_hits += 1
                print(f"    ⚡ [V4 Positional Hit #{len(v4_hits):02d}] Cracked '{cand}' at {v4_hits[cand]}s -> Positional Tensor Boost!")
                reinforce_3d_positional(org3d, org_first3d, int_row)
                if len(v4_hits) == total_targets:
                    break

        if len(v4_hits) < total_targets and len(v4_hits) > 0:
            org3d = (org3d * 0.96) + (base3d * 0.04)
            org_first3d = (org_first3d * 0.95) + (base_first * 0.05)
            org3d, _ = watchdog3d.regulate_homeostasis(org3d, batch_new_hits)

    v4_elapsed = time.time() - t0
    v4_rate = v4_eval / max(v4_elapsed, 1e-6)

    print("\n=================================================================")
    print("                   V4 BENCHMARK VERDICT                          ")
    print("=================================================================")
    print(f"Static 2D Baseline : {len(static_hits):02d}/{total_targets} cracked in {static_elapsed:5.2f}s | {static_eval:>10,} evals ({static_rate:,.0f} c/s)")
    print(f"Organism V3 (2D)   : {len(v3_hits):02d}/{total_targets} cracked in {v3_elapsed:5.2f}s | {v3_eval:>10,} evals ({v3_rate:,.0f} c/s)")
    print(f"Organism V4 (3D)   : {len(v4_hits):02d}/{total_targets} cracked in {v4_elapsed:5.2f}s | {v4_eval:>10,} evals ({v4_rate:,.0f} c/s)")
    print("-----------------------------------------------------------------")
    print(f"V4 vs Static Gain  : {static_eval / max(v4_eval, 1):.1f}x FEWER candidates than Static Baseline!")
    print(f"V4 vs V3 Gain      : {v3_eval / max(v4_eval, 1):.2f}x FEWER candidates than V3 Flat Lattice!")
    print("=================================================================")

if __name__ == "__main__":
    run_fair_benchmark()

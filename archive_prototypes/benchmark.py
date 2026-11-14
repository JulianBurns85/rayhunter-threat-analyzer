import time
import numpy as np
import hashlib
from numba import njit, prange
from entropy_watchdog import ThermodynamicWatchdog

CHARSET_SIZE = 95
PASS_LEN = 6  # Kept concise for quick testing on CPU

@njit(parallel=True, fastmath=True)
def generate_batch_numba(cdf_matrix, num_candidates=50000, seed=42):
    """
    Blazing fast candidate generation across all 24 Ryzen cores using Numba.
    Returns an array of flat integer token arrays.
    """
    num_workers = 24
    chunk_size = num_candidates // num_workers
    results = np.zeros((num_workers, chunk_size, PASS_LEN), dtype=np.int32)

    for w in prange(num_workers):
        rng_state = (seed ^ (w * 1664525 + 1013904223)) & 0xFFFFFFFF
        if rng_state == 0:
            rng_state = 1337

        for i in range(chunk_size):
            # Fast XORShift PRNG
            rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
            rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
            rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
            
            curr_char = int(rng_state % CHARSET_SIZE)
            results[w, i, 0] = curr_char

            for pos in range(1, PASS_LEN):
                rng_state = (rng_state ^ ((rng_state << 13) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rng_state = (rng_state ^ (rng_state >> 17)) & 0xFFFFFFFF
                rng_state = (rng_state ^ ((rng_state << 5) & 0xFFFFFFFF)) & 0xFFFFFFFF
                rand_val = float(rng_state & 0xFFFFFF) / float(0x1000000)

                # Binary search CDF row
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

def decode_candidates(int_matrix):
    """Converts 2D integer token matrix into ASCII candidate strings."""
    # Add 32 to map 0-94 to printable ASCII characters (' ' to '~')
    ascii_chars = int_matrix + 32
    # Vectorized string decoding
    return ["".join(chr(c) for c in row) for row in ascii_chars]

def run_benchmark():
    print("==================================================")
    print("   THERMODYNAMIC ORGANISM VS. STATIC BASELINE")
    print("==================================================")

    # 1. Define Real Target Hashes (Sha256 of 3 hidden test words)
    # Target plaintexts for the test: "dragon", "admin1", "shadow"
    target_plaintexts = ["dragon", "admin1", "shadow"]
    target_hashes = {hashlib.sha256(p.encode()).hexdigest() for p in target_plaintexts}
    print(f"[+] Loaded {len(target_hashes)} real cryptographic SHA-256 targets.")

    test_duration = 30.0 # seconds per test

    # ==========================================
    # FIGHTER 1: THE STATIC BASELINE
    # ==========================================
    print("\n[---] Running Fighter A: Static Markov Baseline...")
    static_weights = np.ones((CHARSET_SIZE, CHARSET_SIZE), dtype=np.float32)
    # Seed static weights with basic common patterns so it's fair
    for word in target_plaintexts:
        for i in range(len(word) - 1):
            r = ord(word[i]) - 32
            c = ord(word[i+1]) - 32
            if 0 <= r < CHARSET_SIZE and 0 <= c < CHARSET_SIZE:
                static_weights[r, c] += 10.0

    static_probs = static_weights / static_weights.sum(axis=1, keepdims=True)
    static_cdf = np.cumsum(static_probs, axis=1, dtype=np.float32)

    static_total_evaluated = 0
    static_hits = set()
    static_start_time = time.time()
    seed_counter = 100

    while (time.time() - static_start_time) < test_duration:
        seed_counter += 1
        raw_batch = generate_batch_numba(static_cdf, num_candidates=60000, seed=seed_counter)
        candidates = decode_candidates(raw_batch)
        
        static_total_evaluated += len(candidates)
        for cand in candidates:
            h = hashlib.sha256(cand.encode()).hexdigest()
            if h in target_hashes:
                static_hits.add(cand)

    static_elapsed = time.time() - static_start_time
    static_rate = static_total_evaluated / static_elapsed
    print(f"[+] Static Baseline Finished.")
    print(f"    - Evaluated: {static_total_evaluated:,} candidates")
    print(f"    - Speed: {static_rate:,.0f} c/sec")
    print(f"    - Real Hits Found: {len(static_hits)} / {len(target_plaintexts)}")

    # ==========================================
    # FIGHTER 2: THE DYNAMIC ORGANISM
    # ==========================================
    print("\n[---] Running Fighter B: Thermodynamic Organism (Live Adaptation + Watchdog)...")
    organism_weights = np.ones((CHARSET_SIZE, CHARSET_SIZE), dtype=np.float32)
    watchdog = ThermodynamicWatchdog(charset_size=CHARSET_SIZE, target_entropy_min=2.0, target_entropy_max=5.8)

    org_total_evaluated = 0
    org_hits = set()
    org_start_time = time.time()
    seed_counter = 100

    while (time.time() - org_start_time) < test_duration:
        seed_counter += 1
        
        # 1. Compute current CDF from live weights
        probs = organism_weights / organism_weights.sum(axis=1, keepdims=True)
        cdf = np.cumsum(probs, axis=1, dtype=np.float32)

        # 2. Generate batch via Numba AVX parallel threads
        raw_batch = generate_batch_numba(cdf, num_candidates=60000, seed=seed_counter)
        candidates = decode_candidates(raw_batch)
        
        org_total_evaluated += len(candidates)
        batch_hits_found = 0

        # 3. Exact-match evaluation against real cryptographic hashes
        for int_row, cand in zip(raw_batch, candidates):
            h = hashlib.sha256(cand.encode()).hexdigest()
            if h in target_hashes:
                org_hits.add(cand)
                batch_hits_found += 1
                # STIGMERGIC REINFORCEMENT: Exact match rewards the literal transition path
                for i in range(len(int_row) - 1):
                    r, c = int_row[i], int_row[i+1]
                    organism_weights[r, c] += 50.0

        # 4. Background Evaporation + Entropy Watchdog regulation
        organism_weights *= 0.95
        organism_weights, report = watchdog.regulate_homeostasis(organism_weights, batch_hits_found)

    org_elapsed = time.time() - org_start_time
    org_rate = org_total_evaluated / org_elapsed
    print(f"[+] Thermodynamic Organism Finished.")
    print(f"    - Evaluated: {org_total_evaluated:,} candidates")
    print(f"    - Speed: {org_rate:,.0f} c/sec")
    print(f"    - Real Hits Found: {len(org_hits)} / {len(target_plaintexts)}")

    # ==========================================
    # FINAL VERDICT
    # ==========================================
    print("\n==================================================")
    print("             BENCHMARK RESULTS SUMMARY            ")
    print("==================================================")
    print(f"Static Baseline Speed  : {static_rate:,.0f} c/sec | Hits: {len(static_hits)}")
    print(f"Organism Speed         : {org_rate:,.0f} c/sec | Hits: {len(org_hits)}")
    print(f"Overhead Cost          : {((static_rate - org_rate)/static_rate)*100:.1f}% reduction in speed")
    print("==================================================")

if __name__ == "__main__":
    run_benchmark()
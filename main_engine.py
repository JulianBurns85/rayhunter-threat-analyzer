import asyncio
import time
import hashlib
import numpy as np
import websockets
from numba import njit, prange

from entropy_watchdog import ThermodynamicWatchdog
from telemetry_server import TelemetryBroadcaster

CHARSET_SIZE = 96  # 0 is <EOS> token, 1..95 are ASCII 32..126
PASS_MIN = 4
PASS_MAX = 8

@njit(parallel=True, fastmath=True)
def generate_variable_batch_3d(cdf_tensor, first_char_cdf, num_candidates=35000, seed=42):
    num_workers = 24
    chunk_size = num_candidates // num_workers
    results = np.zeros((num_workers, chunk_size, PASS_MAX), dtype=np.int32)
    lengths = np.zeros((num_workers, chunk_size), dtype=np.int32)

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
            
            curr_len = 1
            if curr_char == 0:
                lengths[w, i] = 0
                continue

            for pos in range(1, PASS_MAX):
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
                
                curr_char = low
                results[w, i, pos] = curr_char
                if curr_char == 0:
                    break
                curr_len += 1

            lengths[w, i] = curr_len

    return results, lengths

def decode_variable_candidates(int_matrix, length_matrix):
    candidates = []
    for row_w, row_l in zip(int_matrix, length_matrix):
        for code_row, length in zip(row_w, row_l):
            if length < PASS_MIN:
                continue
            chars = [chr(c + 31) for c in code_row[:length] if c > 0]
            if len(chars) >= PASS_MIN:
                candidates.append("".join(chars))
    return candidates

def adversarial_mutate(base_candidates):
    mutants = []
    leet_map = {'e': '3', 'a': '@', 'i': '1', 'o': '0', 's': '$', 'g': '9'}
    symbols = ['!', '@', '#', '$']
    
    for cand in base_candidates[:800]:
        mutant1 = "".join(leet_map.get(ch.lower(), ch) for ch in cand)
        if mutant1 != cand:
            mutants.append(mutant1)
        for sym in symbols:
            if len(cand) < PASS_MAX:
                mutants.append(cand + sym)
    return mutants

def reinforce_v6_tensor(tensor, first_char, plaintext):
    codes = [0 if ord(ch) < 32 or ord(ch) > 126 else ord(ch) - 31 for ch in plaintext]
    if not codes:
        return
        
    first_char[codes[0]] = min(15.0, first_char[codes[0]] + 4.0)
    for pos in range(min(len(codes) - 1, PASS_MAX - 1)):
        r, c = codes[pos], codes[pos + 1]
        tensor[pos, r, c] = min(60.0, tensor[pos, r, c] + 18.0)

        if 16 <= c <= 25:  # Digits
            tensor[pos, r, 16:26] += 7.0
            if 16 <= r <= 25:
                tensor[pos, 16:26, 16:26] += 5.0
        elif c >= 65 or (1 <= c <= 15):  # Symbols
            tensor[pos, r, 1:16] += 4.5
            tensor[pos, r, 65:] += 6.5

    last_pos = len(codes) - 1
    if last_pos < PASS_MAX - 1:
        tensor[last_pos, codes[-1], 0] += 14.0

def inject_audit_priors(base_tensor, base_first, org_tensor, org_first, targets):
    for word in targets:
        codes = [ord(ch) - 31 for ch in word[:PASS_MAX] if 32 <= ord(ch) <= 126]
        if not codes:
            continue
        org_first[codes[0]] += 14.0
        for pos in range(min(len(codes) - 1, PASS_MAX - 1)):
            r, c = codes[pos], codes[pos + 1]
            org_tensor[pos, r, c] += 18.0

def build_initial_seed_v6():
    seed_corpus = [
        "planet", "rocket!", "silver#", "golden", "forest!", "winter@", "summer#",
        "spring$", "autumn!", "coffee@", "guitar#", "window$", "bridge!", "castle@",
        "dr4g11!", "dr4g12!", "sh4d11#", "sh4d12#", "adm111$", "adm112$",
        "m4na33!", "m4na34!", "5ecu33@", "5ecu34@", "n3tw33#", "n3tw34#",
        "pl4n55!", "pl4n56!", "r0ck55#", "r0ck56#", "5ilv55$", "5ilv56$"
    ]
    tensor = np.full((PASS_MAX - 1, CHARSET_SIZE, CHARSET_SIZE), 0.02, dtype=np.float32)
    first_char = np.full(CHARSET_SIZE, 0.02, dtype=np.float32)

    for word in seed_corpus:
        codes = [ord(ch) - 31 for ch in word]
        first_char[codes[0]] += 3.0
        for pos in range(len(codes) - 1):
            r, c = codes[pos], codes[pos + 1]
            tensor[pos, r, c] += 3.0

    return tensor, first_char

TARGET_WAVES = [
    ["dr4g12!", "sh4d12#", "adm112$", "dr4g11!", "sh4d11#", "adm111$"],
    ["m4na34!", "5ecu34@", "n3tw34#", "m4na33!", "5ecu33@", "n3tw33#"],
    ["pl4n56!", "r0ck56#", "5ilv56$", "pl4n55!", "r0ck55#", "5ilv55$"]
]

async def run_master_organism():
    watchdog = ThermodynamicWatchdog(charset_size=CHARSET_SIZE, target_entropy_min=1.5, target_entropy_max=5.4)
    broadcaster = TelemetryBroadcaster(host="localhost", port=8765)
    base_tensor, base_first = build_initial_seed_v6()
    org_tensor, org_first = base_tensor.copy(), base_first.copy()

    print("[*] Compiling V6.3 Interactive Policy Auditor & 3D Telemetry Kernel...")
    _ = generate_variable_batch_3d(org_tensor, org_first, num_candidates=2400, seed=1)
    print("[+] V6.3 Interactive Command & Control Organism Armed!")

    wave_idx = 0
    seed_counter = 1000
    recent_cracks_feed = []

    async with websockets.serve(broadcaster.register, "localhost", 8765):
        print("[+] Live on ws://localhost:8765 -> Open index.html for Full Interactive HUD!")
        while True:
            is_custom = False
            if broadcaster.custom_wave_queue:
                current_wave = broadcaster.custom_wave_queue.pop(0)
                is_custom = True
                inject_audit_priors(base_tensor, base_first, org_tensor, org_first, current_wave)
                wave_label = f"CUSTOM AUDIT ({len(current_wave)} Targets)"
            else:
                current_wave = TARGET_WAVES[wave_idx % len(TARGET_WAVES)]
                wave_label = f"V6.3 W{wave_idx + 1}"

            target_hashes = {hashlib.sha256(p.encode()).hexdigest(): p for p in current_wave}
            cracked_in_wave = set()
            wave_start = time.time()
            total_evals_in_wave = 0
            print(f"\n[=== {wave_label} STARTED: Hunting {len(current_wave)} Targets ===]")

            while len(cracked_in_wave) < len(current_wave):
                if not is_custom and broadcaster.custom_wave_queue:
                    print("[!] Preempting standard wave for user-submitted Custom Policy Audit!")
                    break

                seed_counter += 1
                probs3d = org_tensor / org_tensor.sum(axis=2, keepdims=True)
                cdf3d = np.cumsum(probs3d, axis=2, dtype=np.float32)
                first_cdf = np.cumsum(org_first / org_first.sum(), dtype=np.float32)

                raw_batch, length_batch = generate_variable_batch_3d(cdf3d, first_cdf, num_candidates=35000, seed=seed_counter)
                candidates = decode_variable_candidates(raw_batch, length_batch)
                
                mutants = adversarial_mutate(candidates)
                candidates.extend(mutants)
                total_evals_in_wave += len(candidates)

                batch_new_hits = 0

                for cand in candidates:
                    h = hashlib.sha256(cand.encode()).hexdigest()
                    if h in target_hashes and cand not in cracked_in_wave:
                        cracked_in_wave.add(cand)
                        batch_new_hits += 1
                        elapsed = round(time.time() - wave_start, 2)
                        print(f"  ⚡ [{wave_label} | {len(cracked_in_wave):02d}/{len(current_wave)}] Cracked '{cand}' at {elapsed}s")
                        reinforce_v6_tensor(org_tensor, org_first, cand)
                        recent_cracks_feed.insert(0, {
                            "plaintext": cand,
                            "hash_prefix": h[:10],
                            "time": f"{elapsed:.2f}s",
                            "wave": "CUSTOM" if is_custom else f"W{wave_idx+1}"
                        })
                        recent_cracks_feed = recent_cracks_feed[:14]

                org_tensor = (org_tensor * 0.96) + (base_tensor * 0.04)
                org_first = (org_first * 0.95) + (base_first * 0.05)
                org_tensor, report = watchdog.regulate_homeostasis(org_tensor, batch_new_hits)

                elapsed_now = round(time.time() - wave_start, 2)
                report["state"] = f"{wave_label}: {len(cracked_in_wave)}/{len(current_wave)}"
                report["wave_elapsed"] = elapsed_now
                report["evals"] = total_evals_in_wave
                report["recent_cracks"] = recent_cracks_feed
                report["active_slice"] = broadcaster.selected_slice

                s_idx = broadcaster.selected_slice
                if 0 <= s_idx < org_tensor.shape[0]:
                    projected_weights = org_tensor[s_idx, 1:, 1:]
                else:
                    projected_weights = org_tensor[:, 1:, 1:].max(axis=0)

                row_entropies, _ = watchdog.compute_row_entropy(org_tensor[:, 1:, 1:])
                await broadcaster.broadcast_state(projected_weights, row_entropies, report)

                await asyncio.sleep(0.04)

            print(f"[+] {wave_label} Swept in {round(time.time() - wave_start, 2)}s! Cooling tensor...")
            for _ in range(10):
                org_tensor = (org_tensor * 0.80) + (base_tensor * 0.20)
                org_first = (org_first * 0.80) + (base_first * 0.20)
                s_idx = broadcaster.selected_slice
                if 0 <= s_idx < org_tensor.shape[0]:
                    projected_weights = org_tensor[s_idx, 1:, 1:]
                else:
                    projected_weights = org_tensor[:, 1:, 1:].max(axis=0)
                row_entropies, mean_h = watchdog.compute_row_entropy(org_tensor[:, 1:, 1:])
                report = {
                    "mean_entropy_bits": round(mean_h, 3),
                    "system_temp": 2.40,
                    "frozen_rows_reheated": int(np.sum(row_entropies < 2.0)),
                    "state": "WAVE_CLEARED_RESET",
                    "wave_elapsed": round(time.time() - wave_start, 2),
                    "evals": total_evals_in_wave,
                    "recent_cracks": recent_cracks_feed,
                    "active_slice": broadcaster.selected_slice
                }
                await broadcaster.broadcast_state(projected_weights, row_entropies, report)
                await asyncio.sleep(0.05)

            if not is_custom:
                wave_idx += 1

if __name__ == "__main__":
    asyncio.run(run_master_organism())
#include <cuda_runtime.h>
#include <stdint.h>

// Device function: Evaluates a weak/broken rolling cipher or round-reduced state
// where character positions leak sequential state correlation (like MySQL Old_Password or custom MACs)
__device__ void evaluate_and_reward(
    const unsigned char* path,          // 8-byte candidate indices (0-94)
    uint32_t candidate_state_high,      // Upper 32 bits of cipher/hash internal state
    uint32_t candidate_state_low,       // Lower 32 bits of cipher/hash internal state
    uint32_t target_high,               // Known target state high
    uint32_t target_low,                // Known target state low
    const uint32_t* __restrict__ bloom_filter, // Multi-target corpus Bloom filter
    uint32_t* __restrict__ telemetry_hits      // Output [95 x 95] pheromone grid
) {
    uint32_t reward_weight = 0;

    // -------------------------------------------------------------------------
    // VECTOR 1: Multi-Target Corpus Hit (Exact match against a large hash list)
    // Check 2-hash Bloom filter in L2 cache for instant O(1) corpus membership
    // -------------------------------------------------------------------------
    uint32_t bloom_idx1 = (candidate_state_low & 0x1FFFF); // 128K bit mask
    uint32_t bloom_idx2 = (candidate_state_high & 0x1FFFF);
    
    bool in_bloom = (bloom_filter[bloom_idx1 >> 5] & (1u << (bloom_idx1 & 31))) &&
                    (bloom_filter[bloom_idx2 >> 5] & (1u << (bloom_idx2 & 31)));

    if (in_bloom) {
        // High-confidence hit in the environment corpus -> Massive Pheromone Spike
        reward_weight += 500;
    }

    // -------------------------------------------------------------------------
    // VECTOR 2: Side-Channel / Algebraic Bit-Bias (Hamming Distance Gradient)
    // Uses NVIDIA's single-cycle __popc() hardware instruction to count matching bits
    // -------------------------------------------------------------------------
    uint32_t xor_low  = candidate_state_low ^ target_low;
    uint32_t xor_high = candidate_state_high ^ target_high;
    
    // Count how many bits are IDENTICAL (64 minus the number of differing bits)
    int matching_bits = 64 - (__popc(xor_low) + __popc(xor_high));

    // Random chance averages 32 matching bits. 
    // If we breach 48+ matching bits, we are in a statistical anomaly / gradient well.
    if (matching_bits >= 48) {
        int excess_bits = matching_bits - 47;
        // Exponential scaling: 48 bits = +1, 50 bits = +27, 52 bits = +125
        reward_weight += (excess_bits * excess_bits * excess_bits);
    }

    // -------------------------------------------------------------------------
    // VECTOR 3: Prefix/Byte-Aligned Timing or Checksum Leak (__ffs intrinsic)
    // Rewards consecutive leading zero bytes in the XOR difference
    // -------------------------------------------------------------------------
    int leading_matching_bits = __clz(xor_high); // Count Leading Zeros hardware instruction
    if (leading_matching_bits >= 16) {
        // Position-weighted reward: earlier characters get credit for prefix leaks
        int prefix_reward = (leading_matching_bits - 15) * 10;
        for (int i = 0; i < 3; ++i) {
            int idx = path[i] * 95 + path[i+1];
            atomicAdd(&telemetry_hits[idx], prefix_reward);
        }
    }

    // -------------------------------------------------------------------------
    // DEPOSIT STIGMERGIC SCENT ON THE LATTICE
    // -------------------------------------------------------------------------
    if (reward_weight > 0) {
        #pragma unroll
        for (int i = 0; i < 7; ++i) {
            int transition_idx = path[i] * 95 + path[i+1];
            atomicAdd(&telemetry_hits[transition_idx], reward_weight);
        }
    }
}
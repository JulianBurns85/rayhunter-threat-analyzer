#include <cuda_runtime.h>
#include <stdint.h>

#define CHARSET_SIZE 95
#define PASS_LEN 8

// Fast on-chip PRNG (XORShift32) - stays strictly in GPU registers
__device__ uint32_t xorshift32(uint32_t &state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

extern "C" __global__ void hunt_kernel(
    const float* __restrict__ global_cdf_matrix, // Flattened [95 x 95] CDF
    uint32_t* __restrict__ telemetry_hits,       // Output: stores successful transition indices
    uint32_t seed
) {
    // 1. Load the Markov Brain into ultra-fast L1 Shared Memory
    __shared__ float shared_cdf[CHARSET_SIZE * CHARSET_SIZE];
    int tid = threadIdx.x;
    for (int i = tid; i < CHARSET_SIZE * CHARSET_SIZE; i += blockDim.x) {
        shared_cdf[i] = global_cdf_matrix[i];
    }
    __syncthreads();

    // Unique RNG state per GPU thread
    uint32_t rng_state = seed ^ (blockIdx.x * blockDim.x + tid);
    char candidate[PASS_LEN];
    int current_char_idx = xorshift32(rng_state) % CHARSET_SIZE;
    candidate[0] = (char)(current_char_idx + 32);

    // 2. In-Situ Candidate Generation (Walking the Markov Chain on-chip)
    for (int pos = 1; pos < PASS_LEN; ++pos) {
        float rand_val = (xorshift32(rng_state) & 0xFFFFFF) / (float)0x1000000;
        int row_offset = current_char_idx * CHARSET_SIZE;
        
        // Sample next character using Cumulative Distribution
        int next_idx = 0;
        for (int c = 0; c < CHARSET_SIZE; ++c) {
            if (rand_val <= shared_cdf[row_offset + c]) {
                next_idx = c;
                break;
            }
        }
        candidate[pos] = (char)(next_idx + 32);
        current_char_idx = next_idx;
    }

    // 3. Fast Cryptographic Evaluation / Partial Collision Check
    // (Simulated fast FNV-1a hash check for demonstration)
    uint32_t hash = 2166136261u;
    for (int i = 0; i < PASS_LEN; ++i) {
        hash ^= candidate[i];
        hash *= 16777619u;
    }

    // 4. Telemetry Trigger: If partial collision (e.g., top 20 bits match target)
    if ((hash & 0xFFFFF000) == 0xCAFE0000) {
        // Leave a stigmergic scent marker for the Python Brain
        int prev_c = candidate[0] - 32;
        for (int i = 1; i < PASS_LEN; ++i) {
            int curr_c = candidate[i] - 32;
            atomicAdd(&telemetry_hits[prev_c * CHARSET_SIZE + curr_c], 1);
            prev_c = curr_c;
        }
    }
}
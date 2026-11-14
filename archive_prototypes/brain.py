import numpy as np
import cupy as cp

CHARSET_SIZE = 95

class CyberneticOrchestrator:
    def __init__(self):
        # Initialize uniform probability weights [95 x 95] on CPU
        self.weights = np.ones((CHARSET_SIZE, CHARSET_SIZE), dtype=np.float32)
        
        # Allocate GPU buffers and two asynchronous CUDA streams for double-buffering
        self.stream_compute = cp.cuda.Stream(non_blocking=True)
        self.stream_transfer = cp.cuda.Stream(non_blocking=True)
        
        self.gpu_cdf = cp.zeros((CHARSET_SIZE, CHARSET_SIZE), dtype=cp.float32)
        self.gpu_telemetry = cp.zeros(CHARSET_SIZE * CHARSET_SIZE, dtype=cp.uint32)

    def update_cdf_and_push(self):
        # Convert raw weights into row-wise Cumulative Distribution Functions (0.0 to 1.0)
        row_sums = self.weights.sum(axis=1, keepdims=True)
        probabilities = self.weights / row_sums
        cpu_cdf = np.cumsum(probabilities, axis=1, dtype=np.float32)
        
        # Async DMA push to GPU over the transfer stream
        with self.stream_transfer:
            self.gpu_cdf.set(cpu_cdf)

    def absorb_telemetry_and_mutate(self):
        # Pull hit counts from GPU back to CPU
        with self.stream_transfer:
            hits = self.gpu_telemetry.get().reshape((CHARSET_SIZE, CHARSET_SIZE))
            self.gpu_telemetry.fill(0) # Reset GPU scent counter
            
        self.stream_transfer.synchronize()
        
        # 1. Evaporation (Thermodynamic cooling of dead paths)
        self.weights *= 0.98
        
        # 2. Stigmergic Reinforcement (Boost paths that triggered partial hits)
        if np.any(hits > 0):
            self.weights += (hits * 2.5)
            
        # Clamp minimum weight so no path goes completely extinct (maintains exploration)
        np.clip(self.weights, 0.05, 1000.0, out=self.weights)
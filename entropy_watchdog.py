import numpy as np

class ThermodynamicWatchdog:
    def __init__(
        self, 
        charset_size=95, 
        target_entropy_min=1.6,
        target_entropy_max=5.2,
        base_temperature=1.0
    ):
        self.charset_size = charset_size
        self.max_possible_entropy = np.log2(charset_size)
        self.h_min = target_entropy_min
        self.h_max = target_entropy_max
        self.temperature = base_temperature
        self.stagnation_counter = 0

    def compute_row_entropy(self, weights):
        if weights.ndim == 3:
            w2d = weights.max(axis=0)
        else:
            w2d = weights

        row_sums = w2d.sum(axis=1, keepdims=True)
        probs = w2d / np.maximum(row_sums, 1e-12)
        safe_probs = np.where(probs > 1e-12, probs, 1.0)
        row_entropies = -np.sum(probs * np.log2(safe_probs), axis=1)

        active_mask = w2d.max(axis=1) > 0.05
        if np.any(active_mask):
            mean_active_entropy = float(np.mean(row_entropies[active_mask]))
        else:
            mean_active_entropy = float(np.mean(row_entropies))

        return row_entropies, mean_active_entropy

    def regulate_homeostasis(self, weights, telemetry_hit_count):
        if telemetry_hit_count == 0:
            self.stagnation_counter += 1
        else:
            self.stagnation_counter = 0

        row_sums = weights.sum(axis=-1, keepdims=True)
        probs = weights / np.maximum(row_sums, 1e-12)
        safe_probs = np.where(probs > 1e-12, probs, 1.0)
        slice_entropies = -np.sum(probs * np.log2(safe_probs), axis=-1)

        active_slices = weights.max(axis=-1) > 0.05
        frozen_mask = active_slices & (slice_entropies < self.h_min)
        num_frozen = int(np.sum(frozen_mask))
        status = "OPTIMAL_HUNT"

        if num_frozen > 0:
            status = "ANNEALING_ROWS"
            weights[frozen_mask] = np.power(weights[frozen_mask], 0.78)
            self.temperature = min(2.5, 1.0 + (num_frozen / 25.0))

        row_entropies, mean_entropy = self.compute_row_entropy(weights)

        if self.stagnation_counter >= 25 and mean_entropy < 1.5:
            status = "THERMAL_BURST"
            self.temperature = min(3.0, self.temperature * 1.3)
            weights = np.power(weights, 0.75)
            self.stagnation_counter = 0
        else:
            self.temperature += (1.0 - self.temperature) * 0.15

        np.clip(weights, 0.02, 10000.0, out=weights)

        telemetry_report = {
            "mean_entropy_bits": round(mean_entropy, 3),
            "max_possible_bits": round(self.max_possible_entropy, 2),
            "frozen_rows_reheated": min(95, num_frozen),
            "system_temp": round(self.temperature, 2),
            "state": status
        }
        return weights, telemetry_report
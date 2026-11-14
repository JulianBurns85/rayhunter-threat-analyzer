import numpy as np
import sys
import time

SPARKS = " ▂▃▄▅▆▇█"

def render_terminal_hud(weights_95x95, row_entropies, report):
    # Downsample 95x95 to 19x38 terminal grid by pooling 5x2.5 blocks
    pooled = weights_95x95[:95, :95].reshape(19, 5, 19, 5).max(axis=(1, 3))
    norm = pooled / max(pooled.max(), 1e-5)

    lines = ["\033[H"] # Move cursor to top-left without clearing (zero flicker)
    lines.append(f"=== THERMODYNAMIC LATTICE TUI | STATE: {report['state']} ===")
    lines.append(f"Entropy: {report['mean_entropy_bits']:.3f} bits | Temp: {report['system_temp']:.2f}K | Reheated: {report['frozen_rows_reheated']}/95\n")

    for r in range(19):
        row_str = f"Row {r*5:02d} │ "
        for c in range(19):
            val = norm[r, c]
            idx = min(7, int(val * 7.99))
            # Color gradient: Blue (34) -> Cyan (36) -> Yellow (33) -> Red (31)
            ansi_color = 34 if val < 0.25 else (36 if val < 0.5 else (33 if val < 0.8 else 31))
            row_str += f"\033[1;{ansi_color}m{SPARKS[idx]} \033[0m"
        
        # Append mini row-entropy bar on the right
        h_val = row_entropies[r * 5]
        h_bars = "█" * int((h_val / 6.57) * 10)
        lines.append(f"{row_str}│ H: {h_val:4.2f}b [{h_bars:<10}]")

    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
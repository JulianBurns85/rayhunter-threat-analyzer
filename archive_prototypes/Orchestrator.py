import multiprocessing
import random
import time

# Simulate the "Forest Floor" (Shared Memory Lattice)
# Keys are structural patterns/prefixes; values are probability weights.
def worker_process(worker_id, shared_lattice, active_flag):
    print(f"[Wolf {worker_id}] Entering the forest...")
    
    while active_flag.value:
        # 1. Read the environment (Stigmergy: sample weights from the shared lattice)
        lattice_snapshot = dict(shared_lattice)
        chosen_pattern = weighted_choice(lattice_snapshot)
        
        # 2. Hunt: Generate a micro-batch based on the environment's current scent
        micro_batch = generate_micro_batch(chosen_pattern, size=100)
        
        # 3. Process & Measure Feedback
        score, hit_found = evaluate_batch(micro_batch)
        
        if hit_found:
            print(f"🔥 [Wolf {worker_id}] Hot scent found on pattern '{chosen_pattern}'! Updating lattice.")
            # 4. Leave a marker: Mutate the shared environment so others converge here
            shared_lattice[chosen_pattern] += 5.0
        else:
            # Stale trail: Naturally decay the weight slightly
            shared_lattice[chosen_pattern] = max(0.1, shared_lattice[chosen_pattern] * 0.95)
            
        # Brief pause to simulate micro-batch processing cycle
        time.sleep(0.05)

def weighted_choice(weights_dict):
    patterns = list(weights_dict.keys())
    weights = list(weights_dict.values())
    return random.choices(patterns, weights=weights, k=1)[0]

def generate_micro_batch(pattern, size):
    # Generates strings mutating around the chosen structural pattern
    return [f"{pattern}{random.randint(100, 999)}" for _ in range(size)]

def evaluate_batch(batch):
    # Simulate finding a partial match or structural correlation (e.g., 2% chance)
    if random.random() < 0.05:
        return 100, True
    return 0, False

if __name__ == "__main__":
    manager = multiprocessing.Manager()
    
    # Initial shared probability lattice (the forest's starting state)
    shared_lattice = manager.dict({
        "admin": 1.0,
        "user": 1.0,
        "root": 1.0,
        "test": 1.0,
        "pass": 1.0
    })
    
    active_flag = multiprocessing.Value('i', 1)
    
    # Spawn a "pack" of 4 worker processes
    workers = []
    for i in range(4):
        p = multiprocessing.Process(target=worker_process, args=(i, shared_lattice, active_flag))
        workers.append(p)
        p.start()
        
    # Let the pack hunt for 3 seconds
    time.sleep(3)
    
    # Shut down the pack
    active_flag.value = 0
    for p in workers:
        p.join()
        
    print("\n--- Final Forest State (Lattice Weights) ---")
    print(dict(shared_lattice)) 
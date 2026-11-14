import multiprocessing
import random
import time

class AdaptiveMarkovLattice:
    def __init__(self, manager):
        # Shared dictionary mapping context strings to character weight dictionaries
        # e.g., {"pa": {"s": 10.0, "r": 2.0}, "ad": {"m": 5.0}}
        self.transitions = manager.dict()
        self.initialize_seed_data()

    def initialize_seed_data(self):
        # Seed with basic structural patterns (human defaults)
        seeds = ["admin", "password", "welcome", "spring", "dragon"]
        for word in seeds:
            self.train(word, weight_delta=1.0)

    def train(self, word, weight_delta=1.0, n=2):
        # Build n-gram transitions from a successful string or pattern
        for i in range(len(word) - n):
            context = word[i:i+n]
            next_char = word[i+n]
            
            # Update shared dictionary thread-safely
            current_dict = dict(self.transitions.get(context, {}))
            current_dict[next_char] = current_dict.get(next_char, 1.0) + weight_delta
            self.transitions[context] = current_dict

    def generate_candidate(self, length=8, n=2):
        # Walk the Markov chain to generate a single candidate string
        contexts = list(self.transitions.keys())
        if not contexts:
            return "password"
            
        context = random.choice(contexts)
        result = list(context)
        
        for _ in range(length - len(context)):
            if context in self.transitions:
                possible_chars = self.transitions[context]
                chars = list(possible_chars.keys())
                weights = list(possible_chars.values())
                
                next_char = random.choices(chars, weights=weights, k=1)[0]
                result.append(next_char)
                context = "".join(result[-n:])
            else:
                break
                
        return "".join(result)

def worker_process(worker_id, lattice, active_flag):
    print(f"[Wolf {worker_id}] Hunting via Markov trails...")
    
    while active_flag.value:
        # 1. Generate a micro-batch using current shared probability paths
        micro_batch = [lattice.generate_candidate(length=8) for _ in range(50)]
        
        # 2. Simulate evaluation and partial match feedback
        # If a candidate shares structural features with a target, simulate a "hit"
        hit_found = False
        best_candidate = micro_batch[0]
        
        for candidate in micro_batch:
            if "pass" in candidate or "ad" in candidate: # Simulated partial match trigger
                hit_found = True
                best_candidate = candidate
                break
                
        if hit_found:
            print(f"🔥 [Wolf {worker_id}] High-value structural pattern found in '{best_candidate}'! Reinforcing path.")
            # 3. Reinforce: Mutate the shared lattice weights so the pack swarms this grammar
            lattice.train(best_candidate, weight_delta=5.0)
        else:
            # Subtle background decay to prevent stale lock-in
            pass
            
        time.sleep(0.05)

if __name__ == "__main__":
    manager = multiprocessing.Manager()
    lattice = AdaptiveMarkovLattice(manager)
    active_flag = multiprocessing.Value('i', 1)
    
    # Spawn the wolf pack
    workers = []
    for i in range(3):
        p = multiprocessing.Process(target=worker_process, args=(i, lattice, active_flag))
        workers.append(p)
        p.start()
        
    time.sleep(2)
    active_flag.value = 0
    for p in workers:
        p.join()
        
    print("\n--- Evolved Transition Matrix Sample ---")
    for k, v in list(lattice.transitions.items())[:5]:
        print(f"Context '{k}' -> Weights: {dict(v)}")
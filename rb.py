from coincurve import PublicKey
from multiprocessing import Process
from time import time
from random import randint
import os

# Constants
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
NUM_WORKERS = 8
SAVE_INTERVAL = 100_000
TARGET_FILE = "allpubs_point.txt"

def read_target_x(filename):
    target = set()
    with open(filename, "r") as f:
        for line in f:
            if not line.strip(): continue
            x_str, _ = line.strip().split(",")
            target.add(int(x_str.strip()))
    return target

def read_last_position(worker_id, start):
    filename = f"last_position_worker_{worker_id}.txt"
    try:
        with open(filename, "r") as f:
            return int(f.read().strip())
    except:
        return start

def write_last_position(worker_id, pos):
    filename = f"last_position_worker_{worker_id}.txt"
    with open(filename, "w") as f:
        f.write(str(pos))

def worker(worker_id, start, end, target_x_set):
    # print(f"[Worker {worker_id}] Started range: {start} to {end}")
    current = read_last_position(worker_id, start)
    # print(f"[Worker {worker_id}] Resuming from: {current}")
    checked = 0
    start_time = time()

    while current < end:
        try:
            priv_bytes = current.to_bytes(32, 'big')
            pub = PublicKey.from_valid_secret(priv_bytes)
            x = pub.point()[0]

            if x in target_x_set:
                print(f"[✔ Worker {worker_id}] FOUND! Private key: {hex(current)}")
                with open("found_keys.txt", "a") as out:
                    out.write(f"{hex(current)}\n")
                break

            checked += 1
            if checked % SAVE_INTERVAL == 0:
                write_last_position(worker_id, current)
                print(f"[Worker {worker_id}] Progress saved at {current}")

            current += 1

        except Exception:
            current += 1
            continue

    write_last_position(worker_id, current)
    print(f"[Worker {worker_id}] Done. Last: {current}, Elapsed: {time() - start_time:.2f}s")

def main():
    target_x_set = read_target_x(TARGET_FILE)
    print(f"[+] Loaded {len(target_x_set)} public x targets.")

    chunk = N // NUM_WORKERS
    workers = []

    for i in range(NUM_WORKERS):
        # start = i * chunk + 1
        # end = (i + 1) * chunk if i < NUM_WORKERS - 1 else N
        start = randint(1, N)
        end = randint(1, N)
        if start < end:
            p = Process(target=worker, args=(i, start, end, target_x_set))
        else:
            p = Process(target=worker, args=(i, end, start, target_x_set))
        workers.append(p)
        p.start()

    for p in workers:
        p.join()

if __name__ == "__main__":
    main()

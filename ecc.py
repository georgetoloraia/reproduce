from classSECP import Secp256k1
from coincurve import PublicKey
from random import randint
import multiprocessing as mp
import os

N = Secp256k1.n
Gx = Secp256k1.G.x
P = Secp256k1.p
TARGET_FILE = "allpubs_point.txt"
NUM_CORES = os.cpu_count()  # ყველა ბირთვის გამოყენება

def read_target_x(filename):
    target = set()
    with open(filename, "r") as f:
        for line in f:
            if not line.strip(): continue
            x_str, _ = line.strip().split(",")
            target.add(int(x_str.strip()))
    return target

def worker(target_x_set, queue):
    while True:
        private = randint(1, N)
        public_key = Secp256k1.scalar_mult(private, Secp256k1.G)
        real_pub_x = public_key.x
        your_pub_x = (private * Gx) % P

        for i in target_x_set:
            back_to_private = (N - P + i) % P
            result = (i + your_pub_x) % P
            finished = (back_to_private + result) % N

            # შემოწმება
            try:
                pub = PublicKey.from_valid_secret(back_to_private.to_bytes(32, 'big'))
                x = pub.point()[0]
                if x in target_x_set:
                    queue.put(back_to_private)
                
                pub_sec = PublicKey.from_valid_secret(result.to_bytes(32, 'big'))
                x_sec = pub_sec.point()[0]
                if x_sec in target_x_set:
                    queue.put(result)

                pub_trd = PublicKey.from_valid_secret(finished.to_bytes(32, 'big'))
                x_trd = pub_trd.point()[0]
                if x_trd in target_x_set:
                    queue.put(finished)
            except:
                continue

def writer(queue):
    with open("found_keys.txt", "a") as out:
        while True:
            key = queue.get()
            if key is None: break
            out.write(f"{hex(key)}\n")
            out.flush()

if __name__ == "__main__":
    target_x_set = read_target_x(TARGET_FILE)
    
    manager = mp.Manager()
    queue = manager.Queue()
    
    pool = mp.Pool(NUM_CORES)
    
    # ჩამწერი პროცესი
    writer_proc = mp.Process(target=writer, args=(queue,))
    writer_proc.start()
    
    # სამუშაო პროცესები
    for _ in range(NUM_CORES):
        pool.apply_async(worker, (target_x_set, queue))
    
    pool.close()
    pool.join()
    queue.put(None)
    writer_proc.join()
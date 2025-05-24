#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <secp256k1.h>
#include <gmpxx.h>
#include <cctype>

//////// Commands //////////////
// # Install dependencies
// sudo apt-get install libgmp-dev libsecp256k1-dev
// 
// # Compile with optimizations
// g++ -O3 -std=c++17 -o keyfinder2 keyfinder2.cpp -lsecp256k1 -lgmp -lpthread
// 
// # Run with error logging
// ./keyfinder 2> errors.log
// 
// # Monitor results
// tail -f found_keys.txt

using namespace std;

// Secp256k1 Constants (hex initialization remains same)
mpz_class P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
mpz_class N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
mpz_class Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

template<typename T>
class ConcurrentQueue {
    queue<T> q;
    mutex mtx;
    condition_variable cv;

public:
    void push(const T& item) {
        lock_guard<mutex> lock(mtx);
        q.push(item);
        cv.notify_one();
    }

    bool pop(T& item) {
        unique_lock<mutex> lock(mtx);
        if (cv.wait_for(lock, 100ms, [this]{ return !q.empty(); })) {
            item = std::move(q.front());
            q.pop();
            return true;
        }
        return false;
    }
};

ConcurrentQueue<string> key_queue;
vector<mpz_class> target_x_vec;
secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

void mpz_to_bytes(const mpz_class& num, unsigned char* bytes) {
    mpz_export(bytes, nullptr, -1, 32, 0, 0, num.get_mpz_t());
}

bool check_pubkey(const mpz_class& priv_num, const vector<mpz_class>& targets) {
    unsigned char priv_bytes[32];
    mpz_to_bytes(priv_num, priv_bytes);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_bytes)) return false;

    unsigned char pub_serialized[33];
    size_t len = sizeof(pub_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    mpz_class x;
    mpz_import(x.get_mpz_t(), 32, -1, 1, 0, 0, pub_serialized + 1);
    return binary_search(targets.begin(), targets.end(), x);
}

string sanitize_integer(const string& str) {
    string result;
    for (char c : str) {
        if (isdigit(c)) {
            result += c;
        }
    }
    return result;
}

void worker(int thread_id, int num_threads) {
        // Initialize secp256k1 parameters
    // static mpz_class P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    // static mpz_class N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    // static mpz_class Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    mpz_class plus_to_set = thread_id + 1;

    while (true) {
        // cout << plus_to_set << "\n";
        for (const auto& seted : target_x_vec) {
            mpz_class private_val = seted + plus_to_set;
            if (private_val >= N) continue;

            unsigned char priv_bytes[32];
            mpz_to_bytes(private_val, priv_bytes);

            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_bytes)) continue;

            unsigned char pub_serialized[33];
            size_t len = sizeof(pub_serialized);
            secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &len, &pubkey, SECP256K1_EC_COMPRESSED);

            mpz_class real_pub_x;
            mpz_import(real_pub_x.get_mpz_t(), 32, -1, 1, 0, 0, pub_serialized + 1);
            mpz_class your_pub_x = (private_val * Gx) % N;

            for (const auto& i : target_x_vec) {
                mpz_class back_to_private = (real_pub_x * i) % P;
                mpz_class result = (i * your_pub_x) % P;
                mpz_class finished = (back_to_private * result) % N;

                if (back_to_private > 0 && back_to_private < N && check_pubkey(back_to_private, target_x_vec)) {
                    key_queue.push(back_to_private.get_str());
                }
                if (result > 0 && result < N && check_pubkey(result, target_x_vec)) {
                    key_queue.push(result.get_str());
                }
                if (finished > 0 && finished < N && check_pubkey(finished, target_x_vec)) {
                    key_queue.push(finished.get_str());
                }
            }
        }
        plus_to_set += num_threads;
    }
}

void writer() {
    ofstream outfile("found_keys.txt", ios::app);
    string key;
    while (true) {
        if (key_queue.pop(key)) {
            outfile << key << endl;
            outfile.flush();
        }
    }
}

int main() {
    ifstream infile("allpubs_point.txt");
    if (!infile) {
        cerr << "Error opening input file!" << endl;
        return 1;
    }

    string line;
    int line_num = 0;
    int valid_count = 0;

    while (getline(infile, line)) {
        line_num++;
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        if (line.empty()) {
            cerr << "Warning: Empty line #" << line_num << endl;
            continue;
        }

        size_t comma_pos = line.find(',');
        if (comma_pos == string::npos) {
            cerr << "Skipping line #" << line_num << " (missing comma)" << endl;
            continue;
        }

        string x_str = line.substr(0, comma_pos);
        string clean_x = sanitize_integer(x_str);

        if (clean_x.empty()) {
            cerr << "Skipping invalid number in line #" << line_num << endl;
            continue;
        }

        try {
            mpz_class x(clean_x, 10);  // Decimal parsing
            target_x_vec.push_back(x);
            valid_count++;
        } catch (const exception& e) {
            cerr << "Error parsing line #" << line_num << ": " << e.what() << endl;
            continue;
        }
    }

    if (target_x_vec.empty()) {
        cerr << "Error: No valid targets loaded!" << endl;
        return 1;
    }

    sort(target_x_vec.begin(), target_x_vec.end());
    cerr << "Loaded " << valid_count << " valid targets" << endl;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        cerr << "Error creating crypto context" << endl;
        return 1;
    }

    thread writer_thread(writer);
    vector<thread> workers;
    const unsigned num_threads = thread::hardware_concurrency();

    for (unsigned i = 0; i < num_threads; ++i) {
        workers.emplace_back(worker, i, num_threads);
    }

    writer_thread.join();
    for (auto& t : workers) t.join();

    secp256k1_context_destroy(ctx);
    return 0;
}
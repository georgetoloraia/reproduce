#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <string>
#include <chrono>
#include <cctype>
#include <secp256k1.h>
#include <gmpxx.h>

// g++ -O3 -std=c++17 -o keyfinder2 keyfinder2.cpp -lsecp256k1 -lgmp -lgmpxx -lpthread
// /keyfinder2 allpubs_point.txt found_keys.txt

using namespace std;
using namespace std::chrono;

// Secp256k1 Constants
const mpz_class P("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
const mpz_class N("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
const mpz_class Gx("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

// Thread-safe queue for storing found private keys
template<typename T>
class ConcurrentQueue {
private:
    queue<T> q;
    mutex mtx;
    condition_variable cv;

public:
    void push(const T& item) {
        {
            lock_guard<mutex> lock(mtx);
            q.push(item);
        }
        cv.notify_one();
    }

    bool pop(T& item) {
        unique_lock<mutex> lock(mtx);
        cv.wait(lock, [this]{ return !q.empty(); });
        item = std::move(q.front());
        q.pop();
        return true;
    }
};

ConcurrentQueue<string> key_queue;
vector<mpz_class> target_x_vec;
secp256k1_context* ctx = nullptr;

// Progress tracking
struct Progress {
    atomic<uint64_t> total_keys_tested{0};
    atomic<uint64_t> total_iterations{0};
    mutex print_mutex;
};

// Convert mpz_class to 32-byte big-endian array
void mpz_to_bytes(const mpz_class& num, unsigned char* bytes) {
    mpz_export(bytes, nullptr, 1, 32, 0, 0, num.get_mpz_t());
}

// Generate public key and check if its x-coordinate is in targets
bool check_pubkey(const mpz_class& priv_num, const vector<mpz_class>& targets) {
    unsigned char priv_bytes[32];
    mpz_to_bytes(priv_num, priv_bytes);

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_bytes)) return false;

    unsigned char pub_serialized[33];
    size_t len = sizeof(pub_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    mpz_class x;
    mpz_import(x.get_mpz_t(), 32, 1, 1, 0, 0, pub_serialized + 1); // Big-endian
    return binary_search(targets.begin(), targets.end(), x);
}

// Sanitize input string to keep only digits
string sanitize_integer(const string& str) {
    string result;
    for (char c : str) {
        if (isdigit(c)) {
            result += c;
        }
    }
    return result;
}

// Worker thread function
void worker(int thread_id, int num_threads, atomic<bool>& stop_flag, Progress& progress) {
    mpz_class plus_to_set = thread_id + 1;
    uint64_t keys_tested = 0;
    uint64_t iterations = 0;
    auto last_report = steady_clock::now();

    while (!stop_flag) {
        for (const auto& target_x : target_x_vec) {
            mpz_class private_val = target_x + plus_to_set;
            if (private_val >= N) continue;

            keys_tested++;
            progress.total_keys_tested++;

            unsigned char priv_bytes[32];
            mpz_to_bytes(private_val, priv_bytes);

            secp256k1_pubkey pubkey;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_bytes)) continue;

            unsigned char pub_serialized[33];
            size_t len = sizeof(pub_serialized);
            secp256k1_ec_pubkey_serialize(ctx, pub_serialized, &len, &pubkey, SECP256K1_EC_COMPRESSED);

            mpz_class real_pub_x;
            mpz_import(real_pub_x.get_mpz_t(), 32, 1, 1, 0, 0, pub_serialized + 1);
            mpz_class your_pub_x = (private_val * Gx) % N;

            for (const auto& i : target_x_vec) {
                mpz_class back_to_private = (real_pub_x * i) % P;
                mpz_class result = (i * your_pub_x) % P;
                mpz_class finished = (back_to_private * result) % N;

                if (back_to_private > 0 && back_to_private < N && check_pubkey(back_to_private, target_x_vec)) {
                    key_queue.push(back_to_private.get_str());
                    stop_flag = true;
                    keys_tested += 2; // Account for additional checks
                    progress.total_keys_tested += 2;
                }
                if (result > 0 && result < N && check_pubkey(result, target_x_vec)) {
                    key_queue.push(result.get_str());
                    stop_flag = true;
                }
                if (finished > 0 && finished < N && check_pubkey(finished, target_x_vec)) {
                    key_queue.push(finished.get_str());
                    stop_flag = true;
                }
            }

            // Report progress every 10 seconds
            auto now = steady_clock::now();
            if (duration_cast<seconds>(now - last_report).count() >= 10) {
                lock_guard<mutex> lock(progress.print_mutex);
                cout << "Thread " << thread_id << ": Tested " << keys_tested
                     << " keys, " << iterations << " iterations (plus_to_set = 0x"
                     << plus_to_set.get_str(16).substr(0, 16) << "...)\n";
                last_report = now;
            }
        }
        iterations++;
        progress.total_iterations++;
        plus_to_set += num_threads;

        if (plus_to_set >= N) break; // Exit if search space is exhausted
    }

    // Final report
    {
        lock_guard<mutex> lock(progress.print_mutex);
        cout << "Thread " << thread_id << " finished: Tested " << keys_tested
             << " keys, " << iterations << " iterations\n";
    }
    key_queue.push(""); // End marker
}

// Writer thread function
void writer(const string& output_filename, int num_threads, Progress& progress) {
    ofstream outfile(output_filename, ios::app);
    if (!outfile) {
        cerr << "Error: Could not open output file '" << output_filename << "'\n";
        return;
    }

    int end_count = 0;
    while (true) {
        string key;
        if (key_queue.pop(key)) {
            if (key.empty()) {
                end_count++;
                if (end_count == num_threads) break;
            } else {
                outfile << key << endl;
                outfile.flush();
                lock_guard<mutex> lock(progress.print_mutex);
                cout << "Found key: " << key.substr(0, 16) << "... written to " << output_filename << "\n";
            }
        }
    }

    lock_guard<mutex> lock(progress.print_mutex);
    cout << "Writer finished. Total keys tested: " << progress.total_keys_tested
         << ", Total iterations: " << progress.total_iterations << "\n";
}

int main(int argc, char* argv[]) {
    // Check command-line arguments
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <input_file> <output_file>\n";
        return 1;
    }
    string input_filename = argv[1];
    string output_filename = argv[2];

    // Read target x-coordinates
    ifstream infile(input_filename);
    if (!infile) {
        cerr << "Error: Could not open input file '" << input_filename << "'\n";
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
            mpz_class x(clean_x, 10);
            target_x_vec.push_back(x);
            valid_count++;
        } catch (const exception& e) {
            cerr << "Error parsing line #" << line_num << ": " << e.what() << endl;
        }
    }
    infile.close();

    if (target_x_vec.empty()) {
        cerr << "Error: No valid targets loaded from '" << input_filename << "'\n";
        return 1;
    }
    sort(target_x_vec.begin(), target_x_vec.end());
    cout << "Loaded " << valid_count << " valid targets\n";

    // Initialize secp256k1 context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!ctx) {
        cerr << "Error: Failed to create secp256k1 context\n";
        return 1;
    }

    // Set up threads
    atomic<bool> stop_flag{false};
    Progress progress;
    const unsigned num_threads = thread::hardware_concurrency();
    vector<thread> workers;
    workers.reserve(num_threads);

    cout << "Starting " << num_threads << " worker threads\n";
    for (unsigned i = 0; i < num_threads; ++i) {
        try {
            workers.emplace_back(worker, i, num_threads, ref(stop_flag), ref(progress));
        } catch (const exception& e) {
            cerr << "Error: Failed to create thread " << i << ": " << e.what() << "\n";
            secp256k1_context_destroy(ctx);
            return 1;
        }
    }

    // Launch writer thread
    thread writer_thread(writer, output_filename, num_threads, ref(progress));

    // Wait for threads to complete
    for (auto& t : workers) {
        t.join();
    }
    writer_thread.join();

    // Clean up
    secp256k1_context_destroy(ctx);
    cout << "Search completed. Final stats: " << progress.total_keys_tested
         << " keys tested, " << progress.total_iterations << " iterations\n";
    return 0;
}
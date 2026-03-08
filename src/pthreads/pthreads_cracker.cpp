#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <pthread.h>
#include <atomic>
#include <cmath>
#include <openssl/evp.h>

using namespace std;
using namespace std::chrono;

const string CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";
const int CHARSET_SIZE = CHARSET.length();

// Global flag so all threads stop if one finds the password
atomic<bool> global_found(false);
string cracked_password = "";
atomic<long long> total_global_attempts(0);

// Structure to pass arguments to our POSIX threads
struct ThreadArgs {
    int thread_id;
    int start_idx;
    int end_idx;
    int length;
    string target_hash;
};

// SHA-256 function (OpenSSL 3.0+ EVP API)
string sha256(const string& str) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    
    if (context != nullptr) {
        EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
        EVP_DigestUpdate(context, str.c_str(), str.size());
        EVP_DigestFinal_ex(context, hash, &lengthOfHash);
        EVP_MD_CTX_free(context);
    }

    stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// The Thread Function
void* bruteForceWorker(void* arguments) {
    ThreadArgs* args = (ThreadArgs*)arguments;
    
    vector<int> indices(args->length, 0);
    // Set the starting character for this specific thread
    indices[0] = args->start_idx; 
    
    string current_guess(args->length, CHARSET[0]);
    long long local_attempts = 0;

    while (!global_found) {
        // 1. Generate string
        for (int i = 0; i < args->length; i++) {
            current_guess[i] = CHARSET[indices[i]];
        }

        local_attempts++;

        // 2. Hash and Compare
        if (sha256(current_guess) == args->target_hash) {
            cracked_password = current_guess;
            global_found = true; // Signal other threads to stop
            break;
        }

        // 3. Increment the "odometer"
        int pos = args->length - 1;
        while (pos >= 0) {
            indices[pos]++;
            if (indices[pos] < CHARSET_SIZE) {
                break; 
            }
            indices[pos] = 0;
            pos--; 
        }

        // 4. Check if this thread has finished its assigned chunk
        if (pos < 0 || indices[0] >= args->end_idx) {
            break;
        }
    }

    // Safely add this thread's attempts to the global counter
    total_global_attempts += local_attempts;
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " <length> <target_sha256_hash> <num_threads>" << endl;
        return 1;
    }

    int length = stoi(argv[1]);
    string target_hash = argv[2];
    int num_threads = stoi(argv[3]);

    cout << "--- POSIX Threads Brute-Force Cracker ---" << endl;
    cout << "Target: " << target_hash << " | Length: " << length << " | Threads: " << num_threads << endl;

    auto start_time = high_resolution_clock::now();

    // Array to hold thread identifiers and arguments
    pthread_t threads[num_threads];
    ThreadArgs thread_args[num_threads];

    // Calculate how many starting characters each thread gets
    int chars_per_thread = ceil((double)CHARSET_SIZE / num_threads);

    for (int i = 0; i < num_threads; i++) {
        thread_args[i].thread_id = i;
        thread_args[i].start_idx = i * chars_per_thread;
        thread_args[i].end_idx = min((i + 1) * chars_per_thread, CHARSET_SIZE);
        thread_args[i].length = length;
        thread_args[i].target_hash = target_hash;

        // Ensure we don't spawn threads that have no characters assigned
        if (thread_args[i].start_idx < CHARSET_SIZE) {
            pthread_create(&threads[i], NULL, bruteForceWorker, (void*)&thread_args[i]);
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        if (thread_args[i].start_idx < CHARSET_SIZE) {
            pthread_join(threads[i], NULL);
        }
    }

    auto stop_time = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop_time - start_time);

    if (global_found) {
        cout << "\n[SUCCESS] Password cracked: " << cracked_password << endl;
    } else {
        cout << "\n[FAILED] Password not found in the given domain." << endl;
    }

    cout << "Total attempts across all threads: " << total_global_attempts << endl;
    cout << "Execution Time: " << duration.count() << " ms" << endl;
    cout << "-----------------------------------------" << endl;

    return 0;
}
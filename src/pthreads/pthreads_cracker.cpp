#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <pthread.h>
#include <atomic>
#include <cmath>
#include "../../include/common.h"

using namespace std;
using namespace std::chrono;

// Global flag so all threads stop if one finds the password
atomic<bool> global_found(false);
string cracked_password = "";
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;
atomic<long long> total_global_attempts(0);

// Structure to pass arguments to our POSIX threads
struct ThreadArgs {
    int thread_id;
    int start_idx;
    int end_idx;
    int length;
    string target_hash;
};

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
            pthread_mutex_lock(&found_mutex);
            if (!global_found) {          // double-check inside the lock
                cracked_password = current_guess;
                global_found = true;
            }
            pthread_mutex_unlock(&found_mutex);
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
    vector<pthread_t> threads(num_threads);
    vector<ThreadArgs> thread_args(num_threads);

    // Calculate how many starting characters each thread gets
    int chars_per_thread = ceil((double)CHARSET_SIZE / num_threads);

    // AFTER (creation loop):
    int threads_created = 0;
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].thread_id = i;
        thread_args[i].start_idx = i * chars_per_thread;
        thread_args[i].end_idx = min((i + 1) * chars_per_thread, CHARSET_SIZE);
        thread_args[i].length = length;
        thread_args[i].target_hash = target_hash;
        if (thread_args[i].start_idx < CHARSET_SIZE) {
            pthread_create(&threads[i], NULL, bruteForceWorker, (void*)&thread_args[i]);
            threads_created++;
        }
    }

    // AFTER (join loop):
    for (int i = 0; i < threads_created; i++) {
        pthread_join(threads[i], NULL);
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
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include "../../include/common.h"

using namespace std;
using namespace std::chrono;

bool bruteForceSerial(const string& target_hash, int length) {
    vector<int> indices(length, 0);
    string current_guess(length, CHARSET[0]);
    long long attempts = 0;

    while (true) {
        for (int i = 0; i < length; i++) {
            current_guess[i] = CHARSET[indices[i]];
        }

        attempts++;

        if (sha256(current_guess) == target_hash) {
            cout << "\n[SUCCESS] Password cracked: " << current_guess << endl;
            cout << "Total attempts: " << attempts << endl;
            return true;
        }

        int pos = length - 1;
        while (pos >= 0) {
            indices[pos]++;
            if (indices[pos] < CHARSET_SIZE) {
                break; 
            }
            indices[pos] = 0;
            pos--; 
        }

        if (pos < 0) {
            cout << "\n[FAILED] Password not found in the given domain." << endl;
            cout << "Total attempts: " << attempts << endl;
            return false;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cerr << "Usage: " << argv[0] << " <length> <target_sha256_hash>" << endl;
        return 1;
    }

    int length = stoi(argv[1]);
    if (length <= 0) {
        cerr << "Error: length must be a positive integer." << endl;
        return 1;
    }
    string target_hash = normaliseHash(argv[2]);
    if (!isValidSHA256(target_hash)) {
        cerr << "Error: target hash must be a 64-character hex SHA-256 string." << endl;
        return 1;
    }

    cout << "--- Serial Brute-Force Cracker ---" << endl;
    cout << "Target Hash: " << target_hash << endl;
    cout << "Length: " << length << endl;
    cout << "Character Set: " << CHARSET << " (Size: " << CHARSET_SIZE << ")" << endl;
    cout << "Cracking in progress... Please wait." << endl;

    auto start = high_resolution_clock::now();
    try {
        bruteForceSerial(target_hash, length);
    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        return 1;
    }
    auto stop = high_resolution_clock::now();
    
    auto duration = duration_cast<milliseconds>(stop - start);

    cout << "Execution Time: " << duration.count() << " ms" << endl;
    cout << "----------------------------------" << endl;

    return 0;
}
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <openssl/evp.h> 

using namespace std;
using namespace std::chrono;

const string CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";
const int CHARSET_SIZE = CHARSET.length();


string sha256(const string str) {
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
    string target_hash = argv[2];

    cout << "--- Serial Brute-Force Cracker ---" << endl;
    cout << "Target Hash: " << target_hash << endl;
    cout << "Length: " << length << endl;
    cout << "Character Set: " << CHARSET << " (Size: " << CHARSET_SIZE << ")" << endl;
    cout << "Cracking in progress... Please wait." << endl;

    auto start = high_resolution_clock::now();
    bruteForceSerial(target_hash, length);
    auto stop = high_resolution_clock::now();
    
    auto duration = duration_cast<milliseconds>(stop - start);

    cout << "Execution Time: " << duration.count() << " ms" << endl;
    cout << "----------------------------------" << endl;

    return 0;
}
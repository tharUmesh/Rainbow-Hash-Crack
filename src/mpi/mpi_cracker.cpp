#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <mpi.h>
#include <openssl/evp.h>

using namespace std;
using namespace std::chrono;

const string CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789";
const int CHARSET_SIZE = CHARSET.length();


#define TAG_WORK 1
#define TAG_RESULT 2
#define TAG_DIE 3

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

void masterProcess(int num_procs, int length, const string& target_hash) {
    int next_char_idx = 0;
    int active_workers = 0;
    bool found = false;
    string cracked_password = "";

    auto start_time = high_resolution_clock::now();

    for (int rank = 1; rank < num_procs; rank++) {
        if (next_char_idx < CHARSET_SIZE) {
            MPI_Send(&next_char_idx, 1, MPI_INT, rank, TAG_WORK, MPI_COMM_WORLD);
            next_char_idx++;
            active_workers++;
        } else {
            
            int dummy = 0;
            MPI_Send(&dummy, 1, MPI_INT, rank, TAG_DIE, MPI_COMM_WORLD);
        }
    }

    
    while (active_workers > 0) {
        char result_buffer[256] = {0};
        MPI_Status status;
        
        
        MPI_Recv(result_buffer, 256, MPI_CHAR, MPI_ANY_SOURCE, TAG_RESULT, MPI_COMM_WORLD, &status);
        int worker_rank = status.MPI_SOURCE;
        string result_str(result_buffer);

        if (result_str != "NOT_FOUND" && !found) {
            found = true;
            cracked_password = result_str;
        }

        
        if (next_char_idx < CHARSET_SIZE && !found) {
            MPI_Send(&next_char_idx, 1, MPI_INT, worker_rank, TAG_WORK, MPI_COMM_WORLD);
            next_char_idx++;
        } else {
            
            int dummy = 0;
            MPI_Send(&dummy, 1, MPI_INT, worker_rank, TAG_DIE, MPI_COMM_WORLD);
            active_workers--;
        }
    }

    auto stop_time = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop_time - start_time);

    if (found) {
        cout << "\n[MASTER] SUCCESS! Password cracked: " << cracked_password << endl;
    } else {
        cout << "\n[MASTER] FAILED. Password not found in domain." << endl;
    }
    cout << "Execution Time: " << duration.count() << " ms" << endl;
    cout << "-----------------------------------------" << endl;
}

void workerProcess(int rank, int length, const string& target_hash) {
    while (true) {
        int start_idx;
        MPI_Status status;
        
        
        MPI_Recv(&start_idx, 1, MPI_INT, 0, MPI_ANY_TAG, MPI_COMM_WORLD, &status);

        if (status.MPI_TAG == TAG_DIE) {
            break; 
        }

        
        vector<int> indices(length, 0);
        indices[0] = start_idx; 
        string current_guess(length, CHARSET[0]);
        bool local_found = false;

        while (true) {
            for (int i = 0; i < length; i++) {
                current_guess[i] = CHARSET[indices[i]];
            }

            if (sha256(current_guess) == target_hash) {
                local_found = true;
                break;
            }

            int pos = length - 1;
            while (pos >= 1) { 
                indices[pos]++;
                if (indices[pos] < CHARSET_SIZE) break;
                indices[pos] = 0;
                pos--;
            }

            if (pos == 0) {
                break; 
            }
        }

       
        string reply = local_found ? current_guess : "NOT_FOUND";
        MPI_Send(reply.c_str(), reply.size() + 1, MPI_CHAR, 0, TAG_RESULT, MPI_COMM_WORLD);
    }
}

int main(int argc, char* argv[]) {
    MPI_Init(&argc, &argv);

    int rank, num_procs;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &num_procs);

    if (argc != 3) {
        if (rank == 0) cerr << "Usage: mpirun -np <procs> ./mpi_cracker <length> <hash>" << endl;
        MPI_Finalize();
        return 1;
    }

    int length = stoi(argv[1]);
    string target_hash = argv[2];

    if (num_procs < 2) {
        if (rank == 0) cerr << "Error: MPI requires at least 2 processes (1 Master, 1+ Workers)." << endl;
        MPI_Finalize();
        return 1;
    }

    if (rank == 0) {
        cout << "--- MPI Distributed Brute-Force Cracker ---" << endl;
        cout << "Target: " << target_hash << " | Length: " << length << " | Total Processes: " << num_procs << endl;
        masterProcess(num_procs, length, target_hash);
    } else {
        workerProcess(rank, length, target_hash);
    }

    MPI_Finalize();
    return 0;
}
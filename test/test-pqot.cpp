#include "pq-ot/pq-ot.h"
#include <iostream>
#include <vector>
#include <utility>
#include <unordered_set>
#include <bitset>
#include <random>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;
using namespace emp;

int role;
int port;
int num_threads = 1;
int num_ot = 2;
int bitlen = 256;
int plain_modulus_bitlen = 17;
string address = "127.0.0.1";

// #########################################################################################
// ------------------------------ Constants-------------------------------------------------
// #########################################################################################
const int m = pow(2,10); // m ot_count
const int l = 128; // l base_ot_count
const int n = 256; // n input_length, also the output length of hash
const int k = 128; // k base_ot_msg_length，key_length of PRG(AES-CTR)

// #########################################################################################
// ------------------------------  Base OT -------------------------------------------------
// #########################################################################################
void baseOT( NetIO *io, int role, int port, int bitlen, int num_ot, mpz_t *m_0, mpz_t *m_1, mpz_t *m_b, bool *b) {

    PQOT ot(io, role, num_threads, plain_modulus_bitlen);
    io->sync();
    // Keygen
    ot.keygen();
    // Oblivious Transfer
    io->sync();

    if (role == ALICE) {
        ot.send_ot(m_0, m_1, num_ot, bitlen);
    } else { // role == BOB
        ot.recv_ot(m_b, b, num_ot, bitlen);
    }
    cout << "Base OT Verification: " << endl;
    bool flag;
    if (role == ALICE) {
        flag = ot.verify(m_0, m_1, num_ot);
        for (int i = 0; i < num_ot; i++) {
        }
    } else { // role == BOB
        flag = ot.verify(m_b, b, num_ot);
        for (int i = 0; i < num_ot; i++) {
        }
    }
    assert(flag == true && "Failed Operation");
    cout << "Successful Operation: " << flag << endl;
}

// #########################################################################################
// ------------------------------  Utils   -------------------------------------------------
// #########################################################################################
class Utils {
public:
    static mpz_t *initRandomMatrix(int rows, int cols) {
        mpz_t *result = new mpz_t[cols];
        gmp_randstate_t state;
        gmp_randinit_default(state);

        for (int i = 0; i < cols; ++i) {
            mpz_init(result[i]);
            mpz_urandomb(result[i], state, rows);
        }

        gmp_randclear(state);
        return result;
    }
    static mpz_t *init1Matrix(int rows, int cols) {
        mpz_t *result = new mpz_t[cols];


        for (int i = 0; i < cols; ++i) {
            mpz_init(result[i]);
            mpz_t bits;
            Utils::setBits(bits, rows, 1);
            mpz_set(result[i], bits);
        }

        return result;
    }

    static mpz_t *initMatrix(int rows, int cols) {
        mpz_t *result = new mpz_t[cols];
        for (int i = 0; i < cols; ++i) {
            mpz_init2(result[i], rows);
        }
        return result;
    }

    static void randomBits(mpz_t &obj, int size) {
        gmp_randstate_t state;
        gmp_randinit_default(state);

        mpz_init(obj);
        mpz_urandomb(obj, state, size);

        gmp_randclear(state);
    }

    static bool *mpzToBoolArray(mpz_t value, int size) {
        bool *boolArray = new bool[size];

        for (int i = 0; i < size; ++i) {
            bool bit = mpz_tstbit(value, i);
            boolArray[size - 1 - i] = bit;
        }

        return boolArray;
    }

    static mpz_t *xorMatrices(const mpz_t *arr1, const mpz_t *arr2, int cols) {
        mpz_t *result = new mpz_t[cols];
        for (int i = 0; i < cols; ++i) {
            mpz_init(result[i]);
            mpz_xor(result[i], arr1[i], arr2[i]);
        }
        return result;
    }

    static mpz_t *xorMatrixAndValue(const mpz_t *arr1, const mpz_t value, int cols) {
        mpz_t *result = new mpz_t[cols];
        for (int i = 0; i < cols; ++i) {
            mpz_init(result[i]);
            mpz_xor(result[i], arr1[i], value);
        }
        return result;
    }

    static void setBits(mpz_t &obj, int length, bool bitValue) {
        mpz_init(obj);
        for (int i = 0; i < length; ++i) {
            if (bitValue)
                mpz_setbit(obj, i);
            else
                mpz_clrbit(obj, i);
        }
    }

    static mpz_t *andMatrixAndValue(const mpz_t *arr1, const mpz_t value, int rows, int cols) {
        mpz_t *result = new mpz_t[cols];
        for (int i = 0; i < cols; ++i) {
            mpz_init(result[i]);
            mpz_t bits;
            Utils::setBits(bits, rows, mpz_tstbit(value, cols-1-i));
            mpz_and(result[i], arr1[i], bits);
        }
        return result;
    }

    static void print_mpz(mpz_t *matrix, int cols) {
        for (int i = 0; i < cols; ++i) {
            char *str = mpz_get_str(NULL, 2, matrix[i]);
            cout << "Element " << i << ": " << strlen(str) << endl;
            printf("%s\n", str);
            free(str);
        }
    }

    static void comp_print_mpz(mpz_t *matrix1,mpz_t *matrix2, int cols, bool printDetails) {
        int sum = 0;
        for (int i = 0; i < cols; ++i) {
            char *m1Str = mpz_get_str(NULL, 2, matrix1[i]);
            char *m2Str = mpz_get_str(NULL, 2, matrix2[i]);
            if (printDetails) {
                printf("%s\n", m1Str);
                printf("%s\n", m2Str);
                cout << "--" << endl;
            }
            sum += mpz_cmp(matrix1[i], matrix2[i]);
            free(m1Str);
            free(m2Str);
        }
        if (sum == 0) {
            cout << "Successful OT Extension." << endl;
        }
        else {
            cout << "Failed OT Extension." << endl;
        }
    }

    static void comp3_print_mpz(mpz_t *matrix1,mpz_t *matrix2,mpz_t *matrix3, int cols) {
        for (int i = 0; i < cols; ++i) {
            char *m1Str = mpz_get_str(NULL, 2, matrix1[i]);
            char *m2Str = mpz_get_str(NULL, 2, matrix2[i]);
            char *m3Str = mpz_get_str(NULL, 2, matrix3[i]);
            printf("%s\n", m1Str);
            printf("%s\n", m2Str);
            printf("%s\n", m3Str);
            cout << "--" << endl;
            free(m1Str);
            free(m2Str);
            free(m3Str);
        }
    }

    static mpz_t **convert1DArrayTo2D(mpz_t *arr, int rows, int cols) {
        mpz_t **result = new mpz_t *[rows];
        for (int i = 0; i < rows; ++i) {
            result[i] = new mpz_t[cols];
            for (int j = 0; j < cols; ++j) {
                mpz_init(result[i][j]);
                unsigned int bitValue = mpz_tstbit(arr[j], rows-i-1);
                mpz_set_ui(result[i][j], bitValue);
            }
        }
        return result;
    }

    static mpz_t *convert2DArrayTo1D(mpz_t **arr, int rows, int cols) {
        mpz_t *result = new mpz_t[cols];
        for (int j = 0; j < cols; ++j) {
            mpz_t rowValue;
            mpz_init(rowValue);
            for (int i = 0; i < rows; ++i) {
                mpz_t bitValue;
                mpz_init_set(bitValue, arr[i][j]);
                mpz_mul_2exp(rowValue, rowValue, 1);
                mpz_ior(rowValue, rowValue, bitValue);
                mpz_clear(bitValue);
            }
            mpz_init_set(result[j], rowValue);
            mpz_clear(rowValue);
        }

        return result;
    }

    static void createMatrix(mpz_t**& matrix, int rows, int cols) {
        matrix = new mpz_t*[rows];
        for (int i = 0; i < rows; ++i) {
            matrix[i] = new mpz_t[cols];
            for (int j = 0; j < cols; ++j) {
                mpz_init(matrix[i][j]);
            }
        }
    }
};


// #########################################################################################
// -------------------------------------- PRG ----------------------------------------------
// #########################################################################################
class PRG_AES_CTR {
public:
    static unsigned char iv[EVP_MAX_IV_LENGTH];
    static bool generateNewIV;
    static const char ivFilename[];

    PRG_AES_CTR(bool generateNewIV) {
        ivGenerator(generateNewIV);
    }

    static void ivGenerator(bool generateNewIV) {
        if (generateNewIV) {
            RAND_poll();
            RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        }
    }

    static void encrypt(unsigned char* key, unsigned char* buffer, size_t numBytes, unsigned char* ciphertext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        
        int ciphertextLen = 0;
        EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLen, buffer, numBytes);
        
        int finalLen = 0;
        EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &finalLen);
        
        EVP_CIPHER_CTX_free(ctx);
    }

    static void decrypt(unsigned char* key, unsigned char* ciphertext, size_t ciphertextLen, unsigned char* plaintext) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 0);
        
        int plaintextLen = 0;
        EVP_DecryptUpdate(ctx, plaintext, &plaintextLen, ciphertext, ciphertextLen);
        
        int finalLen = 0;
        EVP_DecryptFinal_ex(ctx, plaintext + plaintextLen, &finalLen);
        
        EVP_CIPHER_CTX_free(ctx);
    }

    static mpz_t* prg(mpz_t* key, size_t inlen_k, size_t outlen_m, size_t outlen_l) {
        mpz_t * G_k = new mpz_t[outlen_l];
        for (size_t i = 0; i < outlen_l; i++) {
            char* kBiStr = mpz_get_str(NULL, 2, key[i]);
            size_t numBytes = (outlen_m + 7) / 8; 
            size_t excessBits = numBytes * 8 - outlen_m;
            unsigned char * output = new unsigned char[numBytes];
            unsigned char* input = new unsigned char[numBytes];
            memset(input, 0, numBytes); 
            encrypt(reinterpret_cast<unsigned char*>(kBiStr), input, numBytes, output);
            mpz_t tmp;
            mpz_init(tmp);
            mpz_import(tmp, numBytes, 1, sizeof(unsigned char), 0, 0, output);
            mpz_init(G_k[i]);
            mpz_tdiv_q_2exp(G_k[i], tmp, excessBits);
            mpz_clear(tmp);
            delete [] input;
            delete [] output;
        }
        return G_k;
    }
};
unsigned char PRG_AES_CTR::iv[EVP_MAX_IV_LENGTH] = {0x2a, 0x5c, 0xe9, 0xf1, 0x86, 0xd3, 0x71, 0x9a, 0xc2, 0x07, 0xbe, 0x34, 0xfd, 0xa9, 0x5e, 0x81};
bool PRG_AES_CTR::generateNewIV = false;

// #########################################################################################
// -------------------------------------- H ----------------------------------------------
// #########################################################################################

class Hash {
public:
    static void mpzToSHA256Hash(mpz_t integer, mpz_t hashInteger) {
        // Convert mpz_t to a string
        // cout << integer << endl;

        char *integerStr = mpz_get_str(NULL, 2, integer);
    //    cout << strlen(integerStr) << endl;

        std::string integerString(integerStr);
        while (integerString.length() < l){
            // integerString = '0'+ integerString;
            integerString = std::string(l - integerString.length(), '0') + integerString;
        }
        // cout << integerString.length() << endl;
        free(integerStr);
        // Calculate the SHA-256 hash
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, integerString.c_str(), integerString.length());
        SHA256_Final(hash, &sha256);

        // Convert the hash to an mpz_t integer
        mpz_import(hashInteger, SHA256_DIGEST_LENGTH, 1, sizeof(unsigned char), 0, 0, hash);
    }

    static mpz_t *matrix(mpz_t *input, size_t cols) {
        mpz_t *result = new mpz_t[cols];
        for (size_t i = 0; i < cols; i++) {
            mpz_init(result[i]);
            Hash::mpzToSHA256Hash(input[i], result[i]);
        }
        return result;
    }
};

// #########################################################################################
// ------------------------------ Eklundh Transposition ------------------------------------
// #########################################################################################

class Eklundh_transposition {
public:
    static vector<vector<pair<int, int>>> generatePairs(int dim) {
        int steps = log2(dim);
        vector<vector<pair<int, int>>> pairs;
        for (int j = 0; j < steps; j++) {
            vector<pair<int, int>> pairsPerStep;
            unordered_set<int> usedRows;
            int offset = pow(2,j);
            for (int r1 = 0; r1 < dim; r1++) {
                int r2 = r1 ^ offset; // 001 <=> 1
                if (usedRows.count(r1) == 0 && usedRows.count(r2) == 0) {
                    pairsPerStep.push_back(make_pair(r1, r2));
                    usedRows.insert(r1);
                    usedRows.insert(r2);
                }
            }
            pairs.push_back(pairsPerStep);
            usedRows.clear(); 
            pairsPerStep.clear();     
        }
        return pairs;
    }

    static void Eklundh_trans_square(mpz_t ** mat, int dim, int startRow, vector<vector<pair<int, int>>> pairs) {
        for (const auto& pairsPerstep : pairs) {
            for (const auto& rows : pairsPerstep) {
                for (const auto& cols : pairsPerstep) {  //columns pairs: pair.second & pair.first 
                    mpz_swap(mat[startRow + rows.first][cols.second],mat[startRow + rows.second][cols.first]); 
                }
            } 
        }
    }

    static mpz_t * transpose(mpz_t * arr, size_t rows, size_t cols) {
        vector<vector<pair<int, int>>> pairs = generatePairs(cols);
        mpz_t ** mat = Utils::convert1DArrayTo2D(arr, rows, cols); 
        mpz_t ** trans;
        Utils::createMatrix(trans, cols, rows);
        size_t blocks = rows / cols;
        for (size_t i = 0; i < blocks; i++) {
            Eklundh_trans_square(mat, cols, i * cols, pairs);
            for (int r = 0; r < cols; r++) {
                for (int c = 0; c < cols; c++) {
                    mpz_set(trans[r][i * cols + c], mat[i * cols + r][c]);
                }
            }
        }
        mpz_t * result = Utils::convert2DArrayTo1D(trans, cols, rows);
        return result;
    }
};

mpz_t *naiveTranspose(mpz_t *arr, size_t rows, size_t cols) {
    mpz_t *transposedArr = Utils::initMatrix(cols,rows);
    for (size_t i = 0; i < cols; ++i) {
        for (size_t j = 0; j < rows; ++j) {
            int bit = mpz_tstbit(arr[i],  rows-j-1 );
            if (bit == 1)
                mpz_setbit(transposedArr[j], cols-i-1);
            else
                mpz_clrbit(transposedArr[j],  cols-i-1);
        }
    }

    return transposedArr;
}

// #########################################################################################
// ------------------------------  Communication -------------------------------------------
// #########################################################################################

class Communication {
public:
    NetIO * io;
    Communication(NetIO *io): io(io) {};

    void send(mpz_t * data, int rows, int cols) {
        // ADD COMMUNICATION COST TRACKING
        long double comm_cost = 0;
        for (int i = 0; i < cols; i++) {
            std::string data_str = mpz_get_str(nullptr, 10, data[i]);
            size_t len = data_str.length();
            io->send_data(&len, sizeof(size_t)); // Send the length first
            comm_cost += sizeof(size_t);
            io->send_data(data_str.c_str(), len); // Send the data
            comm_cost += len; 
        }
        cout << "OT Extension phase: Sending " << comm_cost / 1024.0 << " KiB" << endl;
    }
    mpz_t* receive(int rows, int cols) {
        mpz_t * data = new mpz_t[cols];
        for (int i = 0; i < cols; i++) {
            size_t len;
            io->recv_data(&len, sizeof(size_t)); // Receive the length first
            char* data_str = new char[len + 1];
            io->recv_data(data_str, len); // Receive the data
            data_str[len] = '\0'; // Null-terminate the string
            mpz_init_set_str(data[i], data_str, 10);
            delete[] data_str; // Remember to free the allocated memory
        }
        return data;
    }

};

int main(int argc, char **argv) {

    emp::parse_party_and_port(argv, &role, &port);
    if (argc >= 4) address = argv[3];
    if (argc >= 5) num_ot = atoi(argv[4]);
    if (argc >= 6) bitlen = atoi(argv[5]);
    if (argc >= 7) num_threads = atoi(argv[6]);

    // ----------- Preperation Phase-----------

    cout << "Performing " << m << " 1oo2 OTs on " << n
        << "-bit messages " << endl;
    
    chrono::high_resolution_clock::time_point time_start, time_end;
    time_start = chrono::high_resolution_clock::now();

    mpz_t *alice_x0 = Utils::initRandomMatrix(n, m); // x0
    mpz_t *alice_x1 = Utils::initRandomMatrix(n, m); // x1
    mpz_t bob_r;
    Utils::randomBits(bob_r, m); // r

    // -----------Initial OT Phase-----------

    cout << "###### 1. (a) ######" << endl;
    mpz_t alice_s;
    Utils::randomBits(alice_s, l);
    mpz_t *alice_sr = Utils::initMatrix(k, l); // result of base OT; k^s
    mpz_t *bob_k0 = Utils::initRandomMatrix(k, l);     // Random msgs for base OT
    mpz_t *bob_k1 = Utils::initRandomMatrix(k, l);    // Random msgs for base OT

    cout << "###### 1. (b) ######" << endl;
    time_start = chrono::high_resolution_clock::now();

    NetIO *io = new NetIO(role == ALICE ? NULL : address.c_str(), port);
    Communication channel(io);
    io->sync();
    baseOT(io, role == 1 ? 2 : 1, port, k, l, bob_k0, bob_k1,
           alice_sr, Utils::mpzToBoolArray(alice_s, l));
    
    time_end = chrono::high_resolution_clock::now();
    chrono::duration<double> time_base = time_end - time_start;
    cout << l << " 1oo2 Base OTs on " << k
        << "-bit messages Time: " << time_base.count() << " seconds" << endl;

    // -----------OT Extension phase-----------

    time_start = chrono::high_resolution_clock::now();

    PRG_AES_CTR prg_obj(false);

    if (role == BOB) {
        cout << "###### 2. (a) ######" << endl;

        mpz_t *bob_T = prg_obj.prg(bob_k0, k, m, l); // G(k^0): m * l
        mpz_t *PRG_k1 = prg_obj.prg(bob_k1,  k, m, l); // G(K^1): m * l
        mpz_t *bob_u_step1 = Utils::xorMatrices(bob_T, PRG_k1, l);
        mpz_t *bob_u = Utils::xorMatrixAndValue(bob_u_step1, bob_r, l); // u^i: m * l
        channel.send(bob_u, m, l);

        cout << "###### 2. (e) ######" << endl;

        mpz_t *bob_t_transposed = naiveTranspose(bob_T, m, l);
        // mpz_t *bob_t_transposed = Eklundh_transposition::transpose(bob_T, m, l);
        mpz_t *H_bob_t_transposed = Hash::matrix(bob_t_transposed, m);
        mpz_t *alice_y0 = channel.receive(n, m);
        mpz_t *alice_y1 = channel.receive(n, m);
        io->sync();
        delete io;
        mpz_t *alice_yr = new mpz_t[m];
        for (int i = 0; i < m; ++i) {
            mpz_init(alice_yr[i]);
            if (mpz_tstbit(bob_r, m-1-i) == 1) {
                mpz_set(alice_yr[i], alice_y1[i]);
            } else {
                mpz_set(alice_yr[i], alice_y0[i]);
            }
        }
        mpz_t *bob_xr;
        bob_xr = Utils::xorMatrices( alice_yr, H_bob_t_transposed, m);

        time_end = chrono::high_resolution_clock::now();
        chrono::duration<double> time_extension = time_end - time_start;
        cout << "OT Extension Time: " << time_extension.count() << " seconds" << endl;

        cout << "----------------3. Verificaton Instead of Output---------------------- " << endl;
            mpz_t *correct_result = new mpz_t[m];;
            // Calculated correct output
            for (int i = 0; i < m; ++i) {
                mpz_init(correct_result[i]);
                if (mpz_tstbit(bob_r, m-1-i) == 1) {
                    mpz_set(correct_result[i], alice_x1[i]);
                } else {
                    mpz_set(correct_result[i], alice_x0[i]);
                }
            }
            Utils::comp_print_mpz(bob_xr, correct_result, m, false);
    } 

    else {
        cout << "###### 2. (b) ######" << endl;

        mpz_t * bob_u = channel.receive(m, l);
        mpz_t *alice_q_step1 = Utils::andMatrixAndValue(bob_u, alice_s, m, l);
        mpz_t *PRG_alice_sr = prg_obj.prg(alice_sr, k, m, l);
        mpz_t *alice_q = Utils::xorMatrices(alice_q_step1, PRG_alice_sr, l);

        cout << "###### 2. (c) ######" << endl;

        mpz_t *alice_q_transposed = naiveTranspose(alice_q, m, l);
        // mpz_t *alice_q_transposed = Eklundh_transposition::transpose(alice_q, m, l);

        cout << "###### 2. (d) ######" << endl;

        mpz_t *H_alice_q_transposed = Hash::matrix(alice_q_transposed, m);
        mpz_t *alice_y0 = Utils::xorMatrices(alice_x0, H_alice_q_transposed, m);
        channel.send(alice_y0, n, m);
        mpz_t *alice_q_transposed_xor_s = Utils::xorMatrixAndValue(alice_q_transposed, alice_s, m);
        mpz_t *H_alice_q_transposed_xor_s = Hash::matrix(alice_q_transposed_xor_s, m);
        mpz_t *alice_y1 = Utils::xorMatrices(alice_x1, H_alice_q_transposed_xor_s, m);
        channel.send(alice_y1, n, m);
        io->sync();
        delete io;

    } 

    return 0;
}


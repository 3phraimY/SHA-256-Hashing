#ifndef SHA_HPP
#define SHA_HPP

#include <array>
#include <bitset>
#include <iomanip>
#include <iostream>
#include <queue>
#include <string.h>
#include <vector>
#include <stdint.h>

class SHA 
{
    private:
        /* fields */
        // length of the original message
        uint64_t length;

        // message schedule derived from chunks
        std::vector< std::array<uint32_t, 64> > messageSchedule;

        // initial values for the hash
        uint32_t hashInit[8] = 
        {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        // initial round constants
        uint32_t roundInit[64] = 
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // queue to hold all of the 32-bit words derived from the input stream
        std::queue<uint32_t> words;

        // vector to hold all of the chunks. Each chunk is composed of 512 bits (sixteen words)
        std::queue<std::vector<uint32_t>> chunks;

        /* helper functions */

        // converts the input string into 32-bit words four chars at a time, adding them to the SHA object's words queue
        // the characters represented are padded with a 1-bit followed by 0-bits until the last word is full
        // if the input array is perfectly divisible by four, an additional word will be added following the convention mentioned previously
        void concatenateBits(const char * charArray);
        
        // creates a new chunks from the the words queue
        // each chunk consists of sixteen words. The final 64 bits (two words)
        // of a the final chunk will always represent the length of the input array
        // if a chunk is only partially filled, words composed of all zeroes will be appended
        void populateChunks();

        // creates a new message schedule for each chunk. 
        // Since the chunk is already split into 16 32-bit words, we already have our desired denomination
        //It then undergoes the hashing technique required by SHA-256.
        void createMessageSchedule();

        // functions for filling out the last 48 words of the message. Derived from first sixteen words, which is the chunk currently being operated on.
        uint32_t sigmaZero(uint32_t input);
        uint32_t sigmaOne(uint32_t input);

        // functions used in the compression algorithm. 
        uint32_t capSigmaZero(uint32_t input);
        uint32_t capSigmaOne(uint32_t input);
        uint32_t choose(uint32_t e, uint32_t f, uint32_t g);
        uint32_t majority(uint32_t a, uint32_t b, uint32_t c);

        // compresses message schedule into hashed values.
        uint32_t * compress();
        
    public:
        SHA(const char * input);
};

#endif
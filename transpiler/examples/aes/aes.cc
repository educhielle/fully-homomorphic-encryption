// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "aes.h"

void aes_decrypt();
void add_roundKey(int round);
void aes_encrypt();
void inv_mix_column();
void inv_shift_row();
void inv_sub_byte();
void key_expansion(const vector<uint8_t> &);
void mix_column();
uint8_t Multiply(uint8_t, uint8_t);
void shift_row();
void sub_byte();
uint8_t xtime(uint8_t);

vector<uint8_t> round_key(KEY_EXP_SIZE);
vector<vector<uint8_t>> state;

void aes_decrypt()
{
    uint8_t round = AES_ROUND;

    add_roundKey(round);

    for (round = (AES_ROUND - 1); round > 0; --round)
    {
        inv_shift_row();
        inv_sub_byte();
        add_roundKey(round);
        inv_mix_column();
    }

    inv_shift_row();
    inv_sub_byte();
    add_roundKey(0);
}

void add_roundKey(int round)
{
    for (int i = 0; i < ROW_LEN; i++)
        for (int j = 0; j < COL_LEN; j++)
            state[i][j] ^= round_key[round * KEYLEN + i * ROW_LEN + j];
}

// #pragma hls_top
// vector<uint8_t> AES_ECB_decrypt(const vector<uint8_t> & input, const vector<uint8_t> & key)
// {
//     state = util::array2matrix(input, ROW_LEN, COL_LEN);
//     key_expansion(key);
//     aes_decrypt();
//     return util::matrix2array(state);
// }

#pragma hls_top
vector<uint8_t> AES_ECB_encrypt(const vector<uint8_t> & input, const vector<uint8_t> & key)
{
    state = util::array2matrix(input, ROW_LEN, COL_LEN);
    key_expansion(key);
    aes_encrypt();
    return util::matrix2array(state);
}

void aes_encrypt()
{
    int round = 0;
    // pre-whitening layer
    add_roundKey(round);

    // run this loop for n-1 rounds; 9 roundsfor AES-128
    for (round = 1; round < AES_ROUND; round++)
    {
        sub_byte();
        shift_row();
        mix_column();
        add_roundKey(round);
    }

    // final round
    sub_byte();
    shift_row();
    add_roundKey(round);
}

void inv_mix_column()
{
    int i;
    uint8_t b0, b1, b2, b3;
    for (i = 0; i < 4; ++i)
    {
        b0 = state[i][0];
        b1 = state[i][1];
        b2 = state[i][2];
        b3 = state[i][3];

        state[i][0] = Multiply(b0, 0x0e) ^ Multiply(b1, 0x0b) ^ Multiply(b2, 0x0d) ^ Multiply(b3, 0x09);
        state[i][1] = Multiply(b0, 0x09) ^ Multiply(b1, 0x0e) ^ Multiply(b2, 0x0b) ^ Multiply(b3, 0x0d);
        state[i][2] = Multiply(b0, 0x0d) ^ Multiply(b1, 0x09) ^ Multiply(b2, 0x0e) ^ Multiply(b3, 0x0b);
        state[i][3] = Multiply(b0, 0x0b) ^ Multiply(b1, 0x0d) ^ Multiply(b2, 0x09) ^ Multiply(b3, 0x0e);
    }
}

void inv_shift_row()
{
    uint8_t temp;

    // Rotate first row 1 columns to right
    temp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;

    // Rotate second row 2 columns to right
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // Rotate third row 3 columns to right
    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;
}

void inv_sub_byte()
{
    for (int i = 0; i < ROW_LEN; i++)
        for (int j = 0; j < COL_LEN; j++)
            state[i][j] = rsbox[state[i][j]];
}

void key_expansion(const vector<uint8_t> & key)
{
    int i;
    uint8_t temp[4], k;

    // first round key is same as master key
    for (i = 0; i < WORD_IN_KEY; i++)
    {
        round_key[(i * 4) + 0] = key[(i * 4) + 0];
        round_key[(i * 4) + 1] = key[(i * 4) + 1];
        round_key[(i * 4) + 2] = key[(i * 4) + 2];
        round_key[(i * 4) + 3] = key[(i * 4) + 3];
    }

    for (i = 4; i < WORD_IN_KEY * (ROUND + 1); i++)
    {
        // STEP 1 : temp = WORD[i-1]
        temp[0] = round_key[((i - 1) * 4) + 0];
        temp[1] = round_key[((i - 1) * 4) + 1];
        temp[2] = round_key[((i - 1) * 4) + 2];
        temp[3] = round_key[((i - 1) * 4) + 3];

        //STEP 2 : if (i%4 = 0) then temp = SubWord(RotWord(temp)) ^ RCon[i/4]
        if (i % 4 == 0)
        {
            // RotWord(temp)
            k = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = k;

            //SubWord(RotWord(temp))
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            //SubWord(RotWord(temp)) ^ RCon[i/4]
            temp[0] = temp[0] ^ Rcon[i / 4];
        }

        //STEP 3 : WORD[i] = WORD[i-4] ^ temp
        round_key[(i * 4) + 0] = round_key[((i - 4) * 4) + 0] ^ temp[0];
        round_key[(i * 4) + 1] = round_key[((i - 4) * 4) + 1] ^ temp[1];
        round_key[(i * 4) + 2] = round_key[((i - 4) * 4) + 2] ^ temp[2];
        round_key[(i * 4) + 3] = round_key[((i - 4) * 4) + 3] ^ temp[3];
    }
}

void mix_column()
{
    int i, j;
    uint8_t mul_by_2[4];
    uint8_t temp;
    uint8_t temp_state[4];
    uint8_t current_state[4];

    for (i = 0; i < 4; i++)
    {
        mul_by_2[0] = ((state[i][0] << 1) ^ (0x1B * ((state[i][0] >> 7) & 1)));
        mul_by_2[1] = ((state[i][1] << 1) ^ (0x1B * ((state[i][1] >> 7) & 1)));
        mul_by_2[2] = ((state[i][2] << 1) ^ (0x1B * ((state[i][2] >> 7) & 1)));
        mul_by_2[3] = ((state[i][3] << 1) ^ (0x1B * ((state[i][3] >> 7) & 1)));

        temp_state[0] = mul_by_2[0] ^ state[i][3] ^ state[i][2] ^ (mul_by_2[1] ^ state[i][1]);
        temp_state[1] = mul_by_2[1] ^ state[i][0] ^ state[i][3] ^ (mul_by_2[2] ^ state[i][2]);
        temp_state[2] = mul_by_2[2] ^ state[i][1] ^ state[i][0] ^ (mul_by_2[3] ^ state[i][3]);
        temp_state[3] = mul_by_2[3] ^ state[i][2] ^ state[i][1] ^ (mul_by_2[0] ^ state[i][0]);

        state[i][0] = temp_state[0];
        state[i][1] = temp_state[1];
        state[i][2] = temp_state[2];
        state[i][3] = temp_state[3];
    }
}

uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
            ((y >> 1 & 1) * xtime(x)) ^
            ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

void shift_row()
{
    uint8_t temp;

    //second row rotate by one byte
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    // third row rotate by two byte
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    //fourth row rotate by 3 byte
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}

void sub_byte()
{
    for (int i = 0; i < ROW_LEN; i++)
        for (int j = 0; j < COL_LEN; j++)
            state[i][j] = sbox[ state[i][j] ];
}

uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (0x1B * ((x >> 7) & 1)));
}

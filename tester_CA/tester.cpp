/* Creates connection to CA and runs all the inputs from the test vector */

extern "C"
{
#include "tee_client_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
}
#include "tester.h"

#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

static const TEEC_UUID uuid = {
    0x12345678, 0x8765, 0x4321, { 'T', 'E', 'S', 'T', 'E', 'R', '0', '0'}
};

/* Data buffer sizes */
#define DATA_SIZE	256
#define SHA1_SIZE	20

/* SHA1 TA command IDs */
#define SHA1_UPDATE	0x00000001
#define SHA1_DO_FINAL	0x00000002
#define SHA224_DO_FINAL 0x00000003

const bool DEBUG_ENABLED = true;

//static void debug(std::string msg) {
//    if(DEBUG_ENABLED)
//        std::cout << msg << std::endl;
//}

bool Tester::runTests(const std::vector<TestData> &testDataVector, const CryptoAlgorithm algorithmToTest, uint32_t longestInput ) {
    CryptoAlgorithm algorithmtoUse = algorithmToTest;
    algorithmtoUse = algorithmtoUse;
    longestInput = longestInput;
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_SharedMemory in_mem;
    TEEC_Value input_length;
    TEEC_SharedMemory out_mem;
    TEEC_Result ret;
    uint32_t return_origin;
    uint32_t connection_method = TEEC_LOGIN_PUBLIC;
    char data[DATA_SIZE];
    uint8_t sha1[SHA1_SIZE];
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t tests = 0;
    uint32_t passed = 0;
    printf("START: example SHA1 calc app\n");

    memset((void *)&in_mem, 0, sizeof(in_mem));
    memset((void *)&out_mem, 0, sizeof(out_mem));
    memset((void *)&operation, 0, sizeof(operation));

    /* Initialize context */
    printf("Initializing context: ");
    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", ret);
        goto end_1;
    } else {
        printf("initiliazed\n");
    }

    /* Open session */
    printf("Openning session: ");
    ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
                           NULL, NULL, &return_origin);
    if (ret != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x\n", ret);
        goto end_2;
    } else {
        printf("opened\n");
    }

    /* Register shared memory for initial hash */

    /* Data */
    in_mem.buffer = data;
    in_mem.size = DATA_SIZE;
    in_mem.flags = TEEC_MEM_INPUT;

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEE_SUCCESS) {
        printf("Failed to register DATA shared memory\n");
        goto end_3;
    }
    printf("Registered in mem..\n");

    /* register a shared memory region to hold the output of the sha1 operation */
    out_mem.buffer = sha1;
    out_mem.size = SHA1_SIZE;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEE_SUCCESS) {
        printf("Failed to allocate SHA1 shared memory\n");
        goto end_3;
    }
    printf("Registered out mem..\n");

    /* Fill operation parameters */
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
                                            TEEC_VALUE_INPUT, TEEC_NONE);
    /*
     * reuse the origional input shared memory, because we have just updated the contents
     * of the buffer
     */
    operation.params[0].memref.parent = &in_mem;
    operation.params[1].memref.parent = &out_mem;

    for(i = 0; i < testDataVector.size(); ++i) {
        ++tests;
        TestData testData = testDataVector.at(i);
        std::cout << "testData.input: " << testData.input << std::endl;

        std::cout << "testData.input as hex: " << cstring_to_hexstring(testData.input.c_str(), testData.input.length()) << std::endl;
        memset(data, 0, DATA_SIZE);
        memset(sha1, 0, SHA1_SIZE);
        if(testData.input.length() >= DATA_SIZE) {
            printf("ERROR: Too long test string for the buffer");
            return false;
        }
        char* offset = data;
        for(uint32_t m = 0; m < testData.input.length(); ++m) {
            char c = testData.input.at(m);
            memset(offset, c, 1);
            ++offset;
        }
        input_length.a = testData.input.length();
        operation.params[2].value = input_length;
        /* Invoke command */
        printf("Invoking command: Do final sha1: ");
        ret = TEEC_InvokeCommand(&session, SHA1_DO_FINAL, &operation, &return_origin);
        if (ret != TEEC_SUCCESS) {
            printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
            goto end_4;
        } else {
            printf("done\n");
        }
        /* Print input */
        printf("Input was:");
        for (uint32_t k = 0; k < input_length.a; k++) {
            printf("%02x", data[k]);
        }
        printf("\n");
        /* Printf sha1 buf */

        printf("Calculated sha1: ");
        for (uint32_t l = 0; l < SHA1_SIZE; l++) {
            printf("%02x", sha1[l]);
        }

        printf("\n");
        char* result = reinterpret_cast<char*>(sha1);
        std::string resultString = cstring_to_hexstring(result,SHA1_SIZE);

        if(testData.expected_output.compare(resultString) == 0) {
            std::cout << "SUCCESS! Input was correctly encrypted to: " << resultString << std::endl;
            ++passed;
        } else {
            std::cout << "FAIL! Expected: " << testData.expected_output << std::endl << "     got: " << resultString << std::endl;
        }
    }
    std::cout << "TESTS PASSED/INPUTS: " << passed << "/" <<tests << std::endl;
    /* Cleanup used connection/resources */
end_4:

    printf("Releasing shared out memory..\n");
    TEEC_ReleaseSharedMemory(&out_mem);

end_3:
    printf("Releasing shared in memory..\n");
    TEEC_ReleaseSharedMemory(&in_mem);
    printf("Closing session..\n");
    TEEC_CloseSession(&session);

end_2:

    printf("Finalizing ctx..\n");
    TEEC_FinalizeContext(&context);
end_1:

    printf("END: example SHA1 calc app\n");
    exit(ret);
}

std::string Tester::hex_to_string(std::string hexString) {
    std::string str;
    for(uint32_t i=0; i < hexString.length(); i+=2) {
        std::string byte = hexString.substr(i,2);
        char c = (char) (int)strtol(byte.c_str(), nullptr, 16);
        str.push_back(c);
    }
    return str;
}
char const hex[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b','c','d','e','f'};
std::string Tester::cstring_to_hexstring(const char* str, uint strLength) {
    std::string hexstring;
    for (uint i = 0; i < strLength; ++i) {
        const char ch = str[i];
        hexstring.append(&hex[(ch  & 0xF0) >> 4], 1);
        hexstring.append(&hex[ch & 0xF], 1);
    }
    return hexstring;
}

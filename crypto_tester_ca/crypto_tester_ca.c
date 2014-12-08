#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static const TEEC_UUID uuid = {
    0x12345678, 0x8765, 0x4321, { 'S', 'H', 'A', 'T', 'E', 'S', 'T', 'S'}
};

#define MAX_ARGUMENT_LENGTH 50

/* Data buffer sizes */
#define DATA_SIZE	256
#define SHA1_SIZE 20
#define SHA224_SIZE 28
#define SHA256_SIZE 32
#define SHA384_SIZE 48
#define SHA512_SIZE	64

/* Hash TA command IDs for this applet */
#define HASH_UPDATE	0x00000001
#define HASH_DO_FINAL	0x00000002

/* Hash algoithm */
#define HASH_SHA1	0x00000001
#define HASH_SHA224	0x00000002
#define HASH_SHA256	0x00000003
#define HASH_SHA384	0x00000004
#define HASH_SHA512	0x00000005

#define MAX_INPUT_CHAR_LENGTH 10
#define MAX_INPUT_LENGTH_SINGLE_OPERATION 16

/* error codes */
#define UNKNOWN_ERROR 1
#define TOO_FEW_ARGUMENTS_ERROR 2
#define TOO_LONG_ARGUMENTS_ERROR 3
#define UNKNOWN_ALGORITHM_ERROR 4
#define INVALID_INPUT_FILE 5
#define INVALID_LENGTH_FILE 6
#define INVALID_OUTPUT_FILE 7
#define FAILED_TO_INITIALIZE_CONTEXT 8
#define FAILED_TO_OPEN_SESSION 9
#define FAILED_TO_REGISTER_INPUT_MEMORY 10
#define FAILED_TO_REGISTER_OUTPUT_MEMORY 11
#define FAILED_TO_INVOKE_COMMAND 12

#define ZERO_LENGTH_INPUTS 12

uint32_t get_input_length(char* input_length_str) {
    char* error;
    long length = 0;
    length = strtol(input_length_str, &error, 0);
    if(*error != '\0') {
        return 0;
    }
    return (uint32_t)length;
}

int run_sha_tests(char* input_file, char* length_file, char* expected_output_file, char* algorithm_to_test)
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_SharedMemory in_mem;
    TEEC_SharedMemory out_mem;
    TEEC_Result ret;
    uint32_t return_origin;
    uint32_t connection_method = TEEC_LOGIN_PUBLIC;
    char input[DATA_SIZE];
    uint8_t output[SHA512_SIZE];
    uint32_t algorithm = 0;
    uint32_t return_code = 0;
    char input_length_as_char[MAX_INPUT_CHAR_LENGTH];
    FILE *input_fd = NULL;
    FILE *length_fd = NULL;
    FILE *output_fd = NULL;
    uint32_t input_length;
    uint32_t i = 0;
    if(strcmp(algorithm_to_test, "SHA1") == 0) {
        algorithm = HASH_SHA1;
    } else if (strcmp(algorithm_to_test, "SHA224") == 0) {
        algorithm = HASH_SHA224;
    } else if (strcmp(algorithm_to_test, "SHA256") == 0) {
        algorithm = HASH_SHA256;
    } else if (strcmp(algorithm_to_test, "SHA384") == 0) {
        algorithm = HASH_SHA384;
    } else if (strcmp(algorithm_to_test, "SHA512") == 0) {
        algorithm = HASH_SHA512;
    } else {
        return UNKNOWN_ALGORITHM_ERROR;
    }

    /* Initialize context */
    printf("Initializing context: ");
    ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", ret);
        return_code = FAILED_TO_INITIALIZE_CONTEXT;
        goto end_1;
    } else {
        printf("initiliazed\n");
    }

    /* Open session is expecting HASH algorithm */
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = algorithm;

    /* Open session */
    printf("Openning session: ");
    ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
                           NULL, &operation, &return_origin);
    if (ret != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x\n", ret);
        return_code = FAILED_TO_OPEN_SESSION;
        goto end_2;
    } else {
        printf("opened\n");
    }

    /* Register shared memory for initial hash */

    /* Data */
    in_mem.buffer = input;
    in_mem.size = DATA_SIZE;
    in_mem.flags = TEEC_MEM_INPUT;

    ret = TEEC_RegisterSharedMemory(&context, &in_mem);
    if (ret != TEE_SUCCESS) {
        printf("Failed to register input shared memory\n");
        return_code = FAILED_TO_REGISTER_INPUT_MEMORY;
        goto end_3;
    }
    printf("Registered in mem..\n");
    /* register a shared memory region to hold the output of the operation */
    out_mem.buffer = output;
    out_mem.size = SHA512_SIZE;
    out_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

    ret = TEEC_RegisterSharedMemory(&context, &out_mem);
    if (ret != TEE_SUCCESS) {
        printf("Failed to allocate output shared memory\n");
        return_code = FAILED_TO_REGISTER_OUTPUT_MEMORY;
        goto end_3;
    }
    printf("Registered out mem..\n");

    // open input file and lengths file
    input_fd = fopen(input_file, "r");
    if (!input_fd) {
        return_code = INVALID_INPUT_FILE;
        goto end_4;
    }

    length_fd = fopen(length_file, "r");
    if(!length_fd) {
        return_code = INVALID_LENGTH_FILE;
        goto end_5;
    }
    output_fd = fopen(expected_output_file, "r");
    if(!output_fd) {
        return_code = INVALID_OUTPUT_FILE;
        goto end_5;
    }

    while(fgets(input_length_as_char, MAX_INPUT_CHAR_LENGTH, length_fd) != NULL) {
        input_length = get_input_length(input_length_as_char);
        if(input_length == 0) {
            return_code = ZERO_LENGTH_INPUTS;
            goto end_5;
        }
        while(input_length > MAX_INPUT_LENGTH_SINGLE_OPERATION) {
            fread(input,MAX_INPUT_LENGTH_SINGLE_OPERATION,1,input_fd);
            /* Fill operation parameters */
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
            operation.params[0].memref.parent = &in_mem;
            operation.params[1].value.a = MAX_INPUT_LENGTH_SINGLE_OPERATION;

            /* Invoke command */
            printf("Invoking command: Update sha: ");
            ret = TEEC_InvokeCommand(&session, HASH_UPDATE, &operation, &return_origin);
            if (ret != TEEC_SUCCESS) {
                printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
                return_code = FAILED_TO_INVOKE_COMMAND;
                goto end_5;
            } else {
                printf("done\n");
                input_length -= MAX_INPUT_LENGTH_SINGLE_OPERATION;
            }
        }
        fread(input,input_length,1,input_fd);

        /* Fill operation parameters */
        operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT,
                            TEEC_MEMREF_WHOLE, TEEC_NONE);
        /*
         * reuse the origional input shared memory, because we have just updated the contents
         * of the buffer
         */
        operation.params[0].memref.parent = &in_mem;
        operation.params[1].value.a = input_length;
        operation.params[2].memref.parent = &out_mem;

        /* Invoke command */
        printf("Invoking command: Do final sha1: ");
        ret = TEEC_InvokeCommand(&session, HASH_DO_FINAL, &operation, &return_origin);
        if (ret != TEEC_SUCCESS) {
            printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
            return_code = FAILED_TO_INVOKE_COMMAND;
            goto end_5;
        } else {
            printf("done\n");
        }
        /* Printf sha1 buf */
        printf("Calculated sha1: ");
        for (i = 0; i < SHA1_SIZE; i++)
            printf("%02x", output[i]);
        printf("\n");
        fgets(expected_output, SHA512_SIZE, output_fd);
    }
        /* Cleanup used connection/resources */
    end_5:
        if(input_fd != NULL) {
            fclose(input_fd);
        }
        if (output_fd != NULL) {
            fclose(output_fd);
        }
        if(length_fd != NULL) {
            fclose(length_fd);
        }
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
        return return_code;
}

int main(int argc, char **argv)
{
    int option;
    char* input_file;
    char* length_file;
    char* expected_output_file;
    char* algorithm_to_test;
    while((option = getopt(argc,argv, "i:l:e:a:")) != -1) {
        if(optarg == NULL || strlen(optarg) > MAX_ARGUMENT_LENGTH) {
            return TOO_LONG_ARGUMENTS_ERROR;
        }
        switch(option) {
        case 'i':
            input_file = optarg;
            break;
        case 'l':
            length_file = optarg;
        case 'e':
            expected_output_file = optarg;
            break;
        case 'a':
            algorithm_to_test = optarg;
            break;
        default:
            printf("unknown error");
            return UNKNOWN_ERROR;
        }
    }
    printf("input file: %s\n", input_file);

    printf("expected output file: %s\n" ,expected_output_file);

    printf("algorithm to test: %s\n", algorithm_to_test);

    return run_sha_tests(input_file, length_file, expected_output_file, algorithm_to_test);
}

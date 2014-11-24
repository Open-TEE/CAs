/*****************************************************************************
** Copyright 2014 Hannu Lahtinen hannu.lahtinen@student.tut.fi              **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
**                                                                          **
** ClientApplication for Open-TEE project that is indended                  **
** to test handling of SHA calculations through out the project             **
**                                                                          **
** This file was created as part of an assignment work                      **
** for course "Turvallinen ohjelmointi part 2" in                           **
** Tampere University of Technology                                         **
**                                                                          **
** NOTE: This application is based on example_sha1_ca found at:             **
** http://github.com/Open-TEE/CAs/tree/master/example_sha1_ca               **
*****************************************************************************/

#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static const TEEC_UUID uuid = {
	0x12345678, 0x8765, 0x4321, { 'S', 'H', 'A', 'T', 'E', 'S', 'T', 'S' }
};

#define MAX_ARGUMENT_LENGTH 100

/*
 * Defines the max amount of characters in one input length read from the file.
 */
#define MAX_INPUT_CHAR_LENGTH 10

/*
 * Defines how long a string has to be before it is split into multiple updates
 * NOTE: needs to be less than DATA_SIZE to prevent buffer overflow on CA side
 */
#define MAX_INPUT_LENGTH_SINGLE_OPERATION 100

/* Data buffer sizes */
#define DATA_SIZE	512
#define HEX_OUTPUT_MAX_SIZE 1025
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

/* error codes */
#define UNEXPECTED_RESULT_FROM_TEST 1
#define UNKNOWN_ERROR 2
#define ARGUMENTS_ERROR 3
#define UNKNOWN_ALGORITHM_ERROR 4
#define INVALID_INPUT_FILE 5
#define INVALID_LENGTH_FILE 6
#define INVALID_OUTPUT_FILE 7
#define FAILED_TO_INITIALIZE_CONTEXT 8
#define FAILED_TO_OPEN_SESSION 9
#define FAILED_TO_REGISTER_INPUT_MEMORY 10
#define FAILED_TO_REGISTER_OUTPUT_MEMORY 11
#define FAILED_TO_INVOKE_COMMAND 12
#define OUTPUT_FILE_ENDED_UNEXPECTEDLY 13

/*
 * Turns a string in to an int
 * String can contain line end characters
 */
uint32_t get_input_length(char *input_length_str)
{
	uint32_t j;
	char *error;
	long length = 0;
	for (j = 0; j < strlen(input_length_str); ++j) {
		char one_char = input_length_str[j];
		if (one_char == '\n' || one_char == '\r')
			input_length_str[j] = '\0';
	}
	length = strtol(input_length_str, &error, 0);
	if (*error != '\0')
		return 0;
	return (uint32_t)length;
}

/*
 * Feeds x bytes from input_file to TA for every line in length
 * where x is the number value on that line in length file
 *
 * Compares output from TA to a line in expected_output_file
 * Line number of compared line is the same as line number
 * read from length file
 */
int run_sha_tests(char *input_file, char *length_file,
				char *expected_output_file, char *algorithm_to_test)
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
	char hex_output[HEX_OUTPUT_MAX_SIZE];
	char expected_hex_output[HEX_OUTPUT_MAX_SIZE];
	uint32_t algorithm = 0;
	uint32_t return_code = 0;
	char input_length_as_char[MAX_INPUT_CHAR_LENGTH];
	FILE *input_fd = NULL;
	FILE *length_fd = NULL;
	FILE *output_fd = NULL;
	uint32_t input_length;
	uint32_t i = 0;
	uint32_t inputs = 0;
	uint32_t succesful = 0;
	uint32_t size_to_use = 0;
	if (strcmp(algorithm_to_test, "SHA-1") == 0) {
		algorithm = HASH_SHA1;
		size_to_use = SHA1_SIZE;
	} else if (strcmp(algorithm_to_test, "SHA-224") == 0) {
		algorithm = HASH_SHA224;
		size_to_use = SHA224_SIZE;
	} else if (strcmp(algorithm_to_test, "SHA-256") == 0) {
		algorithm = HASH_SHA256;
		size_to_use = SHA256_SIZE;
	} else if (strcmp(algorithm_to_test, "SHA-384") == 0) {
		algorithm = HASH_SHA384;
		size_to_use = SHA384_SIZE;
	} else if (strcmp(algorithm_to_test, "SHA-512") == 0) {
		algorithm = HASH_SHA512;
		size_to_use = SHA512_SIZE;
	} else {
		printf("Unknown algorithm: %s\n", algorithm_to_test);
		return UNKNOWN_ALGORITHM_ERROR;
	}

	memset((void *)&in_mem, 0, sizeof(in_mem));
	memset((void *)&out_mem, 0, sizeof(out_mem));
	memset((void *)&operation, 0, sizeof(operation));

	/* Initialize context */
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", ret);
		return_code = FAILED_TO_INITIALIZE_CONTEXT;
		goto end_1;
	}

	/* Open session is expecting HASH algorithm */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
											TEEC_NONE, TEEC_NONE,
											TEEC_NONE);
	operation.params[0].value.a = algorithm;
	operation.started = 0;

	/* Open session */
	ret = TEEC_OpenSession(&context, &session, &uuid, connection_method,
						NULL, &operation, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		return_code = FAILED_TO_OPEN_SESSION;
		goto end_2;
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

	/* open files before loop */
	input_fd = fopen(input_file, "rb");
	if (input_fd == NULL) {
		printf("Failed to open input file\n");
		return_code = INVALID_INPUT_FILE;
		goto end_4;
	}

	length_fd = fopen(length_file, "r");
	if (length_fd == NULL) {
		printf("Failed to open length file\n");
		return_code = INVALID_LENGTH_FILE;
		goto end_5;
	}
	output_fd = fopen(expected_output_file, "r");
	if (output_fd  == NULL) {
		printf("Failed to open expected output file\n");
		return_code = INVALID_OUTPUT_FILE;
		goto end_5;
	}

	/* read length_fd line by line */
	while (fgets(input_length_as_char, MAX_INPUT_CHAR_LENGTH, length_fd) != NULL) {
		input_length = get_input_length(input_length_as_char);
		++inputs;

		/* update TA for every MAX_INPUT_LENGTH_SINGLE_OPERATION in input_length */
		while (input_length > MAX_INPUT_LENGTH_SINGLE_OPERATION) {

			/* read MAX_INPUT_LENGTH_SINGLE_OPERATION bytes from input file */
			fread(input, MAX_INPUT_LENGTH_SINGLE_OPERATION, 1, input_fd);

			/* Fill operation parameters */
			operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
													TEEC_VALUE_INPUT,
													TEEC_NONE, TEEC_NONE);
			operation.params[0].memref.parent = &in_mem;
			operation.params[1].value.a = MAX_INPUT_LENGTH_SINGLE_OPERATION;

			/* Invoke update command */
			ret = TEEC_InvokeCommand(&session, HASH_UPDATE, &operation, &return_origin);
			if (ret != TEEC_SUCCESS) {
				printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
				return_code = FAILED_TO_INVOKE_COMMAND;
				goto end_5;
			} else {
				input_length -= MAX_INPUT_LENGTH_SINGLE_OPERATION;
			}
		}
		/* read the rest of the input bytes
		 * if input was empty string(ie input_length=0)
		 * we don't need to read any bytes */
		if (input_length > 0)
			fread(input, input_length, 1, input_fd);

		/* Fill operation parameters */
		operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INPUT,
												TEEC_MEMREF_WHOLE, TEEC_NONE);

		/* reuse the original input shared memory */
		operation.params[0].memref.parent = &in_mem;
		operation.params[1].value.a = input_length;
		operation.params[2].memref.parent = &out_mem;

		/* Invoke do final command */
		ret = TEEC_InvokeCommand(&session, HASH_DO_FINAL, &operation, &return_origin);
		if (ret != TEEC_SUCCESS) {
			printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
			return_code = FAILED_TO_INVOKE_COMMAND;
			goto end_5;
		}
		/* Save calculated sha buf as hex */
		printf("Calculated %s: ", algorithm_to_test);
		for (i = 0; i < size_to_use; i++) {
			sprintf(&hex_output[i*2], "%02x", output[i]);
			if (hex_output[i*2] == '\0')
				break;
		}

		printf("%s\n", hex_output);

		/* read line from expected output file */
		if (fgets(expected_hex_output, HEX_OUTPUT_MAX_SIZE, output_fd) != NULL) {
			expected_hex_output[strlen(expected_hex_output)-1] = '\0';
			printf("Expected %s: %s ", algorithm_to_test, expected_hex_output);

			/* Compare test result and expected result */
			if (strcmp(expected_hex_output, hex_output) == 0) {
				printf("Test Success!\n");
				++succesful;
			} else {
				printf("Test failure!\n");
				return_code = UNEXPECTED_RESULT_FROM_TEST;
			}
		} else {
			printf("Expected output file %s", expected_output_file);
			printf(" ended unexpectedly\n");
			return_code = OUTPUT_FILE_ENDED_UNEXPECTEDLY;
			break;
		}
	}

/* Cleanup used connection/resources */
end_5:
	printf("Results for %s:\n", input_file);
	printf("%i / %i succesful/tested\n", succesful, inputs);
	if (input_fd != NULL)
		fclose(input_fd);
	if (output_fd != NULL)
		fclose(output_fd);
	if (length_fd != NULL)
		fclose(length_fd);
end_4:
	TEEC_ReleaseSharedMemory(&out_mem);

end_3:
	TEEC_ReleaseSharedMemory(&in_mem);
	TEEC_CloseSession(&session);

end_2:
	TEEC_FinalizeContext(&context);
end_1:
	return return_code;
}

int main(int argc, char **argv)
{
	int option;
	char *input_file;
	char *length_file;
	char *expected_output_file;
	char *algorithm_to_test;
	while ((option = getopt(argc, argv, "i:l:e:a:")) != -1) {
		switch (option) {
		case 'i':
			input_file = optarg;
			break;
		case 'l':
			length_file = optarg;
			break;
		case 'e':
			expected_output_file = optarg;
			break;
		case 'a':
			algorithm_to_test = optarg;
			break;
		case '?':
			printf("Unknown argument option\n");
			return ARGUMENTS_ERROR;
		case ':':
			printf("Missing argument\n");
			return ARGUMENTS_ERROR;
		default:
			printf("Unknown arguments error\n");
			return ARGUMENTS_ERROR;
		}
	}
	if (input_file == NULL || expected_output_file == NULL
			|| length_file == NULL || algorithm_to_test == NULL) {
		printf("All arguments are mandatory!\n");
		printf("Usage: ./this -aSHA-1 -iinput.in -eexpected.out -linput.length\n");
		return ARGUMENTS_ERROR;
	}
	printf("input file: %s\n", input_file);

	printf("expected output file: %s\n", expected_output_file);

	printf("algorithm to test: %s\n", algorithm_to_test);

	return run_sha_tests(input_file, length_file, expected_output_file, algorithm_to_test);
}

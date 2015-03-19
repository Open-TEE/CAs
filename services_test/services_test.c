/*****************************************************************************
** Copyright (C) 2015 Roni Jaakkola.                                        **
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
*****************************************************************************/

/* Simple application to test services TA's monotonic counter functionality.
 * This application simply calls the TA to return current counter value
 * and increment it. */

#include "tee_client_api.h"
#include "ta_services_ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {0x3E93632E, 0xA710, 0x469E, {'C', 'O', 'U', 'N', 'T', 'E', 'R'}};

static TEEC_Result open_session(TEEC_Context *context, TEEC_Session *session)
{
	TEEC_Operation operation;
	uint32_t connection_method = TEEC_LOGIN_PUBLIC;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Set the parameter types */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Open session */
	return TEEC_OpenSession(context, session, &uuid, connection_method, NULL, &operation, NULL);
}

static TEEC_Result invoke_command(TEEC_Session *session, TEEC_SharedMemory *inout_mem,
				  uint32_t command_type)
{
	TEEC_Operation operation;
	TEEC_Result ret;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Set the parameter types */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	operation.params[0].memref.parent = inout_mem;

	/* Invoke command */
	ret = TEEC_InvokeCommand(session, command_type, &operation, NULL);
	return ret;
}

static TEEC_Result do_counter_tests(TEEC_Session *session, TEEC_SharedMemory *inout_mem,
				    uint64_t *value)
{
	TEEC_Result ret;
	uint64_t previous_value;

	/* Get and increment the counter for the first time */
	ret = invoke_command(session, inout_mem, CMD_GET_CTR);
	if (ret != TEEC_SUCCESS)
		goto end;

	previous_value = *value;
	printf("Value after the first get_counter: %d\n", (int)*value);

	/* Increment it again and check that the value has changed */
	ret = invoke_command(session, inout_mem, CMD_GET_CTR);
	if (ret != TEEC_SUCCESS)
		goto end;

	printf("Value after the second get_counter: %d\n", (int)*value);
	if (++previous_value != *value)
		ret = TEEC_ERROR_GENERIC;

end:
	return ret;
}

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_SharedMemory inout_mem = {0};
	TEEC_Result ret;
	uint64_t value;

	printf("START: services test app\n");

	/* Initialize context */
	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%x\n", ret);
		goto end_1;
	} else {
		printf("initiliazed\n");
	}

	inout_mem.buffer = &value;
	inout_mem.size = sizeof(value);
	inout_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_RegisterSharedMemory(&context, &inout_mem);
	if (ret != TEE_SUCCESS) {
		printf("Failed to register shared memory");
		goto end_1;
	}

	/* Open session */
	printf("Opening session: ");
	ret = open_session(&context, &session);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("opened\n");
	}

	printf("Initialization complete\n");

	/* Invoke commands */
	printf("Testing the counter\n");
	ret = do_counter_tests(&session, &inout_mem, &value);
	if (ret != TEEC_SUCCESS) {
		printf("Counter test failed: 0x%x\n", ret);
		goto end_3;
	} else {
		printf("Counter test ok\n");
	}

/* Cleanup */
end_3:
	printf("Closing session: ");
	TEEC_CloseSession(&session);
	printf("closed\n");

end_2:
	TEEC_ReleaseSharedMemory(&inout_mem);
	printf("Finalizing context: ");
	TEEC_FinalizeContext(&context);
	printf("finalized\n");

end_1:
	printf("END: services test app\n");
	exit(ret);
}

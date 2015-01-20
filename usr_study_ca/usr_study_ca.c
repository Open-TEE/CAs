/*****************************************************************************
** Copyright (C) 2015 Intel Corporation.                                    **
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

/* NOTE!!
 *
 * This is implemented for user study. It is serving the purpose of user study!
 * Therefore it might not have the most perfect design choices and implementation.
 *
 * NOTE!!
 */

#include "tee_client_api.h"
#include "usr_study_ta_ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
	0x12345678, 0x8765, 0x4321, { 'U', 'S', 'R', 'S', 'T', 'U', 'D', 'Y'}
};

#define MAX_MSG_SIZE	100

#define DEPOSIT_MSG_1 "Winn"
#define DEPOSIT_MSG_2 "Salary"
#define DEPOSIT_MSG_3 "Sell old stuff"

#define WITHDRAW_MSG_1 "Rent"
#define WITHDRAW_MSG_2 "Gas"
#define WITHDRAW_MSG_3 "New TV from store"
#define WITHDRAW_MSG_4 "New phone from friends store"

static TEEC_Result open_session(TEEC_Context *context, TEEC_Session *session,
				uint32_t currency_type)
{
	TEEC_Operation operation;
	uint32_t conn_method = TEEC_LOGIN_PUBLIC;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Open session is expection account currency */
	operation.params[0].value.a = currency_type;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	/* Open session with TA */
	return TEEC_OpenSession(context, session, &uuid, conn_method, NULL, &operation, NULL);
}

static TEEC_Result exec_transaction(TEEC_Session *session, TEEC_SharedMemory *shm_inout,
				    uint32_t transaction_type, uint32_t amount,
				    char *msg, uint32_t msg_len)
{
	TEEC_Operation operation;

	/* Reset operation struct */
	memset((void *)&operation, 0, sizeof(operation));

	/* Set amount to operation */
	operation.params[0].value.a = amount;

	/* Copy message to shm and assign to operation */
	memcpy(shm_inout->buffer, msg, msg_len);
	operation.params[1].memref.parent = shm_inout;
	operation.params[1].memref.size = msg_len;

	/* Fill in parameters type */
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_WHOLE,
						TEEC_NONE, TEEC_NONE);

	/* Execute transaction*/
	if (transaction_type == USR_STUDY_CMD_DEPOSIT)
		return TEEC_InvokeCommand(session, USR_STUDY_CMD_DEPOSIT, &operation, NULL);
	else
		return TEEC_InvokeCommand(session, USR_STUDY_CMD_WITHDRAW, &operation, NULL);
}

static TEEC_Result do_dummy_transactions(TEEC_Session *session, TEEC_SharedMemory *shm_inout)
{
	TEE_Result ret = TEE_SUCCESS;

	printf("Invoking deposit: ");
	ret = exec_transaction(session, shm_inout, USR_STUDY_CMD_DEPOSIT,
			       2000, DEPOSIT_MSG_1, sizeof(DEPOSIT_MSG_1));
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		return ret;
	} else {
		printf("invoked\n");
	}

	printf("Invoking deposit: ");
	ret = exec_transaction(session, shm_inout, USR_STUDY_CMD_DEPOSIT,
			       500, DEPOSIT_MSG_2, sizeof(DEPOSIT_MSG_2));
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		return ret;
	} else {
		printf("invoked\n");
	}

	printf("Invoking whitdrawing: ");
	ret = exec_transaction(session, shm_inout, 1500, USR_STUDY_CMD_WITHDRAW,
			       WITHDRAW_MSG_1, sizeof(WITHDRAW_MSG_1));
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		return ret;
	} else {
		printf("whitdrawed\n");
	}

	printf("Invoking whitdrawing: ");
	ret = exec_transaction(session, shm_inout, 1500, USR_STUDY_CMD_WITHDRAW,
			       WITHDRAW_MSG_2, sizeof(WITHDRAW_MSG_2));
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		return ret;
	} else {
		printf("whitdrawed\n");
	}

	return ret;
}

int main()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_SharedMemory shm_inout;
	TEEC_Result ret;

	printf("START: usr study app\n");

	/* Initialize context */
	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_1;
	} else {
		printf("initiliazed\n");
	}


	/* Alloc used shared memory */
	printf("Allocating shared memory: ");

	shm_inout.size = MAX_MSG_SIZE;
	shm_inout.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

	ret = TEEC_AllocateSharedMemory(&context, &shm_inout);
	if (ret != TEE_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_2;
	} else {
		printf("allocated\n");
	}

	printf("Openning session: ");
	ret = open_session(&context, &session, USR_STUDY_CUR_X);
	if (ret != TEEC_SUCCESS) {
		printf("failed: 0x%x\n", ret);
		goto end_3;
	} else {
		printf("opened\n");
	}

	if (do_dummy_transactions(&session, &shm_inout) != TEE_SUCCESS)
		goto end_4;



	/* Cleanup used connection/resources */
end_4:
	printf("Closing session: ");
	TEEC_CloseSession(&session);
	printf("Closed\n");

end_3:
	printf("Releasing shared memory: ");
	TEEC_ReleaseSharedMemory(&shm_inout);
	printf("released\n");
end_2:
	printf("Finalizing ctx: ");
	TEEC_FinalizeContext(&context);
	printf("Finalized\n");

end_1:
	printf("END: usr study app\n");
	exit(ret);
}

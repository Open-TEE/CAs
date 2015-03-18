/* Simple application to test services TAs monotonic counter functionality.
 * This application simply calls the TA to return current counter value
 * and increment it. */

#include "tee_client_api.h"
#include "ta_services_ctrl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
	0x3E93632E, 0xA710, 0x469E, { 'C', 'O', 'U', 'N', 'T', 'E', 'R' }
};

#define DUMMY_DATA_SIZE 1024

static TEEC_Result
open_session(TEEC_Context *context, TEEC_Session *session)
{
   TEEC_Operation operation;
   uint32_t connection_method = TEEC_LOGIN_PUBLIC;

   /* Reset operation struct */
   memset((void *)&operation, 0, sizeof(operation));

   /* Set the parameter types */
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
                                           TEEC_NONE, TEEC_NONE);
   
   /* Open session */
   return TEEC_OpenSession(context, session, &uuid, connection_method, NULL,
                           &operation, NULL);
}

static TEEC_Result
invoke_command(TEEC_Session *session, TEEC_SharedMemory *inout_mem, uint32_t command_type)
{
   TEEC_Operation operation;
   TEEC_Result ret;

   /* Reset operation struct */
   memset((void *)&operation, 0, sizeof(operation));

   /* Set the parameter types */
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE,
                                           TEEC_NONE, TEEC_NONE);

   operation.params[0].memref.parent = inout_mem;

   /* Invoke command */
   ret = TEEC_InvokeCommand(session, command_type, &operation, NULL);
    
   return ret;
}

static TEEC_Result
do_counter_tests(TEEC_Session *session, TEEC_SharedMemory *inout_mem)
{
   int i;
   TEEC_Result ret;

   /* Get counter value three times */
   for (i = 0; i < 3; ++i)
      ret = invoke_command(session, inout_mem, CMD_GET_CTR);
   
   return ret;
}

int main()
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_SharedMemory inout_mem;
   TEEC_Result ret;
   uint64_t value;

   memset((void *)&inout_mem, 0, sizeof(inout_mem));
   
   printf("START: services test app\n");

   /* Initialize context */
   printf("Initializing context: ");
   ret = TEEC_InitializeContext(NULL, &context);
   if (ret != TEEC_SUCCESS)
   {
      printf("TEEC_InitializeContext failed: 0x%x\n", ret);
      goto end_1;
   }
   else
   {
      printf("initiliazed\n");
   }

   inout_mem.buffer = &value;
   inout_mem.size = sizeof(value);
   inout_mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

   ret = TEEC_RegisterSharedMemory(&context, &inout_mem);
   if (ret != TEE_SUCCESS)
   {
      printf("Failed to register shared memory");
      goto end_1;
   }

   /* Open session */
   printf("Opening session: ");
   ret = open_session(&context, &session);
   if (ret != TEEC_SUCCESS)
   {
      printf("TEEC_OpenSession failed: 0x%x\n", ret);
      goto end_2;
   }
   else
   {
      printf("opened\n");
   }

   printf("Initialization complete\n");

   /* Invoke commands */
   printf("Invoking commands: ");
   ret = do_counter_tests(&session, &inout_mem);
   if (ret != TEEC_SUCCESS)
   {
      printf("TEEC_InvokeCommand failed: 0x%x\n", ret);
      goto end_3;
   }
   else
   {
      printf("invoked\n");
      
      /* Print the last counter value */
      printf("Counter value: %d\n", (int)value);
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

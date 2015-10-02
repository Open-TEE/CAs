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
#include <stdint.h>

#include "conn_test_ctl.h"

void reverse_buffer(uint8_t *buffer,
                    uint32_t buffer_length,
                    uint32_t *reversed_size)
{
	uint32_t i, j;
	uint8_t tmp;

	for (i = 0, j = buffer_length - 1; i < j; i++, j--) {
		tmp = buffer[i];
		buffer[i] = buffer[j];
		buffer[j] = tmp;
	}

	if (reversed_size)
		*reversed_size = REVERSED_SIZE(buffer_length);
}

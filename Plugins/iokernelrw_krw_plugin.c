#include <IOKit/IOKitLib.h>
#include <iokernelrw.h>
#include <mach/arm/kern_return.h>
#include <mach/kern_return.h>
#include <sys/errno.h>

#include "libkrw_plugin.h"

io_connect_t krw_client = IO_OBJECT_NULL;

int kread_wrapper(uint64_t from, void* to, size_t len)
{
    kern_return_t result_read;
    int result;

    if (krw_client == IO_OBJECT_NULL)
    {
        krw_client = iokernelrw_open();
    }

    result_read = iokernelrw_read(krw_client, from, to, len);

    if (result_read == KERN_SUCCESS)
    {
        result = 0;
    }
    else
    {
        result = EDEVERR;
    }

    return result;
}

int krw_plugin_initializer(krw_handlers_t handlers)
{
    handlers->kread = kread_wrapper;

    return 0;
}
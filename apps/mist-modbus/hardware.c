#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "wish_platform.h"
#include "wish_io.h"
#include "mist_follow.h"
#include "mist_app.h"
#include "mist_follow_funcs.h"
#include "mist_model.h"
#include "mist_app.h"
#include "wish_debug.h"
#include <string.h>

#include "bson_visitor.h"
#include "wish_debug.h"

#include <pthread.h>
#include <errno.h>

#include "mbport.h"
#include "mbm.h"
#include "common/mbportlayer.h"


extern mist_app_t *modbus_mist_app;

#define MBM_SERIAL_PORT	          ( 0 )
#define MBM_SERIAL_BAUDRATE       ( 19200 )
#define MBM_PARITY                ( MB_PAR_NONE )
#define MBM_MODE                  ( MB_RTU )

STATIC char    *prvszMBMode2String( eMBSerialMode eMode );
STATIC char    *prvszMBParity2String( eMBSerialParity eParity );

pthread_t thread1;

void modbus_reconnect();
void *functionC();
pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
int counter = 0;
int end = 0;

xMBHandle       xMBMMaster;

USHORT          usNRegs[880];
USHORT          RegsCache[880];
USHORT          usRegCnt = 180;

void android_flash(int on);

double modbus_state = -1;



enum mist_error hw_read(struct mist_model *model, char * id, enum mist_type type, void * result) {
    WISHDEBUG(LOG_DEBUG, "hw read: %s, type %d", id, type);
    if (strncmp(id, "r-", 2) == 0) {
        int regNo = atoi(&id[2]);
        
        //printf("Reading register %d: %hu", regNo, RegsCache[regNo]);
        
        if (type == MIST_TYPE_FLOAT) {
            double * double_result = result;
            *double_result = RegsCache[regNo];
        }
    } else if (strncmp(id, "c-", 2) == 0) {
        int coilNo = atoi(&id[2]);
        
        //printf("Reading register %d: %hu", regNo, RegsCache[regNo]);
        
        if (type == MIST_TYPE_BOOL) {
            bool * bool_result = result;
            *bool_result = RegsCache[coilNo+800] == 0 ? false : true;
        }
    }
 
    return MIST_NO_ERROR;
}

enum mist_error hw_write(struct mist_model *model, char * id, enum mist_type type, void * new_value) {
    eMBErrorCode eStatus = MB_ENOERR, eStatus2;

    WISHDEBUG(LOG_DEBUG, "hw write: %s, type %d", id, type);
    if (strncmp(id, "r-", 2) == 0) {
        int regNo = atoi(&id[2]);
        //printf("Writing register %d: %hu", regNo, RegsCache[regNo]);

        pthread_mutex_lock( &mutex1 );
        //printf("write lock\n");
        
        if (type == MIST_TYPE_FLOAT) {
            double* value = new_value;
            //printf("hw_write: modbus %d, %f\n", type, *value);
            if( MB_ENOERR != ( eStatus2 = eMBMWriteSingleRegister( xMBMMaster, 1, regNo, (USHORT)*value ) ) )
            {
                eStatus = eStatus2;
                modbus_reconnect();
            }
        } else if (type == MIST_TYPE_INT) {
            int32_t* value = new_value;
            //printf("hw_write: modbus %d, %d\n", type, *value);

            //printf("hw_write: actually writing to modbus %d, %d\n", type, *value);
            
            if( MB_ENOERR != ( eStatus2 = eMBMWriteSingleRegister( xMBMMaster, 1, regNo, (USHORT)*value ) ) )
            {
                eStatus = eStatus2;
                //printf("modbus error: %d\n", eStatus2);
                modbus_reconnect();
            }
        }
        pthread_mutex_unlock( &mutex1 );
        
        //printf("write unlock\n");
    } else if (strncmp(id, "c-", 2) == 0) {
        int coilNo = atoi(&id[2]);
        if (type == MIST_TYPE_BOOL) {
            bool* bool_value = new_value;

            pthread_mutex_lock( &mutex1 );
            
            if( MB_ENOERR != ( eStatus2 = eMBMWriteSingleCoil( xMBMMaster, 1, coilNo, *bool_value ) ) )
            {
                eStatus = eStatus2;
                //printf("modbus error: %d\n", eStatus2);
                modbus_reconnect();
            }
            pthread_mutex_unlock( &mutex1 );
        }
    }

    if (eStatus != MB_ENOERR) {
        WISHDEBUG(LOG_CRITICAL, "MB err in hw_write");

    }
 
    return MIST_NO_ERROR;
}

enum mist_error hw_invoke(struct mist_model *model, char * id, uint8_t *args_array, uint8_t *response, size_t response_max_len) {

    WISHDEBUG(LOG_CRITICAL, "In invoke handler,  endpoint %s.", id);
    /* Get the endpoint and value from "args" array */
    char* endpoint = 0;
    int endpoint_len = 0;
    bson_get_string(args_array, "0", &endpoint, &endpoint_len);

    /* Get the arguments to invoke */
    uint8_t arg_type = 0;
    uint8_t *arg_value = NULL;
    int32_t arg_len = 0;
    if (bson_get_elem_by_name(args_array, "1", &arg_type, &arg_value,
            &arg_len) == BSON_FAIL) {
        WISHDEBUG(LOG_CRITICAL, "Could not get arguments");
        return MIST_ERROR;
    }

    switch (arg_type) {
    case BSON_KEY_DOCUMENT:
    case BSON_KEY_ARRAY:
        WISHDEBUG(LOG_CRITICAL, "Got a document (or array) parameter:");
        bson_visit(arg_value, elem_visitor);
        break;
    case BSON_KEY_INT32:
        WISHDEBUG(LOG_CRITICAL, "Got a int parameter: %d", *arg_value);
        break;
    case BSON_KEY_BOOLEAN:
        WISHDEBUG(LOG_CRITICAL, "Got a bool parameter: %d", *arg_value);
        break;
    case BSON_KEY_STRING:
        WISHDEBUG(LOG_CRITICAL, "Got a string parameter of len: %s", arg_value);
        break;
    default:
        WISHDEBUG(LOG_CRITICAL, "Unhandled argument type %hhx", arg_type);
        break;
    }

    return MIST_NO_ERROR;
}

void hw_init(void) {
    mist_set_ep_read_fn(&(modbus_mist_app->model), hw_read);
    mist_set_ep_write_fn(&(modbus_mist_app->model), hw_write);
    /*
    mist_set_ep_read_fn(&(test_mist_app->model), hw_read);
    mist_set_ep_write_fn(&(test_mist_app->model), hw_write);
    mist_set_ep_invoke_fn(&(test_mist_app->model), hw_invoke);
    */

#if 0
    eMBErrorCode eStatus;
    
    vMBPOtherDLLInit();
    
    if (MB_ENOERR == (eStatus = eMBMSerialInit(&xMBMMaster, MBM_MODE, MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, MBM_PARITY))) {
        fprintf(stderr, "MODBUS master instance ready (MODE=%s, PORT=%d, BAUDRATE=%d, PARITY=%s)\n",
                prvszMBMode2String(MBM_MODE), MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, prvszMBParity2String(MBM_PARITY));
    } else {
        fprintf(stderr, "Can't start MODBUS master instance (MODE=%s, PORT=%d, BAUDRATE=%d, PARITY=%s)!\n",
                prvszMBMode2String(MBM_MODE), MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, prvszMBParity2String(MBM_PARITY));
    }
    
    int rc1;

    /* Create independent threads each of which will execute functionC */
    if( (rc1=pthread_create( &thread1, NULL, &functionC, NULL)) )
    {
        printf("Thread creation failed: %d\n", rc1);
    }
#endif
}

void hw_destroy(void) {
    end = 1;
    pthread_join( thread1, NULL);

    eMBErrorCode eStatus;

    // close the modbus connection
    if( MB_ENOERR != ( eStatus = eMBMClose( xMBMMaster ) ) )
    {
        MBP_ASSERT( 0 );
    }
}

void modbus_reconnect() {
    eMBErrorCode eStatus;
    
    // try to close and reconnect the modbus connection
    if( MB_ENOERR != ( eStatus = eMBMClose( xMBMMaster ) ) )
    {
        MBP_ASSERT( 0 );
    }
    if (MB_ENOERR == (eStatus = eMBMSerialInit(&xMBMMaster, MBM_MODE, MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, MBM_PARITY))) {
        fprintf(stderr, "MODBUS master instance ready (MODE=%s, PORT=%d, BAUDRATE=%d, PARITY=%s)\n",
                prvszMBMode2String(MBM_MODE), MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, prvszMBParity2String(MBM_PARITY));
    } else {
        fprintf(stderr, "Can't start MODBUS master instance (MODE=%s, PORT=%d, BAUDRATE=%d, PARITY=%s)!\n",
                prvszMBMode2String(MBM_MODE), MBM_SERIAL_PORT, MBM_SERIAL_BAUDRATE, prvszMBParity2String(MBM_PARITY));
    }
}


void *functionC()
{
    eMBErrorCode eStatus, eStatus2;
    
    while (1) {
        if(end) { break; }
        
        int lock = pthread_mutex_trylock( &mutex1 );

        if(lock == 0) {
            //printf("read lock\n");

            eStatus = MB_ENOERR;
            int i;
            for(i=0; i<8; i++) {
                if( MB_ENOERR != ( eStatus2 = eMBMReadHoldingRegisters( xMBMMaster, 1, i*100, 100, &usNRegs[i*100] ) ) ) {
                    eStatus = eStatus2;
                    //printf("read error\n");
                    modbus_reconnect();
                    break;
                }
            }

//eMBMReadCoils( xMBMHandle xHdl, UCHAR ucSlaveAddress, USHORT usCoilStartAddress, USHORT usNCoils,
//               /*@out@ */ UBYTE arubBufferOut[] )
            
            if (MB_ENOERR != (eStatus2 = eMBMReadCoils(xMBMMaster, 1, 0, 80, (UBYTE *) &usNRegs[800]))) {
                eStatus = eStatus2;
                //printf("read error\n");
                modbus_reconnect();
                break;
            }

            
            if(eStatus == MB_ENOERR) {
            
                USHORT ubIdx;
                for( ubIdx = 0; ubIdx < 800; ubIdx++ )
                {
                    if(RegsCache[ubIdx] != usNRegs[ubIdx]) {
                        //printf(" change in reg %hu: %hu to %hu\n", ubIdx, RegsCache[ubIdx], usNRegs[ubIdx]);
                        RegsCache[ubIdx] = usNRegs[ubIdx];

                        if( (ubIdx<=10 && ubIdx != 2) || ubIdx == 135 || ubIdx == 157) {
                            char ep[20];
                            snprintf(ep, 20, "r-%d", ubIdx);
                            mist_value_changed(&(modbus_mist_app->model), ep);
                        }
                    }
                }
                for( ubIdx = 0; ubIdx < 80; ubIdx++ )
                {
                    int coil = usNRegs[800+ubIdx/16] & (1 << (ubIdx % 16)) ? true : false;
                    if(RegsCache[ubIdx+800] != coil ) {
                        //printf("byte: %d bit: %d mask: %d\n", ubIdx/16, ubIdx % 16, (1 << (ubIdx % 16)));
                        //printf(" change in reg %hu: %hu to %hu\n", ubIdx, RegsCache[ubIdx], usNRegs[ubIdx]);
                        RegsCache[ubIdx+800] = (USHORT)coil;
                        
                        if(ubIdx == 1 || ubIdx == 3 || ubIdx == 8 || ubIdx == 10) {
                            char ep[20];
                            snprintf(ep, 20, "c-%d", ubIdx);
                            
                            //printf("Coil 1 changed: %d\n", coil);
                            mist_value_changed(&(modbus_mist_app->model), ep);
                        }
                    }
                }
            } else {
                //printf("Skipped updating values due to read error.\n");
            }

            /* Wait 100ms before next try. */
            
            //printf("read unlock\n");
            
            pthread_mutex_unlock( &mutex1 );
        } else {
            //printf("read lock failed %d\n", lock);
        }
        
        usleep(100000);
    }
    return NULL;
}

STATIC char    *
prvszMBMode2String( eMBSerialMode eMode )
{
    char           *szMode;

    switch ( eMode )
    {
    case MB_RTU:
        szMode = "RTU";
        break;
    case MB_ASCII:
        szMode = "ASCII";
        break;
    default:
        szMode = "unknown";
        break;
    }
    return szMode;
}

STATIC char    *
prvszMBParity2String( eMBSerialParity eParity )
{
    char           *szParity;

    switch ( eParity )
    {
    case MB_PAR_EVEN:
        szParity = "RTU";
        break;
    case MB_PAR_NONE:
        szParity = "ASCII";
        break;
    case MB_PAR_ODD:
        szParity = "ODD";
        break;
    default:
        szParity = "unknown";
        break;
    }
    return szParity;
}


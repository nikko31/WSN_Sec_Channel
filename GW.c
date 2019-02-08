#include "contiki.h"
#include "net/rime/rime.h"
#include "random.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>

#define NUM_NODES 1
#define def_key_size 256


typedef struct firstMessageStruct firstMessageStr;
struct firstMessageStruct
{
    uint8_t idUser[def_key_size/8];
    uint8_t first[def_key_size/8];
    uint8_t second[def_key_size/8];
};

//addresses of nodes
linkaddr_t addr_nodes[NUM_NODES];

/*
  ---------------------PARAMETERS PROTOCOL
*/
uint8_t count=1;
uint8_t count2=1;
uint8_t userID[def_key_size/8]={{0}};
uint8_t sensID[def_key_size/8]={{0}};
uint8_t xGwUser[def_key_size/8]={{0}};
uint8_t xGwSens[def_key_size/8]={{0}};
uint8_t xGwUserNew[def_key_size/8]={{0}};
uint8_t xGwSensNew[def_key_size/8]={{0}};
uint8_t qj[def_key_size/8]={{0}};
uint8_t pi[def_key_size/8]={{0}};
uint8_t passwordUser[def_key_size/8]={{0}};
uint8_t passwordSens[def_key_size/8]={{0}};
uint8_t sharedSecredKey[def_key_size/8]={{0}};
uint8_t firstMessage[def_key_size/8]={{0}};

linkaddr_t addr_user;
//addresses of nodes
linkaddr_t addr_sens;

void getRandomBytes(uint8_t *p_dest, unsigned p_size)
{
    int i;
    for (i = 0; i < p_size; i++)
    {
        p_dest[i] = random_rand();
    }
}

static int test_hexdigit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return  ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return  ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return  ch - 'a' + 10;
    return -1;
}

static int test_readhex(uint8_t *buf, const char *str, int maxbytes)
{
    int i, h, l;

    for (i = 0; i < maxbytes; i++) {
        h = test_hexdigit(str[2 * i]);
        if (h < 0)
            return i;
        l = test_hexdigit(str[2 * i + 1]);
        if (l < 0)
            return i;
        buf[i] = (h << 4) + l;
    }

    return i;
}

/*---------------------------------------------------------------------------*/
static void sent_uc(struct unicast_conn *c, int status, int num_tx);
static void recv_uc(struct unicast_conn *c, const linkaddr_t *from);
static const struct unicast_callbacks unicast_callbacks = {recv_uc, sent_uc};
static struct unicast_conn uc;
PROCESS(example_broadcast_process, "Gateway");
AUTOSTART_PROCESSES(&example_broadcast_process);


static void recv_uc(struct unicast_conn *c, const linkaddr_t *from)
{
    uint8_t i=0;
    firstMessageStr firstMessageS;
    uint8_t passwordImageSens[def_key_size/8]={{0}};
    uint8_t passwordImageUser[def_key_size/8]={{0}};
    if(from->u8[0]==2)
    {
        if(count==1){
           
            memcpy((firstMessageStr *)&firstMessageS,(firstMessageStr *) packetbuf_dataptr(), sizeof(firstMessageStr));
            addr_sens.u8[0] = from->u8[0];
            addr_sens.u8[1] = from->u8[1];
            powertrace_print("FIRST 1MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                passwordImageSens[i] = (firstMessageS.first)[i]^sensID[i];
            }
            powertrace_print("FIRST 2MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                firstMessage[i] = passwordImageSens[i]^sharedSecredKey[i];
            }
            packetbuf_copyfrom(firstMessage, sizeof(firstMessage));
            unicast_send(&uc, &addr_sens);
            count=2;
            powertrace_print("END1");
        }else
        {
            uint8_t i=0;
            uint8_t firstMessageTemp[def_key_size/8]={{0}};
            uint8_t firstMessageTemp2[def_key_size/8]={{0}};
            //uint8_t firstMessageTemp[def_key_size/8]={{0}};
            //signedMessage=(signedMessageStr *) packetbuf_dataptr();
            powertrace_print("RECEIVED SENSOR_MESSAGE2");
            memcpy((uint8_t *)firstMessage,(uint8_t *) packetbuf_dataptr(), sizeof(firstMessage));

            powertrace_print("SECOND MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                firstMessageTemp[i] = xGwSens[i]^sharedSecredKey[i];
            }
            powertrace_print(" HASH ");
            sha3(firstMessageTemp, def_key_size/8, firstMessageTemp2, def_key_size/8);
           
            /* Confirm proper reception of SK*/
            if(memcmp(firstMessage, firstMessageTemp2, def_key_size/8)==0)
            {
                getRandomBytes(xGwSensNew, def_key_size/8);
               
                for(i=0;i<def_key_size/8;i++){
                    firstMessageTemp[i]=sharedSecredKey[i]^xGwSensNew[i];
                }
                powertrace_print("END2");
                packetbuf_copyfrom(firstMessageTemp, sizeof(firstMessageTemp));
                unicast_send(&uc, &addr_sens);
                powertrace_print("SEND_SENS second");
            }
        }
    }
    else{
       
        if(count2==1){
            powertrace_print("RECEIVED USER_MESSAGE1");
            memcpy((firstMessageStr *)&firstMessageS,(firstMessageStr *) packetbuf_dataptr(), sizeof(firstMessageStr));
            addr_user.u8[0] = from->u8[0];
            addr_user.u8[1] = from->u8[1];
            powertrace_print("FIRST USER_1MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                passwordImageSens[i] = (firstMessageS.first)[i]^sensID[i];
            }
            powertrace_print("FIRST USER_2MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                firstMessage[i] = passwordImageSens[i]^sharedSecredKey[i];
            }
            packetbuf_copyfrom(firstMessage, sizeof(firstMessage));
            unicast_send(&uc, &addr_user);
            count2=2;
            powertrace_print("USER_END1");
        }
        else{
            uint8_t i=0;
            uint8_t firstMessageTemp[def_key_size/8]={{0}};
            uint8_t firstMessageTemp2[def_key_size/8]={{0}};
            //uint8_t firstMessageTemp[def_key_size/8]={{0}};
            //signedMessage=(signedMessageStr *) packetbuf_dataptr();
            powertrace_print("RECEIVED USER_MESSAGE2");
            memcpy((uint8_t *)firstMessage,(uint8_t *) packetbuf_dataptr(), sizeof(firstMessage));

            powertrace_print("SECOND USER_MESSAGEXOR");
            for(i=0; i<def_key_size/8; i++){
                firstMessageTemp[i] = xGwUser[i]^sharedSecredKey[i];
            }
            powertrace_print(" USER_HASH ");
            sha3(firstMessageTemp, def_key_size/8, firstMessageTemp2, def_key_size/8);
            /* Confirm proper reception of SK*/
            if(memcmp(firstMessage, firstMessageTemp2, def_key_size/8)==0)
            {
                getRandomBytes(xGwUserNew, def_key_size/8);
               
                for(i=0;i<def_key_size/8;i++){
                    firstMessageTemp[i]=sharedSecredKey[i]^xGwUserNew[i];
                }
                powertrace_print("USER_END2");
                packetbuf_copyfrom(firstMessageTemp, sizeof(firstMessageTemp));
                unicast_send(&uc, &addr_user);
                powertrace_print("SEND_USER second");
            }
        }
    }
}
/*---------------------------------------------------------------------------*/
static void sent_uc(struct unicast_conn *c, int status, int num_tx)
{
    powertrace_print("sent message");
}

uint8_t ii=0;
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(example_broadcast_process, ev, data)
{
 
    static struct etimer et;

    uint8_t cc=0;
    PROCESS_EXITHANDLER(unicast_close(&uc);)

    PROCESS_BEGIN();
    unicast_open(&uc, 146, &unicast_callbacks);


    powertrace_print("start");
    while (1)
    {
       
        etimer_set(&et, CLOCK_SECOND * 4 + random_rand() % (CLOCK_SECOND * 4));
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

    }

    PROCESS_END();
}

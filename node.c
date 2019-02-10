#include "contiki.h"
#include "net/rime/rime.h"
#include "random.h"
#include "sha3.h"
#include "string.h"
#include <stdio.h>
#define NUM_NODES 1
#define def_key_size 256

typedef struct secretTStruct secretTStr;
struct secretTStruct
{
    uint8_t node_ID[def_key_size/8];
    uint8_t t[def_key_size/8];
};

typedef struct secondMessageStruct secondMessageStr;
struct secondMessageStruct
{
    uint8_t group_ID[def_key_size/8];
    uint8_t hmac[def_key_size/8];
    uint8_t partial_group_key[def_key_size/8];
    secretTStr secretTS[NUM_NODES-1];
};

typedef struct firstMessageStruct firstMessageStr;
struct firstMessageStruct
{
    uint8_t group_ID[def_key_size/8];
    uint8_t hmac[def_key_size/8];
    uint8_t message[def_key_size/8];
};

typedef struct joinMessageStruct joinMessageStr;
struct joinMessageStruct
{
    uint8_t group_ID[def_key_size/8];
    uint8_t hash_of_secret_GW[def_key_size/8];
};

/*
  ---------------------PARAMETERS PROTOCOL
*/
uint8_t group_ID[def_key_size/8]={{0}};
uint8_t one_time_pad[def_key_size/8]={{0}};
uint8_t x_secret[def_key_size/8]={{0}};
secretTStr secretTS[NUM_NODES-1];
uint8_t group_key[def_key_size/8];

uint8_t sensID[def_key_size/8]={{0}};
uint8_t userID[def_key_size/8]={{0}};
uint8_t xGwSens[def_key_size/8]={{0}};
uint8_t xGwSensNew[def_key_size/8]={{0}};
uint8_t qj[def_key_size/8]={{0}};
uint8_t sharedSecredKey[def_key_size/8]={{0}};
uint8_t firstMessage[def_key_size/8]={{0}};
linkaddr_t addr_gw;

uint8_t counter=1;
uint8_t counter2=1;

void getRandomBytes(uint8_t *p_dest, unsigned p_size)
{
    int i;
    for (i = 0; i < p_size; i++)
    {
        p_dest[i] = random_rand();
    }
}

/*---------------------------------------------------------------------------*/
static void broadcast_recv(struct broadcast_conn *c, const linkaddr_t *from);
static void sent_uc(struct unicast_conn *c, int status, int num_tx);
static void recv_uc(struct unicast_conn *c, const linkaddr_t *from);

static const struct unicast_callbacks unicast_callbacks = {recv_uc, sent_uc};
static struct unicast_conn uc;
static const struct broadcast_callbacks broadcast_call = {broadcast_recv};
static struct broadcast_conn broadcast;

PROCESS(proj_process, "node");
AUTOSTART_PROCESSES(&proj_process);

static void broadcast_recv(struct broadcast_conn *c, const linkaddr_t *from)
{
    uint8_t i=0;
    joinMessageStr joinMessageS;
    firstMessageStr firstMessageS;
    uint8_t message[def_key_size/8]={{0}};
    powertrace_print("RECEIVED MESSAGE");
    memcpy((joinMessageStr *)&joinMessageS,(joinMessageStr *) packetbuf_dataptr(), sizeof(joinMessageStr));
    /* Gateway address */
    addr_gw.u8[0] = from->u8[0];
    addr_gw.u8[1] = from->u8[1];
    memcpy(group_ID, joinMessageS.group_ID, sizeof(group_ID));
    
    powertrace_print("GENERATE_MESSAGE_XOR");
    for(i=0; i<def_key_size/8; i++){
        message[i] = x_secret[i]^one_time_pad[i];
    }
    memcpy(firstMessageS.message,message,def_key_size/8);
    memcpy(firstMessageS.group_ID,group_ID,def_key_size/8);
    packetbuf_copyfrom((void *)(&firstMessageS), sizeof(firstMessageStr));
    unicast_send(&uc, &addr_gw);
}

static void recv_uc(struct unicast_conn *c, const linkaddr_t *from)
{
    uint8_t i=0;
    secondMessageStr secondMessageS;
    uint8_t temp_group_key[def_key_size/8]={{0}};
    //signedMessage=(signedMessageStr *) packetbuf_dataptr();
    powertrace_print("received message");
    memcpy((secondMessageStr *)&secondMessageS, (secondMessageStr *) packetbuf_dataptr(), sizeof(secondMessageStr));
    powertrace_print("FIRST MESSAGEXOR ");
    memcpy(secretTS, secondMessageS.secretTS, sizeof(secondMessageS.secretTS));
    memcpy(temp_group_key, secondMessageS.partial_group_key,def_key_size/8);

    for(i=0; i<def_key_size/8; i++){
        group_key[i] = temp_group_key[i]^x_secret[i];
        printf("%d\n",group_key[i]);
    }
    sha3(sharedSecredKey, def_key_size/8, firstMessage, def_key_size/8);
    powertrace_print("calculated group_secret");
    packetbuf_copyfrom(firstMessage, sizeof(firstMessage));
    unicast_send(&uc, &addr_gw);

}
/*---------------------------------------------------------------------------*/
static void sent_uc(struct unicast_conn *c, int status, int num_tx)
{
    powertrace_print("sent message");
}

uint8_t ii=0;
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(proj_process, ev, data)
{
 
    static struct etimer et;
    firstMessageStr firstMessageS;
    uint8_t firstMessageTemp[def_key_size/8]={{0}};

    PROCESS_EXITHANDLER(broadcast_close(&broadcast);unicast_close(&uc);)

    PROCESS_BEGIN();
    broadcast_open(&broadcast, 129, &broadcast_call);
    unicast_open(&uc, 146, &unicast_callbacks);
    int i;
    /* Generate random secret x */
    getRandomBytes((uint8_t *)x_secret, def_key_size/8);

    while(1) {

        /* Delay 2-4 seconds */
        etimer_set(&et, CLOCK_SECOND * 4 + random_rand() % (CLOCK_SECOND * 4));

        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }

    PROCESS_END();
}

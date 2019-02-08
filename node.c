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
    memcpy((joinMessageStr *)&joinMessageS,(joinMessageStr *) packetbuf_dataptr(), sizeof(joinMessageStr));
    addr_gw.u8[0] = from->u8[0];
    addr_gw.u8[1] = from->u8[1];
    memcpy(joinMessageS.group_ID, group_ID,def_key_size/8);
    /* Generate random secret x */
    getRandomBytes((uint8_t *)x_secret, def_key_size/8);
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
    if(counter==1){
        uint8_t i=0;
        uint8_t firstMessageTemp[def_key_size/8]={{0}};
        //signedMessage=(signedMessageStr *) packetbuf_dataptr();
        powertrace_print("received message");
        memcpy((uint8_t *)firstMessageTemp,(uint8_t *) packetbuf_dataptr(), sizeof(firstMessageTemp));
        addr_gw.u8[0] = from->u8[0];
        addr_gw.u8[1] = from->u8[1];
        powertrace_print("FIRST MESSAGEXOR ");

        for(i=0; i<def_key_size/8; i++){
            sharedSecredKey[i] = firstMessage[i]^firstMessageTemp[i]^xGwSens[i];
        }
        sha3(sharedSecredKey, def_key_size/8, firstMessage, def_key_size/8);
        powertrace_print("calculated h(SK^xGwSens)");
        packetbuf_copyfrom(firstMessage, sizeof(firstMessage));
        unicast_send(&uc, &addr_gw);
        counter=2;
    }    
    else{
        uint8_t i=0;
        //uint8_t firstMessageTemp[def_key_size/8]={{0}};
        //signedMessage=(signedMessageStr *) packetbuf_dataptr();
        powertrace_print("received message2");
        memcpy((uint8_t *)firstMessage,(uint8_t *) packetbuf_dataptr(), sizeof(firstMessage));
        powertrace_print("GET NEW KEY ");
        for(i=0; i<def_key_size/8; i++){
            xGwSensNew[i] = firstMessage[i]^sharedSecredKey[i];

        }
        powertrace_print("END");
    }
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
    /* Gateway address */
    addr_gw.u8[0] = 1;
    addr_gw.u8[1] = 0;

    powertrace_print("START generate 1Message");
    /* Generate random password qi */
    getRandomBytes((uint8_t *)qj, def_key_size/8);

    powertrace_print("START XOR");
    /* q XOR xSens,GW */
    for(i=0; i<def_key_size/8; i++){
        firstMessage[i]=qj[i]^xGwSens[i];
    }
    powertrace_print("START HASH");
    /* First HASH */
    sha3(firstMessage, def_key_size/8, firstMessageTemp, def_key_size/8);
    powertrace_print("SECOND HASH");
    /* Second HASH */
    sha3(firstMessageTemp, def_key_size/8, firstMessage, def_key_size/8);
    
    powertrace_print("START XOR2");
    for(i=0; i<def_key_size/8; i++){
        firstMessageTemp[i]=firstMessage[i]^userID[i];
    }
    memcpy(firstMessageS.first,firstMessageTemp,def_key_size/8);
    
    powertrace_print("START 2XOR2");
    for(i=0; i<def_key_size/8; i++){
        firstMessageTemp[i]=firstMessage[i]^xGwSens[i];
    }
    memcpy(firstMessageS.second,firstMessageTemp,def_key_size/8);
    memcpy(firstMessageS.id,sensID,def_key_size/8);
    powertrace_print("message ready ");
    
    packetbuf_copyfrom((void *)(&firstMessageS), sizeof(firstMessageStr));
    unicast_send(&uc, &addr_gw);
    powertrace_print("finish unicast");
    while(1) {

        /* Delay 2-4 seconds */
        etimer_set(&et, CLOCK_SECOND * 4 + random_rand() % (CLOCK_SECOND * 4));

        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }

    PROCESS_END();
}

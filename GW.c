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

//addresses of nodes
linkaddr_t addr_nodes[NUM_NODES];

/*
  ---------------------PARAMETERS PROTOCOL
*/
uint8_t group_ID[def_key_size/8]={{0}};
uint8_t one_time_pad[def_key_size/8]={{0}};
uint8_t x_secret[def_key_size/8]={{0}};
secretTStr secretTS[NUM_NODES-1];
uint8_t group_key[def_key_size/8];

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
static void broadcast_recv(struct broadcast_conn *c, const linkaddr_t *from);
static void sent_uc(struct unicast_conn *c, int status, int num_tx);
static void recv_uc(struct unicast_conn *c, const linkaddr_t *from);

static const struct unicast_callbacks unicast_callbacks = {recv_uc, sent_uc};
static struct unicast_conn uc;
static const struct broadcast_callbacks broadcast_call = {broadcast_recv};
static struct broadcast_conn broadcast;

PROCESS(example_broadcast_process, "Gateway");
AUTOSTART_PROCESSES(&example_broadcast_process);

static void broadcast_recv(struct broadcast_conn *c, const linkaddr_t *from){

}

static void recv_uc(struct unicast_conn *c, const linkaddr_t *from)
{
    uint8_t i=0;
    
}
/*---------------------------------------------------------------------------*/
static void sent_uc(struct unicast_conn *c, int status, int num_tx)
{
    powertrace_print("sent message");
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(example_broadcast_process, ev, data)
{
    uint8_t i=0;
    static struct etimer et;
    joinMessageStr joinMessageS;
    uint8_t group_ID[def_key_size/8] = {{1}};
    uint8_t hash_of_secret_GW[def_key_size/8] = {{0}};

    PROCESS_EXITHANDLER(unicast_close(&uc);)

    PROCESS_BEGIN();
    broadcast_open(&broadcast, 129, &broadcast_call);
    unicast_open(&uc, 146, &unicast_callbacks);

    memcpy(joinMessageS.group_ID, group_ID, def_key_size/8);
    memcpy(joinMessageS.hash_of_secret_GW, hash_of_secret_GW, def_key_size/8);
    packetbuf_copyfrom((void *)(&joinMessageS), sizeof(joinMessageStr));
    broadcast_send(&broadcast);
    powertrace_print("start");
    while (1)
    {
        etimer_set(&et, CLOCK_SECOND * 4 + random_rand() % (CLOCK_SECOND * 4));
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }

    PROCESS_END();
}

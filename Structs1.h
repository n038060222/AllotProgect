#include <stdlib.h>
#include <stdio.h>
typedef struct connection
{
    int connection_id;
    struct listTrans *trans;
    struct five_tuple *key;
    int num_trans;
    size_t total_bandwidth;
} connection;
typedef struct five_tuple
{
    struct in_addr sourse_ip_address;
    struct in_addr destination_ip_address;
    int ip_protocol;
    int udp_source_port;
    int udp_destination_port;
} five_tuple;
typedef struct transaction
{
    int size_packet;
    int transaction_id;
    double start_time;
    double last_time;
    int recive_server_packet;
    int num_in_packet_in_range;
    int num_out_packet_in_range;
    int max_packet_size_in;
    int min_packet_size_in;
    double max_diff_time_in;
    double min_diff_time_in;
    double sum_squre_in_packet_time;
    double rtt;
} transaction;
typedef struct node
{
    struct connection *data;
    struct node *next;
    struct node *prev;

} node;
typedef struct nodeTrans
{
    struct transaction *data;
    struct nodeTrans *next;
    struct nodeTrans *prev;

} nodeTrans;
typedef struct listTrans
{
    nodeTrans *head;
    nodeTrans *tail;
    int size;
} listTrans;
typedef struct list
{
    node *head;
    node *tail;
    int size;
} list;

static inline list *create_list()
{
    list *l = (list *)malloc(sizeof(list));
    l->size = 0;
    l->head = l->tail = NULL;
    return l;
}

static inline void push_back(list *l, connection *data)
{
    node *n = (node *)malloc(sizeof(node) * 1);
    n->data = data;
    n->next = NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
        n->prev = NULL;
    }
    else
    {
        node *temp=l->tail;
        n->prev = temp;
        temp->next = n;
        l->tail = n;
        
    }
    l->size++;
}

static inline void push_front(list *l, connection *data)
{
    node *n = (node *)malloc(sizeof(node) * 1);
    n->data = data;
    n->prev = NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
        n->next = NULL;
    }
    else
    {
        l->head->prev = n;
        n->next = l->head;
        l->head = n;
    }
    l->size++;
}

static inline connection *pop_back(list *l)
{

    if (l == NULL || l->size == 0)
        return NULL;
    connection *data = l->tail->data;
    if (l->size == 1)
        l->head = NULL;
    l->tail = l->tail->prev;
    l->size--;
    return data;
}

static inline connection *pop_front(list *l)
{
    if (l == NULL || l->size == 0)
        return NULL;
    connection *data = l->head->data;
    if (l->size == 1)
        l->tail = NULL;
    l->head = l->head->next;
    l->size--;
    return data;
}

static inline int is_empty(list *l)
{
    return l->size <= 0;
}
static inline listTrans *create_list_trans()
{
    listTrans *l = (listTrans *)malloc(sizeof(listTrans));
    l->size = 0;
    l->head = l->tail = NULL;
    return l;
}

static inline void push_back_trans(listTrans *l, transaction *data)
{
    nodeTrans *n = (nodeTrans *)malloc(sizeof(nodeTrans) * 1);
    n->data = data;
    n->next = NULL;
    n->prev=NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
    }
    else
    {
        nodeTrans *temp=l->tail;
        n->prev = temp;
        temp->next = n;
        l->tail = n;
    }
    l->size++;
}

static inline void push_front_trans(listTrans *l, transaction *data)
{
    nodeTrans *n = (nodeTrans *)malloc(sizeof(nodeTrans) * 1);
    n->data = data;
    n->prev = NULL;
    n->next = NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
    }
    else
    {
        nodeTrans *templist=l->head;
        n->next = templist;
        templist->prev = n;
        
        l->head = n;
    }
    l->size++;
}

static inline nodeTrans *pop_back_trans(listTrans *l)
{
    if (l == NULL || l->size == 0)
        return NULL;
    nodeTrans *data = l->tail;
    if (l->size == 1)
        l->head = NULL;
    l->tail = l->tail->prev;
    l->size--;
    return data;
}

static inline nodeTrans *pop_front_trans(listTrans *l)
{
    if (l == NULL || l->size == 0)
        return NULL;
    nodeTrans *data = l->head;
    if (l->size == 1)
        l->tail = NULL;
    l->head = l->head->next;
    l->size--;
    return data;
}

static inline int is_empty_trans(listTrans *l)
{
    return l->size <= 0;
}
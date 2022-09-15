#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
//#pragma warrning<disable 4996>
#include <json-c/json.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <time.h>
#include "Structs1.h"
#define PCAP_BUF_SIZE 1024
#define PCAP_SRC_FILE 2
#define LEN_HASH_SIZE 100
#define SIZE_ADRRESS 30
#define UDP_PROTOCOL 17
#define YOU_TUBE_PORT 443
#define max_packet_size 2000
#define min_packet_size 0
#define MAX_TIME 20
// static FILE *ini_file;
list *hash_table[LEN_HASH_SIZE];
// void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int request_packet_threshold;
int min_video_connection_size;
int inbound_packets_in_range_min;
int inbound_packets_in_range_max;
int outbound_packets_in_range_min;
int outbound_packets_in_range_max;
double max_diff_time_inbound_threshold;
double min_diff_time_inbound_threshold;
int number_of_videos_to_output_statistics_per_video;
int max_number_of_connections;
int max_number_of_transaction_per_video;
int video_connection_timeout;
int connection_num = 0;
int transaction_num = 0;
struct sockaddr_in source, dest;
// stistic
int videos_connections = 0;
double duration_time_all_videos = 0;
double size_all_videos = 0;
double number_of_TDRs = 0;
double duration_all_TDRs = 0;
double time_between_two_consecutive_TDR = 0;
void CreateConnection(struct connection *connect, list *list_conect);
void WriteAllTansctionPerConn(struct connection *foundConnection);
void InsertNewTrans(struct connection *foundConnection, struct nodeTrans *newNode);
transaction *InitTransaction(const struct pcap_pkthdr *header, const u_char *buffer);
void PacketHandler(u_char *args, const struct pcap_pkthdr *, const u_char *);
void ClientToServer(const struct pcap_pkthdr *header, const u_char *buffer);
void ClientHandler(struct node *foundNode, struct connection *newConn, int flag);
void ServerHandler(node *foundNode, struct connection *newConn);
void ServerToClient(const struct pcap_pkthdr *header, const u_char *buffer);
void NewTransaction(struct connection *connect, struct transaction *new_trans);
void OvrideConnection(struct connection *connect, struct connection *new_connect);
void DeleteConnection(node *foundNode);
struct node *SearchConnectionInList(connection *connect, const u_char *buffer);
static inline int FiveTupleCheck(struct five_tuple *iph, struct in_addr sourse_ip_address, struct in_addr destination_ip_address, int udp_source_port);
void WriteToCsvFile(int connection_id, struct five_tuple *five_tuple, transaction *trans);
static inline int Hashfunction(struct five_tuple *key);
void ReadConfigFile();
struct connection *InitConnectionClientToServer(const struct pcap_pkthdr *header, const u_char *buffer);
struct connection *InitConnectionServerToClient(const struct pcap_pkthdr *header, const u_char *buffer);
FILE *fpt;
void UpdateConnections(struct connection *foundConnection, struct nodeTrans *newNode);
void UpdateTransaction(connection *connect, transaction *current_trans);
void InsertOpenConnToHashTable();
void WriteStisticToFile();
void OvrideConnection(struct connection *connect, struct connection *new_connect);
void handle_timeout(struct connection *foundConnection, struct connection *newConnection, struct nodeTrans *newNode, int flag);
void StisticHandler(connection *connect, transaction *current_trans);
int main(int argc, char **argv)
{

    ReadConfigFile();
    fpt = fopen("file1_TDR.csv", "w");
    fprintf(fpt, "conn_id ,  client_ip ,  server_ip , ip_protocol,udp_client_port,udp_server_port ,transaction_id ,start_time ,num_inbound_packets_in_range,num_outbound_packets_in_range,max_packet_size_inbound,min_packet_size_inbound,max_diff_time_inbound,min_diff_time_inbound,SumSquareInboundPacketTimeDiff,RTT \n");
    //printf("%d\n", video_connection_timeout);
    pcap_t *fp;
    char errbuffer[PCAP_ERRBUF_SIZE];

    fp = pcap_open_offline("pcap_file.pcap", errbuffer);
    if (fp == NULL)
    {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuffer);
        return 0;
    }

    if (pcap_loop(fp, 0, PacketHandler, NULL) < 0)
    {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        return 0;
    }
    // over for all the hash and insert all the conn that the timeout finish
    InsertOpenConnToHashTable();
    printf("%d\n",transaction_num);
    fclose(fpt);
    WriteStisticToFile();
}
void WriteStisticToFile()
{
    FILE *file_stistic;
    file_stistic = fopen("file_stistic.csv", "w");
    fprintf(file_stistic, "How many videos connections have been watched=%d\n", videos_connections);
    fprintf(file_stistic, "Average duration of the videos=%f\n", duration_time_all_videos / videos_connections);
    fprintf(file_stistic, "Average size of the videos=%f\n", size_all_videos / videos_connections);
    fprintf(file_stistic, "Average number of TDRs per video=%f\n", number_of_TDRs / videos_connections);
    fprintf(file_stistic, "Average size of the TDRs per video=%f\n", size_all_videos / number_of_TDRs);
    fprintf(file_stistic, "Average duration of the TDRs per video=%f\n", duration_all_TDRs / number_of_TDRs);
    fprintf(file_stistic, "Average time between two consecutive TDRs in a video connection=%f\n", time_between_two_consecutive_TDR / number_of_TDRs);
    fclose(file_stistic);
}
void InsertOpenConnToHashTable()
{
    for (int i = 0; i < LEN_HASH_SIZE; i++)
    {
        list *list_all_conn = hash_table[i];
        node *nodeConn = list_all_conn->head;
        while (list_all_conn != NULL && nodeConn != NULL && nodeConn->data != NULL && list_all_conn->size > 0) // nodeConn != NULL
        {
            if (nodeConn != NULL && nodeConn->data != NULL && list_all_conn->size > 0 && nodeConn->data->total_bandwidth >= min_video_connection_size)
            {
                size_all_videos += nodeConn->data->total_bandwidth;
                number_of_TDRs += nodeConn->data->trans->size;
                nodeTrans *node_trans = nodeConn->data->trans->head; 
                if (nodeConn->data->trans != NULL && nodeConn->data->trans->size > 0)
                {
                    double start_time = nodeConn->data->trans->head->data->start_time;
                    double end_time = nodeConn->data->trans->tail->data->last_time;
                    duration_time_all_videos += end_time - start_time;
                }
                while (node_trans != NULL && node_trans->data != NULL && nodeConn->data->trans->size > 0)
                {
                    duration_all_TDRs += node_trans->data->last_time - node_trans->data->start_time;
                    if (node_trans->next != NULL)
                        time_between_two_consecutive_TDR += node_trans->next->data->start_time - node_trans->data->start_time;
                    WriteToCsvFile(nodeConn->data->connection_id, nodeConn->data->key, node_trans->data);
                    node_trans = node_trans->next;
                    pop_front_trans(nodeConn->data->trans);
                }
            }
            nodeConn = nodeConn->next;
            pop_front(list_all_conn);
        }
    }
}
// read at the beginning of the program all the data variables from FILE
void ReadConfigFile()
{

    // for json file
    char buffer[PCAP_BUF_SIZE];
    FILE *fi;

    // open json file
    fi = fopen("ini.json", "r");
    // read data from json file to buffer
    fread(buffer, PCAP_BUF_SIZE, 1, fi);
    // close json file
    fclose(fi);
    // parse data from buffer to json object
    struct json_object *parsed_j;
    parsed_j = json_tokener_parse(buffer);

    struct json_object *jrequest_packet_threshold;
    struct json_object *jmin_video_connection_size;
    struct json_object *jinbound_packets_in_range_min;
    struct json_object *jinbound_packets_in_range_max;
    struct json_object *joutbound_packets_in_range_min;
    struct json_object *joutbound_packets_in_range_max;
    struct json_object *jmax_diff_time_inbound_threshold;
    struct json_object *jmin_diff_time_inbound_threshold;
    struct json_object *jnumber_of_videos_to_output_statistics_per_video;
    struct json_object *jmax_number_of_connections;
    struct json_object *jmax_number_of_transaction_per_video;
    struct json_object *jvideo_connection_timeout;
    json_object_object_get_ex(parsed_j, "request_packet_threshold", &jrequest_packet_threshold);
    json_object_object_get_ex(parsed_j, "min_video_connection_size", &jmin_video_connection_size);
    json_object_object_get_ex(parsed_j, "inbound_packets_in_range_min", &jinbound_packets_in_range_min);
    json_object_object_get_ex(parsed_j, "inbound_packets_in_range_max", &jinbound_packets_in_range_max);
    json_object_object_get_ex(parsed_j, "outbound_packets_in_range_min", &joutbound_packets_in_range_min);
    json_object_object_get_ex(parsed_j, "outbound_packets_in_range_max", &joutbound_packets_in_range_max);
    json_object_object_get_ex(parsed_j, "max_diff_time_inbound_threshold", &jmax_diff_time_inbound_threshold);
    json_object_object_get_ex(parsed_j, "min_diff_time_inbound_threshold", &jmin_diff_time_inbound_threshold);
    json_object_object_get_ex(parsed_j, "number_of_videos_to_output_statistics_per_video", &jnumber_of_videos_to_output_statistics_per_video);
    json_object_object_get_ex(parsed_j, "max_number_of_connections", &jmax_number_of_connections);
    json_object_object_get_ex(parsed_j, "max_number_of_transaction_per_video", &jmax_number_of_transaction_per_video);
    json_object_object_get_ex(parsed_j, "video_connection_timeout", &jvideo_connection_timeout);

    request_packet_threshold = json_object_get_int(jrequest_packet_threshold);
    min_video_connection_size = json_object_get_int(jmin_video_connection_size);
    inbound_packets_in_range_min = json_object_get_int(jinbound_packets_in_range_min);
    inbound_packets_in_range_max = json_object_get_int(jinbound_packets_in_range_max);
    outbound_packets_in_range_min = json_object_get_int(joutbound_packets_in_range_min);
    outbound_packets_in_range_max = json_object_get_int(joutbound_packets_in_range_max);
    max_diff_time_inbound_threshold = json_object_get_int(jmax_diff_time_inbound_threshold);
    min_diff_time_inbound_threshold = json_object_get_int(jmin_diff_time_inbound_threshold);
    number_of_videos_to_output_statistics_per_video = json_object_get_int(jnumber_of_videos_to_output_statistics_per_video);
    max_number_of_connections = json_object_get_int(jmax_number_of_connections);
    max_number_of_transaction_per_video = json_object_get_int(jmax_number_of_transaction_per_video);
    video_connection_timeout = json_object_get_int(jvideo_connection_timeout);
}
// get tow con and ovride the last connection
void OvrideConnection(struct connection *connect, struct connection *new_connect)
{
    connect->key->destination_ip_address = new_connect->key->destination_ip_address;
    connect->key->sourse_ip_address = new_connect->key->sourse_ip_address;
    connect->key->ip_protocol = new_connect->key->ip_protocol;
    connect->key->udp_destination_port = new_connect->key->udp_destination_port;
    connect->key->udp_source_port = new_connect->key->udp_source_port;
    connect->connection_id = new_connect->connection_id;
    connect->trans = create_list_trans();
}
int y = 0;
// func treat for all the packet that arrived from the pcap_file
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl << 2;
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    if (iph->protocol == UDP_PROTOCOL)
    {
        if (ntohs(udph->dest) != YOU_TUBE_PORT && ntohs(udph->source) != YOU_TUBE_PORT)
            return;
        // client to server
        if (ntohs(udph->dest) == YOU_TUBE_PORT)
        {
            ClientToServer(header, buffer);
        }
        // server to client
        else if (ntohs(udph->source) == YOU_TUBE_PORT)
        {
            ServerToClient(header, buffer);
        }
    }
}
// func that init connection for packet from server to client
struct connection *InitConnectionServerToClient(const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl << 2;
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    struct connection *connect = (struct connection *)malloc(sizeof(connection) * 1);
    connect->connection_id = connection_num;
    struct five_tuple *key = (struct five_tuple *)malloc(sizeof(five_tuple) * 1);
    struct in_addr clinet_ip = source.sin_addr;
    struct in_addr server_ip = dest.sin_addr;
    key->sourse_ip_address = server_ip;
    key->destination_ip_address = clinet_ip;
    key->ip_protocol = iph->protocol;
    int client_port = ntohs(udph->source);
    int server_port = ntohs(udph->dest);
    key->udp_source_port = server_port;
    key->udp_destination_port = client_port;
    connect->key = key;
    connect->num_trans = 0;
    struct listTrans *alltrans = create_list_trans();
    struct transaction *newTrans = InitTransaction(header, buffer);
    push_front_trans(alltrans, newTrans);
    connect->trans = alltrans;
    return connect;
}
// hash func that calculates the index in the hash by 5_tuple
static inline int Hashfunction(struct five_tuple *key)
{
    int x = (key->destination_ip_address.s_addr + key->sourse_ip_address.s_addr + key->udp_source_port) % LEN_HASH_SIZE;
    return x > 0 ? x : -x;
}
// update the details for transction
void UpdateTransaction(connection *connect, transaction *current_trans)
{
    transaction *old_node_transaction = connect->trans->tail->data;
    // update the time of the transaction
    old_node_transaction->last_time = current_trans->start_time;
    old_node_transaction->num_out_packet_in_range += 1;
}
void StisticHandler(connection *connect, transaction *current_trans)
{
   // sleep(6);
    transaction *old_node_transaction = connect->trans->tail->data;
    // update the time of the transaction
    old_node_transaction->last_time = current_trans->start_time;
    // // Number of packets from the server to the client with size in range.
    if (inbound_packets_in_range_min < current_trans->size_packet && inbound_packets_in_range_max > current_trans->size_packet)
    {
        //printf("num_in_packet_in_range***************************************************************%d\n",old_node_transaction->num_in_packet_in_range);
        //sleep(10);
        old_node_transaction->num_in_packet_in_range += 1;
    }
    // Max packet size in inbound direction.
    if (old_node_transaction->max_packet_size_in < current_trans->size_packet)
    {
        //printf("old_node_transaction->max_packet_size_in*********************************************** %d\n",old_node_transaction->max_packet_size_in);
        old_node_transaction->max_packet_size_in = current_trans->size_packet;
    }
    // Min packet size in inbound direction.
    if (old_node_transaction->min_packet_size_in > current_trans->size_packet)
    {
        old_node_transaction->min_packet_size_in = current_trans->size_packet;
    }
    // // Max/Min diff time between two consecutive packets (size more than predefine size) in the inbound direction.
    double diff = current_trans->start_time - old_node_transaction->start_time;
    if (diff >= old_node_transaction->max_diff_time_in)
        old_node_transaction->max_diff_time_in = diff;
    if (diff <= old_node_transaction->min_diff_time_in)
        old_node_transaction->min_diff_time_in = diff;

    if (old_node_transaction->recive_server_packet== 0) //
    {
        old_node_transaction->recive_server_packet =1;
        // update the rtt current_time-first_time_request// from the client
        old_node_transaction->rtt =current_trans->start_time-old_node_transaction->start_time;
    }
}
void DeleteConnection(node *foundNode)
{
    // del connection
    node *nodeTemp = foundNode;
    if (foundNode->prev != NULL)
        foundNode->prev->next = foundNode->next;
    else
    {
        list *list_conn = hash_table[Hashfunction(foundNode->data->key)];
        list_conn->head = foundNode->next;
    }
    free(nodeTemp);
}
// func that writeToCsvFile all the data
void handle_timeout(struct connection *foundConnection, struct connection *newConn, struct nodeTrans *newNode, int flag)
{
    double last_time = foundConnection->trans->tail->data->last_time;
    if (last_time != 0)
    {                                                  // not a new connaction
        struct nodeTrans *head = newConn->trans->head; // newNode;
        if (head != NULL)
        {
            //printf("in the handle_timeout list\n");
            double epoch_time = head->data->start_time - last_time;
            // check the diff time between the last transaction and the current transaction
            if (video_connection_timeout < (int)epoch_time || foundConnection->num_trans > max_number_of_transaction_per_video)
            {
                //printf("in the handle_timeout list");
                WriteAllTansctionPerConn(foundConnection);
                // we dont need free because we ovride it
                //  state that the connection ovride the connection by the current connection and insert a transaction
                if (flag == 1)
                {
                    OvrideConnection(foundConnection, newConn);
                    InsertNewTrans(newConn, newNode);
                }
                // if the packet not big over timeout-nothing
            }
            // if not finish the time out!-we dont finish conn
            else if (video_connection_timeout >= (int)epoch_time)
            {
                /// if the big size open transaction
                if (flag)
                {
                    OvrideConnection(foundConnection, newConn);
                    InsertNewTrans(newConn, newNode);
                }
                else
                    UpdateTransaction(foundConnection, newNode->data);
                return;
            }
            else if (!flag)
            {
                // for the server to client side
                StisticHandler(foundConnection, newNode->data);
            }
        }
        else
        {
            //printf("\nnewConnection->trans->head is not null\n");
        }
    }
}

void ClientHandler(struct node *foundNode, struct connection *newConn, int flag)
{
    struct nodeTrans *newNode=newConn->trans->head;
    struct connection *foundConnection = foundNode->data;
    double last_time = foundConnection->trans->tail->data->last_time;
    if (last_time != 0)
    {                                     // not a new connaction
        struct nodeTrans *head = newNode; //->data->start_time;//newConn->trans->head; // newNode;?//??
        if (head != NULL)
        {
            double epoch_time = head->data->start_time - last_time;
            // check the diff time between the last transaction and the current transaction
            if (video_connection_timeout < (int)epoch_time || foundConnection->num_trans > max_number_of_transaction_per_video)
            {
                WriteAllTansctionPerConn(foundConnection);
                // we dont need free because we ovride it
                //  state that the connection ovride the connection by the current connection and insert a transaction
                if (flag == 1)
                {
                    OvrideConnection(foundConnection, newConn);
                    InsertNewTrans(newConn, newNode);
                    //printf("after insert size=%d\n", newConn->trans->size);
                }
                else
                {
                    DeleteConnection(foundNode);
                }
            }
            // if not finish the time out!-we dont finish conn
            else if (video_connection_timeout >= (int)epoch_time)
            {
                /// if the big size open transaction
                if (flag)
                {
                    InsertNewTrans(foundConnection, newNode);
                }
                else
                    UpdateTransaction(foundConnection, newNode->data);
            }
        }
    }
}

void WriteToCsvFile(int connection_id, struct five_tuple *five_tuple, transaction *trans)
{
    char *srv_ip = malloc(SIZE_ADRRESS);
    char *cli_ip = malloc(SIZE_ADRRESS);
    sprintf(srv_ip, "%s", inet_ntoa(five_tuple->sourse_ip_address));
    sprintf(cli_ip, "%s", inet_ntoa(five_tuple->destination_ip_address));
    time_t ti = trans->start_time;
    struct tm *tmp = localtime(&ti);
    if(trans->min_diff_time_in==MAX_TIME)
        trans->min_diff_time_in=0;
    if(trans->min_packet_size_in==INT32_MAX)
        trans->min_packet_size_in=0;
    fprintf(fpt, " %d, %s, %s,       %d,       %d ,       %d,       %d,      %d:%d:%d,       %d,      %d,      %d,        %d,      %f,         %f,       %f \n", connection_id, cli_ip, srv_ip, five_tuple->ip_protocol, five_tuple->udp_source_port, five_tuple->udp_destination_port, trans->transaction_id, tmp->tm_hour, tmp->tm_min, tmp->tm_sec, trans->num_in_packet_in_range, trans->num_out_packet_in_range, trans->max_packet_size_in, trans->min_packet_size_in, trans->max_diff_time_in, trans->min_diff_time_in, trans->rtt);
}

struct connection *InitConnectionClientToServer(const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl << 2;
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));
    struct connection *connect = (struct connection *)malloc(sizeof(connection) * 1);
    struct five_tuple *key = (struct five_tuple *)malloc(sizeof(five_tuple) * 1);
    struct in_addr clinet_ip = source.sin_addr;
    struct in_addr server_ip = dest.sin_addr;
    key->sourse_ip_address = clinet_ip;
    key->destination_ip_address = server_ip;
    key->ip_protocol = iph->protocol;
    int client_port = ntohs(udph->source);
    int server_port = ntohs(udph->dest);
    key->udp_source_port = client_port;
    key->udp_destination_port = server_port;
    connect->key = key;
    struct listTrans *alltrans = create_list_trans();
    struct transaction *newTrans = InitTransaction(header, buffer);
    push_front_trans(alltrans, newTrans);
    //printf("size trand%d\n", alltrans->size);
    connect->trans = alltrans;
    connect->num_trans = 0;
    connect->total_bandwidth = 0;
    connect->connection_id = connection_num;
    return connect;
}
void ServerHandler(node *foundNode, struct connection *newConn)
{
    //printf(" in func ServerHandler\n");
    struct nodeTrans *newNode=newConn->trans->head;
    struct connection *foundConnection = foundNode->data;
    double last_time = foundConnection->trans->tail->data->last_time;
    if (last_time != 0)
    {                                     // not a new connaction
        struct nodeTrans *head = newNode; // newConn->trans->head; // newNode;
        if (head != NULL)
        {
            double epoch_time = head->data->start_time - last_time;
            // check the diff time between the last transaction and the current transaction
            if (video_connection_timeout < (int)epoch_time || foundConnection->num_trans > max_number_of_transaction_per_video)
            {
                WriteAllTansctionPerConn(foundConnection);
                DeleteConnection(foundNode);
            }
            else
            {
                StisticHandler(foundConnection, newNode->data);
            }
        }
    }
}

void ServerToClient(const struct pcap_pkthdr *header, const u_char *buffer)
{
    struct connection *connect = InitConnectionServerToClient(header, buffer);
    struct node *foundnode = SearchConnectionInList(connect, buffer);
    //printf("%s-----------", inet_ntoa(dest.sin_addr));
    //printf("%s-----------", inet_ntoa(source.sin_addr));
    if (foundnode != NULL && foundnode->data != NULL&&foundnode->data->trans->size>0)
    {
       // sleep(3);
        ServerHandler(foundnode, connect);
    }
}
// // func treat for packet client to server
void ClientToServer(const struct pcap_pkthdr *header, const u_char *buffer)
{
    int flag_size = 0;
    struct connection *connect = InitConnectionClientToServer(header, buffer);
    struct node *foundnode = SearchConnectionInList(connect, buffer);
    int size = header->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
    if (request_packet_threshold <= size)
    {
        flag_size = 1;
    }
    if (foundnode != NULL && foundnode->data != NULL && foundnode->data->trans->size > 0)
    {
        ClientHandler(foundnode, connect, flag_size);
    }
    // new trans+connection
    else if (flag_size && foundnode == NULL)
    {
        //printf("new connection+new transaction\n");
        list *list_conect = hash_table[Hashfunction(connect->key)];
        if (list_conect == NULL)
        {
            list_conect = create_list();
            hash_table[Hashfunction(connect->key)] = list_conect;
        }
        UpdateConnections(connect, connect->trans->head);
        //printf("update conn%d\n", connect->trans->size);
        //printf("size before insert trand%d\n", connect->trans->size);
        CreateConnection(connect, list_conect);
        //printf("size after insert conn%d\n", list_conect->size);
    }
    //printf("\nClientToServerend\n");
}
// func that check if the connection equal to the five_tuple
int inline FiveTupleCheck(struct five_tuple *iph, struct in_addr sourse_ip_address, struct in_addr destination_ip_address, int udp_source_port)
{
    int x = (iph->sourse_ip_address.s_addr == sourse_ip_address.s_addr && iph->destination_ip_address.s_addr == destination_ip_address.s_addr && iph->udp_source_port == udp_source_port);
    //printf("\n%d,%d,%d,%d,%d,%d\n", iph->sourse_ip_address.s_addr, sourse_ip_address.s_addr, iph->destination_ip_address.s_addr, destination_ip_address.s_addr, iph->udp_source_port, udp_source_port);
    return x;
}
// func that get connection and access by the five_tuple to the place in the hash
//  and search this connection in the list-return the connection if it exists else null
struct node *SearchConnectionInList(connection *connect, const u_char *buffer)
{
    if (connect == NULL)
    {
        //printf("connection====null");
        return NULL;
    }
    list *list_conect = hash_table[Hashfunction(connect->key)];
    if (list_conect != NULL)
    {
        node *temp = list_conect->head;
        if (temp == NULL)
            return NULL;
        //printf("temp id = %d\n", ((struct connection *)(temp->data))->connection_id);
        //printf("%dtemp->data->num_trans", temp->data->key->ip_protocol);
        while (temp != NULL && temp->data != NULL)
        {
            struct five_tuple *key = temp->data->key;
            if (FiveTupleCheck(connect->key, key->sourse_ip_address, key->destination_ip_address, key->udp_source_port))
                return temp;
            else
                temp = temp->next;
        }
    }
    return NULL;
}

transaction *InitTransaction(const struct pcap_pkthdr *header, const u_char *buffer)
{
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl << 2;
    double epoch_time = header->ts.tv_sec + (double)header->ts.tv_usec / 1000000;
    struct transaction *new_trans = (struct transaction *)malloc(sizeof(transaction) * 1);
    new_trans->transaction_id = 0;
    new_trans->last_time = epoch_time;
    new_trans->sum_squre_in_packet_time = 0;
    new_trans->rtt = 0;
    new_trans->start_time = epoch_time;
    new_trans->recive_server_packet = 0;
    new_trans->num_in_packet_in_range = 0;
    new_trans->num_out_packet_in_range = 0;
    new_trans->min_packet_size_in = INT32_MAX;
    new_trans->max_packet_size_in = 0;
    new_trans->max_diff_time_in = 0;
    new_trans->min_diff_time_in = MAX_TIME;
    int size = header->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
    new_trans->size_packet = size;
    return new_trans;
}
void UpdateConnections(struct connection *foundConnection, struct nodeTrans *newNode)
{
    foundConnection->num_trans += 1;
    foundConnection->total_bandwidth += newNode->data->size_packet;
    newNode->data->transaction_id = transaction_num++;
}
void InsertNewTrans(struct connection *foundConnection, struct nodeTrans *newNode)
{
    // if the list not empty
    if (foundConnection->trans != NULL)
    {
        UpdateConnections(foundConnection, newNode);
        push_back_trans(foundConnection->trans, newNode->data);
    }
}
void WriteAllTansctionPerConn(struct connection *foundConnection)
{
    if (foundConnection->trans != NULL && foundConnection->trans->size > 0)
    {
        if (foundConnection->total_bandwidth < min_video_connection_size)
            return;
        videos_connections += 1;
        double start_time = foundConnection->trans->head->data->start_time;
        double end_time = foundConnection->trans->tail->data->last_time;
        duration_time_all_videos += end_time - start_time;
        size_all_videos += foundConnection->total_bandwidth;
        number_of_TDRs += foundConnection->trans->size;
        //printf(" size of translist====%d\n", foundConnection->trans->size);
        nodeTrans *temp = foundConnection->trans->head;
        while (temp != NULL && temp->data != NULL)
        {
            duration_all_TDRs = temp->data->last_time - temp->data->start_time;
            if (temp->next != NULL)
                time_between_two_consecutive_TDR +=temp->next->data->start_time - temp->data->start_time;
            WriteToCsvFile(foundConnection->connection_id, foundConnection->key, temp->data);
            //printf("\n after writetocsvfile\n");
            // struct nodeTrans *freeTemp = temp;
            //  temp->next = temp->next->next;
            temp = temp->next;
            pop_front_trans(foundConnection->trans);
            // free(freeTemp); // freeTemp->data????
        }
        foundConnection->trans->head = NULL;
        foundConnection->trans->tail = NULL;
        foundConnection->trans->size = 0;
    }
}
void CreateConnection(struct connection *connect, list *list_conect)
{
    connect->connection_id = connection_num;
    push_back(list_conect, connect);
    connection_num++;
}

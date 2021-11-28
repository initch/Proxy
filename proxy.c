/*
   The firewall framework is used to show the foundmental principle the proxy firwwall works, the undergraduates can do some experiments based on the framework, we hope you like these experiments.

   The framework is proposed by Information Security School at Shanghai Jiaotong Univ. If you have any question during the experiments, please send mail to the author, zixiaochao@sjtu.edu.cn, asking for the techinical supports.
 
   Thank you all.
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <sqlite3.h>
#include <stdlib.h>
#include "log.h"

#define REMOTE_SERVER_PORT 80			
#define BUF_SIZE 4096*4 				
#define QUEUE_SIZE 100

typedef struct {
	struct sockaddr_in cl_addr;
	int accept_sockfd;
}accept_info;

pthread_mutex_t conp_mutex;
char lastservername[256] = "192.168.33.1:80";
int lastserverip = 1;
sqlite3 *db;

// 连接数据库
void openDatabase()
{
	int rc = sqlite3_open("log.db", &db);
	if (rc) {
		printf("Can't open database: \n");
		exit(0);
	} else{
		printf("Open database successfully\n");
	}
}

//数据库操作回调函数
static int callback(void *NotUsed, int argc, char **argv, char **azColName){
   int i;
   for(i=0; i<argc; i++){
      printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
   }
   printf("\n");
   return 0;
}

//访问控制数据记录
void access_log(struct sockaddr_in cl_addr, bool accept)
{
	openDatabase();

	//访问时间
	time_t t = time(NULL);
	char time_buffer[80];
   	strftime(time_buffer, 80, "%Y-%m-%e %H:%M:%S", localtime(&t));

	//访问源IP及端口
	char client[INET_ADDRSTRLEN + 1] = {0};  
	inet_ntop(AF_INET, &cl_addr.sin_addr, client, INET_ADDRSTRLEN);  
	uint16_t src_port = ntohs(cl_addr.sin_port);
	char *port = (char*)malloc(10);
	sprintf(port, "%d", src_port);
	char* status = "0";
	if(accept) status = "1";

	printf("[Log] source: %s:%d, destination: %s, policy: %d\n", client, src_port, lastservername, accept);
	
	//数据库操作
	char *sql = (char*)malloc(256);
	char *errMsg = 0;

	strcat(sql, "INSERT INTO access(time, srcIP, srcPort, destIP, destPort, protocol, policy) VALUES ('");
	strcat(sql, time_buffer);
	strcat(sql, "', '");
	strcat(sql, client);
	strcat(sql, "', ");
	strcat(sql, port);
	strcat(sql, ", '192.168.33.1', 80,'TCP',");
	strcat(sql, status);
	strcat(sql, ");");
	//printf(sql);
	int rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
	if (rc != 1 ){
		printf("[SQL error]: %s\n", errMsg);
		sqlite3_free(errMsg);
	}else {
		printf("[Log] Access data inserted done.\n");
	}

	free(port);
	free(sql);
	sqlite3_close(db);
}

//流量数据记录
void flow_log(time_t open, time_t close, struct sockaddr_in cl_addr, int in_packets, int in_bytes, int out_packets, int out_bytes)
{
	openDatabase();

	// 获取客户IP和端口
	char client[INET_ADDRSTRLEN + 1] = {0};  
	inet_ntop(AF_INET, &cl_addr.sin_addr, client, INET_ADDRSTRLEN);  
	uint16_t src_port = ntohs(cl_addr.sin_port);

	// 端口、数据转化为字符串格式
	char *port = (char*)malloc(10);
	sprintf(port, "%d", src_port);
	char *buf_1 = (char*)malloc(10);
	sprintf(buf_1, "%d", in_packets);
	char *buf_2 = (char*)malloc(10);
	sprintf(buf_2, "%d", in_bytes);
	char *buf_3 = (char*)malloc(10);
	sprintf(buf_3, "%d", out_packets);
	char *buf_4 = (char*)malloc(10);
	sprintf(buf_4, "%d", out_bytes);

	// 时间转化为字符串格式
	char open_time[80];
	char close_time[80];
   	strftime(open_time, 80, "%Y-%m-%e %H:%M:%S", localtime(&open));
	strftime(close_time, 80, "%Y-%m-%e %H:%M:%S", localtime(&close));

	char *sql = (char*)malloc(512);
	char *errMsg = 0;

	strcat(sql, "INSERT INTO flow(open,close,srcIP,srcPort,destIP,destPort,protocol,inPackets,inBytes,outPackets,outBytes) VALUES ('");
	strcat(sql, open_time);
	strcat(sql, "', '");
	strcat(sql, close_time);
	strcat(sql, "', '");
	strcat(sql, client);
	strcat(sql, "', ");
	strcat(sql, port);
	strcat(sql, ", '192.168.33.1', 80,'TCP',");
	strcat(sql, buf_1);
	strcat(sql, ", ");
	strcat(sql, buf_2);
	strcat(sql, ", ");
	strcat(sql, buf_3);
	strcat(sql, ", ");
	strcat(sql, buf_4);
	strcat(sql, ");");
	//printf(sql);

	int rc = sqlite3_exec(db, sql, callback, 0, &errMsg);
	if (rc != 1 ){
		printf("[SQL error]: %s\n", errMsg);
		sqlite3_free(errMsg);
	}else {
		printf("[Log] Flow data inserted done.\n");
	}

	free(port);
	free(sql);
	free(buf_1);
	free(buf_2);
	free(buf_3);
	free(buf_4);

	sqlite3_close(db);
	return;
}

int checkserver(char *hostname){
	/*please add some statments here to accomplish Experiemnt 4! 
	The experiment's mission is to check the ip addr of the server, 
	and block the connection to the server you don't wish to access.*/

	/*A simple example is shown here, you can follow it to accomplish Experiment 4. 
	If you let the client access the server , please return 1, otherwise return -1 */
	

	/*
		#define BLOCKED_SERVER "bbs.sjtu.edu.cn"

		if (strstr(hostname, BLOCKED_SERVER) != NULL) {
			printf("Destination blocked! \n");
			return -1;
		}
	*/
	return 1;

}

int checkclient(in_addr_t cli_ipaddr) {
	printf("Check client...\n");   //if the output statement disturbs the experiments, please delete it.  

	/*please add some statments here to accomplish Experiemnt 3! 
	The experiment's mission is to check the ip addr of the cliens, 
	and block the connection from these clients you don't provide the proxy service.*/

	/*A simple example is shown here, you can follow it to accomplish Experiment 3. 
	If you want to provide the proxy server to the clients, please return 1, otherwise return -1 */

	char REJECTED_IP[20] =  "192.168.98.2";
	int rejectedip;
	inet_aton(REJECTED_IP,&rejectedip);
	if (rejectedip == cli_ipaddr)	{
		printf("Client %s authentication failed !\n ", REJECTED_IP);
		return -1;
	}
	
	/*
		char ALLOWED_CLIENTIP[20] =  "192.168.245.1";
		int allowedip;
		inet_aton(ALLOWED_CLIENTIP,&allowedip);
		if (allowedip != cli_ipaddr)	{
			printf("Client IP authentication failed !\n ");
			return -1;
		}
	
	*/
	return 1;
}


void print_clientinfo(struct sockaddr_in cli_addr)
{
	/*please add some statments here to accomplish the Experiemnt 2! 
	The experiment's mission is to print the ip addr and port of client making proxy request.*/

	char buff[INET_ADDRSTRLEN + 1] = {0};  
	inet_ntop(AF_INET, &cli_addr.sin_addr, buff, INET_ADDRSTRLEN);  
	uint16_t port = ntohs(cli_addr.sin_port);
	printf("Received a request from %s, port %d\n", buff, port);
 
	return;
}

void print_severinfo(struct sockaddr_in server_addr)
{
	//please add some statments here to accomplish the Experiemnt 2! 
	//The mission is to print the ip addr and port of the remote web server.
	char buff[INET_ADDRSTRLEN + 1] = {0};  
	inet_ntop(AF_INET, &server_addr.sin_addr, buff, INET_ADDRSTRLEN);  
	uint16_t port = ntohs(server_addr.sin_port);
	printf("HTTP server: %s, port %d\n", buff, port);
 
	return;
}


void* dealonereq(void *arg)
{
	time_t open_time = time(NULL);
	int in_packets = 0, in_bytes = 0, out_packets = 0, out_bytes = 0;

	int bytes;
	char buf[BUF_SIZE]; 											// buffer for incoming file
	char recvbuf[BUF_SIZE],hostname[256];
	int remotesocket;
	accept_info* info = (accept_info*)arg;
	struct sockaddr_in cl_addr = info->cl_addr;
	int accept_sockfd = info->accept_sockfd;
	pthread_detach(pthread_self());
	//
	bzero(buf,BUF_SIZE);
	bzero(recvbuf,BUF_SIZE);

	bytes = read(accept_sockfd, buf, BUF_SIZE); 							// read a buffer from socket
	if (bytes <= 0) {	
		close(accept_sockfd);
		return; 
	}
	in_bytes += bytes;

	getHostName(buf,hostname,bytes);
	if (sizeof(hostname) == 0) {
		printf("Invalid host name");
		close(accept_sockfd);
		return;
	}
	if (checkserver(hostname) != 1){
		close(accept_sockfd);
		return; 
	}

	remotesocket = connectserver(hostname);
	if (remotesocket == -1){
		close(accept_sockfd);
		return; 
	}

	send(remotesocket, buf, bytes,MSG_NOSIGNAL);
	in_packets += 1;

	while(1) {
		int readSizeOnce = 0;
		readSizeOnce = read(remotesocket, recvbuf, BUF_SIZE);				
		if (readSizeOnce <= 0) {
			break;
		}
		send(accept_sockfd, recvbuf, readSizeOnce,MSG_NOSIGNAL);
		out_packets += 1;
		out_bytes += readSizeOnce;
	}

	printf("In packets: %d \n", in_packets);
	printf("In bytes: %d B\n", in_bytes);
	printf("Out packets: %d \n", out_packets);
	printf("Out bytes: %d B\n", out_bytes);

	close(remotesocket);
	close(accept_sockfd);
	time_t close_time = time(NULL);
	
	flow_log(open_time, close_time, cl_addr, in_packets, in_bytes, out_packets, out_bytes);  // 数据流量统计记录
}

/*
 * Main entry: read listening port from the command prompt
 */
int main(int argc, char **argv)
{
	short port = 0;
	char opt;
	struct sockaddr_in cl_addr,proxyserver_addr;
	socklen_t sin_size = sizeof(struct sockaddr_in);
	int sockfd, accept_sockfd, on = 1;
	pthread_t Clitid;

	while( (opt = getopt(argc, argv, "p:")) != EOF) {
		switch(opt) {
		case 'p':
			port = (short) atoi(optarg);
			break;
		default:
			printf("Usage: %s -p port\n", argv[0]);
			return -1;
		}
	}

	if (port == 0) {
		printf("Invalid port number, try again. \n");
			printf("Usage: %s -p port\n", argv[0]);
			return -1;
	}

	printf("Welcome to attend the experiments of designing a proxy firewall! \n");

	memset(&proxyserver_addr, 0, sizeof(proxyserver_addr));							// zero proxyserver_addr
	proxyserver_addr.sin_family = AF_INET;
	proxyserver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	proxyserver_addr.sin_port = htons(port);

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);			// create socket
	if (sockfd < 0) {
		printf("Socket failed...Abort...\n");
		return;
	} 
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));
	if (bind(sockfd, (struct sockaddr *) &proxyserver_addr, sizeof(proxyserver_addr)) < 0) {
		printf("Bind failed...Abort...\n");
		return;
	} 
	if (listen(sockfd, QUEUE_SIZE) < 0) {
		printf("Listen failed...Abort...\n");
		return;
	}
	
	while (1) {
		accept_sockfd = accept(sockfd, (struct sockaddr *)&cl_addr, &sin_size); 	// block for connection request
		if (accept_sockfd < 0) {
			printf("accept failed");
			continue;
		}

		print_clientinfo(cl_addr);

		accept_info info;
		info.cl_addr = cl_addr;
		info.accept_sockfd = accept_sockfd;

		bool accept = false;
		if (checkclient(cl_addr.sin_addr.s_addr) == 1)
		{
			accept = true;
			pthread_attr_t attr; 
    		pthread_attr_init(&attr); 
    		pthread_attr_setdetachstate(&attr,1); 
			pthread_create(&Clitid, &attr, dealonereq, (void*)&info);
		}
		else {
			close(accept_sockfd);
		}		
		access_log(cl_addr, accept);  // 访问控制数据记录
	}
	
	return 0;
}


int getHostName(char* buf,char *hostname, int length)			//tested, must set this pointer[-6] to be '\n' again.
{
	
	char *p=strstr(buf,"Host: ");
	int i,j = 0;
	if(!p) {
		p=strstr(buf,"host: ");
	}
	bzero(hostname,256);
	for(i = (p-buf) + 6, j = 0; i<length; i++, j++)	{
		if(buf[i] =='\r') {
			hostname[j] ='\0';
			return 0;
		}
		else 
			hostname[j] = buf[i];
	}	
	return -1;
}

int connectserver(char* hostname)
{
	int cnt_stat;
	struct hostent *hostinfo;								// info about server
	struct sockaddr_in server_addr; 							// holds IP address
	int remotesocket;
	int remoteport = REMOTE_SERVER_PORT;  //80
	char newhostname[32];
	char *tmpptr;

	strcpy(newhostname, lastservername); 
	tmpptr = strchr(newhostname,':');
	if (tmpptr != NULL)   //port is included in newremotename
	{
		remoteport = atoi(tmpptr + 1); //skip the char ':'
		*tmpptr = '\0';		
	}
		

	remotesocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (remotesocket < 0) {
		printf("can't create socket! \n");
		return -1;
	}
	memset(&server_addr, 0, sizeof(server_addr));

	//

	server_addr.sin_family= AF_INET;
//	server_addr.sin_port= htons(REMOTE_SERVER_PORT);
	server_addr.sin_port= htons(remoteport);
	pthread_mutex_lock(&conp_mutex);
	if (strcmp(lastservername, newhostname) != 0)
	{ 	
		hostinfo = gethostbyname(newhostname);						
		if (!hostinfo) {
			
			printf("gethostbyname(%s) failed! \n",newhostname);
			pthread_mutex_unlock(&conp_mutex);
			return -1;
		}
		strcpy(lastservername,newhostname);
		lastserverip = *(int *)hostinfo->h_addr;
	}
	server_addr.sin_addr.s_addr = lastserverip;
	pthread_mutex_unlock(&conp_mutex);

	print_severinfo(server_addr);

	if (connect(remotesocket, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
		printf("remote connect failed! \n");
		close(remotesocket);
		return -1;
	}

	//You can delete the statement in case of voiding too much output.
	//printf("A proxy connection is established properly, the experiment 1 is done! Congratulation! \n");  

 	return remotesocket;
}




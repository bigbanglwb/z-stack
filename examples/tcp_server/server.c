#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>
#include<stdio.h>
#include<arpa/inet.h>
#include <rte_arp.h>
#include "api.h"
#include "ip.h"

#define BUFFER_SIZE 1024
static int tcp_server_entry(__attribute__((unused))  void *arg){

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr,0,sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);

	nbind(listenfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

	nlisten(listenfd,10);

	while(1){

		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd,(struct sockaddr *)&client,&len);

		char buff[BUFFER_SIZE] = {0};
		while(1){
			int n = nrecv(connfd,buff,BUFFER_SIZE,0);
			if(n > 0){
				printf("recv: %s\n",buff);
				nsend(connfd,buff,n,0);
			}else if(n == 0){
				nclose(connfd);
				break;
			}else{
				
			}
		}
	}
	nclose(listenfd);
}
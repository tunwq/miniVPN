#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555
#define BUFF_SIZE 2000

struct sockaddr_in peerAddr;

/* header files copied from tlsserver.c file */
#include "tls_root_ca.h"
#include "tlse.c"
#include <netdb.h>
#include <unistd.h>

/*libraries for authentication */
#include <shadow.h>
#include <crypt.h>

/*libraries for multi client */
#include <fcntl.h>

#define CHK_SSL(err)               \
   if ((err) < 1)                  \
   {                               \
      ERR_print_errors_fp(stderr); \
      exit(2);                     \
   }
//#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stdout); exit(2); }
#define CHK_ERR(err, s) \
   if ((err) == -1)     \
   {                    \
      perror(s);        \
      exit(1);          \
   }

int setupTCPServer();                                             // Defined in Listing 19.10
void processRequest(int pipefd, SSL *ssl, int sockfd, int tunfd); // Defined in Listing 19.12

void closeSSLAndSocket(SSL *ssl, int newsock)
{
   if (ssl != NULL)
   {
      SSL_shutdown(ssl);
      SSL_free(ssl);
   }
   close(newsock);
}

int createTunDevice()
{
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);
   printf("Created a tun device with the name: %s\n", ifr.ifr_name);
   return tunfd;
}

void pipeSelected(int pipefd, int sockfd, SSL *ssl)
{
   //   nbytes = read(fd[0], readbuffer, sizeof(readbuffer)); ➂
   int len;
   char buff[BUFF_SIZE];

   //    printf("Got a packet from TUN Interface\n");

   bzero(buff, BUFF_SIZE);
   len = read(pipefd, buff, BUFF_SIZE);
   buff[len] = '\0';
   SSL_write(ssl, buff, len);
   /*   sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                      sizeof(peerAddr));*/
}
// void tunPipeselected(int tunfd, int sockfd, SSL *ssl) {
void tunPipeSelected(int tunfd, int pipefd)
{
   int len;
   char buff[BUFF_SIZE];

   //    printf("Got a packet from TUN Interface\n");

   bzero(buff, BUFF_SIZE);
   len = read(tunfd, buff, BUFF_SIZE);
   buff[len] = '\0';
   write(pipefd, buff, len);
}

void checkforTermination(char buff[], SSL *ssl, int sockfd)
{
   if ((buff[0] != '\0') && strstr(buff, "terminate$$connection") != NULL)
   {
      printf("Received a request to terminate the connection\n");
      closeSSLAndSocket(ssl, sockfd);
      exit(0);
   }
   // the above sends a sigchild to the parent to handle the kill of the child.
}

void socketSelected(int pipefd, int sockfd, SSL *ssl, int tunfd)
{
   int len;
   char buff[BUFF_SIZE];
   char *ptr = buff;
   //  printf("Got a packet from the tunnel established \n");

   bzero(buff, BUFF_SIZE);
   /* len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
    write(tunfd, buff, len); */
   /*   do {
      len = SSL_read(ssl, ptr, sizeof(buff)-1);
      ptr += len;
     // buff[len] = '\0';
      } while(len > 0);*/
   len = SSL_read(ssl, buff, BUFF_SIZE);
   buff[len] = '\0';
   // write code for connection termination;
   checkforTermination(buff, ssl, sockfd);
   //   printf("Writing buf: %s to the tun/tap interface\n", buff);
   write(tunfd, buff, len);
}

/*int initUDPServer() {
    int sockfd;
    struct sockaddr_in server;
    char buff[100];

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_NUMBER);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sockfd, (struct sockaddr*) &server, sizeof(server));

    // Wait for the VPN client to "connect".
    bzero(buff, 100);
    int peerAddrLen = sizeof(struct sockaddr_in);
    int len = recvfrom(sockfd, buff, 100, 0,
                (struct sockaddr *) &peerAddr, &peerAddrLen);

    printf("Connected with the client: %s\n", buff);
    return sockfd;
}*/

void processRequest(int pipefd, SSL *ssl, int sockfd, int tunfd)
{
   /* char buf[1024];
     while(1) {
     int len = SSL_read(ssl, buf, sizeof(buf)-1);
     buf[len] = '\0';
     printf("Received: %s\n",buf);

     // Construct and send the HTML page
      char *html =
         "HTTP/1.1 200 OK\r\n"
         "Content-Type: text/html\r\n\r\n"
         "<!DOCTYPE html><html>"
         "<head><title>Hello World</title></head>"
         "<style>body {background-color: black}"
         "h1 {font-size:3cm; text-align: center; color: white;"
         "text-shadow: 0 0 3mm yellow}</style></head>"
         "<body><h1>Hello, world!</h1></body></html>";
     SSL_write(ssl, html, strlen(html));
      sleep(2);
    }*/

   while (1)
   {
      fd_set readFDSet;

      FD_ZERO(&readFDSet);
      FD_SET(sockfd, &readFDSet);
      FD_SET(pipefd, &readFDSet);
      select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

      if (FD_ISSET(pipefd, &readFDSet))
         pipeSelected(pipefd, sockfd, ssl);
      if (FD_ISSET(sockfd, &readFDSet))
         socketSelected(pipefd, sockfd, ssl, tunfd);
   }

   //    SSL_shutdown(ssl);  SSL_free(ssl);
}

int setupTCPServer()
{
   struct sockaddr_in sa_server;
   int listen_sock;

   listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   CHK_ERR(listen_sock, "socket");
   memset(&sa_server, '\0', sizeof(sa_server));
   sa_server.sin_family = AF_INET;
   sa_server.sin_addr.s_addr = INADDR_ANY;
   sa_server.sin_port = htons(4433);
   int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));
   CHK_ERR(err, "bind");
   err = listen(listen_sock, 5);
   CHK_ERR(err, "listen");
   printf("Created a tcp server listening on port: 4433 for any IP\n");
   return listen_sock;
}

int authenticateClient(SSL *ssl, int newsock)
{
   char username[100];
   char password[1000];
   char recvBuff[BUFF_SIZE];
   bzero(recvBuff, BUFF_SIZE);
   memset(&username, 0x00, sizeof(username));
   memset(&password, 0x00, sizeof(password));

   int len;
   len = SSL_read(ssl, recvBuff, BUFF_SIZE - 1);
   recvBuff[len] = '\0';
   printf("Server received the following string for authentication: %s\n", recvBuff);
   char *pch;
   pch = strtok(recvBuff, "$");
   if (pch != NULL)
   {
      strcpy(username, pch);
      pch = strtok(NULL, "$");
   }
   if (pch != NULL)
   {
      strcpy(password, pch);
   }
   //  printf("username given is %s and password given is %s\n", username, password);
   /*  len = SSL_read(ssl, username, strlen(username));
     username[len] = '\0';
     len = SSL_read(ssl, password, strlen(password));
     password[len] = '\0'; */
   struct spwd *pw;
   char *epasswd;
   pw = getspnam(username);
   if (pw == NULL)
   {
      printf("No password for the given user name\n");
      return -1;
   }
   printf("Given user name: %s\n", username);
   printf("Given password: %s\n", password);
   printf("Login name: %s\n", pw->sp_namp);
   printf("Passwd : %s\n", pw->sp_pwdp);
   epasswd = crypt(password, pw->sp_pwdp);
   char sendNegResp[] = "not-ok-auth";
   char sendPosResp[] = "auth$ok";
   if (strcmp(epasswd, pw->sp_pwdp))
   {
      printf("Password entered doesn't match with correct password\n");
      SSL_write(ssl, sendNegResp, strlen(sendNegResp));
      return -1;
   }
   SSL_write(ssl, sendPosResp, strlen(sendPosResp));
   return 1;
}

int main(int argc, char *argv[])
{
   int tunfd, sockfd;
   int fd[2];
   int fdd[2];
   pid_t pid;

   tunfd = createTunDevice();
   pipe(fd);
   // pipe2(fdd, O_DIRECT);
   if ((pid = fork()) == -1)
   {
      perror("fork");
      exit(1);
   }

   if (pid > 0)
   {                // parent process
      close(fd[0]); // Close the input end of the sender pipe.
                    //   close(fdd[1]); // Close the output end of the receiver pipe.
      while (1)
      {
         fd_set readFDSet;
         FD_ZERO(&readFDSet);
         //     FD_SET(fd[1], &readFDSet);
         FD_SET(tunfd, &readFDSet);
         select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

         if (FD_ISSET(tunfd, &readFDSet))
            tunPipeSelected(tunfd, fd[1]);
         //    if (FD_ISSET(fd[1], &readFDSet))  pipeSelected(tunfd, fd[1]);
      }
      // Write data to the pipe.
      //     write(fd[1], string, (strlen(string)+1)); ➁
      exit(0);
   }
   else
   {
      close(fd[1]); // Close the output end of the receiver pipe.
                    //  close(fdd[0]); // Close the input end of the sender pipe.
                    //  close(fd[0]); // Close the input end of the pipe.
                    // child process
      // Read data from the pipe.
      //   nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
      //    printf("Child process received string: %s", readbuffer);
      //   }

      // Step 3: Create a new SSL structure for a connection
      /*******************************************
      // doing the below step in the child process
       *******************************************/

      struct sockaddr_in sa_client;
      size_t client_len;

      sockfd = setupTCPServer();

      SSL *server_ctx = SSL_CTX_new(SSLv3_server_method());
      if (!server_ctx)
      {
         fprintf(stderr, "Error creating server context.\n");
         return -1;
      }
      SSL_CTX_use_certificate_file(server_ctx, "./cert_server/server-gangula.crt", SSL_SERVER_RSA_CERT);
      SSL_CTX_use_PrivateKey_file(server_ctx, "./cert_server/server-gangula.key", SSL_SERVER_RSA_KEY);

      if (!SSL_CTX_check_private_key(server_ctx))
      {
         fprintf(stderr, "private key not loaded.\n");
         return -2;
      }

      // Enter the main loop
      while (1)
      {
         int client_sock = accept(sockfd, (struct sockaddr *)&sa_client, &client_len);
         if (fork() == 0)
         { // The child process
            /*close the listening socket on the child process */
            close(sockfd);
            printf("Closed the listening socket for child process\n");
            printf("New connection is running on child proceess\n");

            SSL *client_ctx = SSL_new(server_ctx);
            if (!client_ctx)
            {
               fprintf(stderr, "Error creating SSL client.\n");
               return -4;
            }

            SSL_set_fd(client_ctx, client_sock);
            printf("SSL_Set_fd is successful executed.\n");

            if(!SSL_accept(client_ctx)) {
               closeSSLAndSocket(client_ctx, client_sock);
               printf("SSL Connect error.\n");
               return 0;
            }
            fprintf(stderr, "Cipher %s\n", tls_cipher_name(client_ctx));
            //   printf("SSL_accept there is some error\n");
            printf("SSL Handshake is successfully established in child process!\n");
            //    fd_set readFDSet;
            if (authenticateClient(client_ctx, client_sock) != 1)
            {
               closeSSLAndSocket(client_ctx, client_sock);
               printf("Cleared socket and ssl structures.. ENd of child process\n");
               return 0;
            }
            printf("CLient authentication is successful and ready to receive data on the channel\n");
            processRequest(fd[0], client_ctx, client_sock, tunfd);
            closeSSLAndSocket(client_ctx, client_sock);
            printf("Cleared socket and ssl structures.. End of child process\n");
            return 0;
            /*   FD_ZERO(&readFDSet);
            FD_SET(sockfd, &readFDSet);
            FD_SET(tunfd, &readFDSet);
            select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
            processRequest(tunfd, newsock, ssl);
            if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, newsock, ssl);
            if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, newsock, ssl);*/

            /************************************************************************************************
              Where should i place the below line check once
             *************************************************************************************************/
            //  processRequest(ssl);
         }
         else
         {
            // The parent process
            // close the accepted tcp connection on the server process
            close(client_sock);
            //	close(tunfd);
            printf("Closed the accepted connected inside parent process");
         }
      }
   }
}

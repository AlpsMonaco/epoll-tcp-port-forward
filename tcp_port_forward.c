#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EVENTS 32
#define BUF_SIZE 64

static void print_help_msg() {
  printf("usage:\n  ./tcp_port_forward [local_port] [remote_ip] [remote_port]");
}

// A session binds a client socket to a remote socket and forwards data between
// them.
struct session {
  int client_fd; // File descriptor for the client socket.
  int remote_fd; // File descriptor for the remote socket.

  // Indicates whether the remote socket is ready for communication.
  // When the remote socket is not connected, the client might have sent some
  // data. In this case, we avoid reading data from the client until the remote
  // socket is ready. If we don't read from the client, epoll will continue to
  // signal readability events, allowing us to read the data later when the
  // remote socket is ready.
  bool ready;
  struct session *next;
};

// a linked list that handles all sessions.
typedef struct session *sessions;

// Bind a client socket to a remote socket, create a session that holds them,
// and push it to the sessions list for later querying.
static struct session *add_session(sessions *head, int client_fd,
                                   int remote_fd) {
  struct session *new_session =
      (struct session *)malloc(sizeof(struct session));
  new_session->client_fd = client_fd;
  new_session->remote_fd = remote_fd;
  new_session->ready = false;
  new_session->next = NULL;
  if (*head == NULL) {
    *head = new_session;
  } else {
    struct session *p = *head;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = new_session;
  }
  return new_session;
}

// Delete a session from the sessions list using the client file descriptor.
static void del_session(sessions *head, int client_fd) {
  struct session *prev = NULL, *p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->client_fd == client_fd) {
      if (prev != NULL) {
        prev->next = p->next;
      } else {
        *head = p->next;
      }
      free(p);
      return;
    }
    prev = p;
    p = p->next;
  }
}

// Query a session by the remote file descriptor.
static struct session *query_remote_session(sessions *head, int remote_fd) {
  struct session *p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->remote_fd == remote_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL; // Return NULL if no matching session is found.
}

// Query a session by the client file descriptor.
static struct session *query_client_session(sessions *head, int client_fd) {
  struct session *p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->client_fd == client_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL; // Return NULL if no matching session is found.
}

// Remove monitoring of a client fd and a remote fd from epoll,
// close them, and delete the session from the sessions list.
static void free_session(struct session *session, sessions *head, int epfd) {
  if (session == NULL) {
    return;
  }
  // Remove the remote file descriptor from epoll monitoring.
  epoll_ctl(epfd, EPOLL_CTL_DEL, session->remote_fd, NULL);
  // Remove the client file descriptor from epoll monitoring.
  epoll_ctl(epfd, EPOLL_CTL_DEL, session->client_fd, NULL);

  // Close the remote and client file descriptors.
  close(session->remote_fd);
  close(session->client_fd);

  // Log the closing of the file descriptors.
  printf("[-] client socket is closed,fd:%d\n", session->client_fd);
  printf("[-] remote socket is closed,fd:%d\n", session->remote_fd);

  // Delete the session from the sessions list.
  del_session(head, session->client_fd);
}

static void print_last_error() { fprintf(stderr, strerror(errno)); }

/// @brief Parses a string to a port number and checks if the input is valid.
/// @param src The input string representing the port number (e.g., argv[1] or
/// argv[3]).
/// @param port Pointer to an unsigned short to store the parsed port number.
/// @return A boolean indicating whether the input is a valid port number.
static bool get_port(const char *src, unsigned short *port) {
  char *end;
  unsigned long result = strtoul(src, &end, 10);
  if (*end != '\0') {
    return false;
  }
  if (result == 0 || result > 65535) {
    fprintf(stderr, "invalid port");
    return false;
  }
  *port = result;
  return true;
}

/// @brief Sets the socket file descriptor to non-blocking mode. Necessary for
/// epoll.
/// @param sockfd The socket file descriptor to set to non-blocking mode.
/// @return A boolean indicating whether the non-blocking state was successfully
/// set.
static bool set_non_blocking(int sockfd) {
  int flag;
  // Retrieve the current file descriptor flags.
  flag = fcntl(sockfd, F_GETFL, 0);
  if (flag == -1) {
    return false;
  }
  // Set the file descriptor flags to include O_NONBLOCK.
  flag = fcntl(sockfd, F_SETFL, flag | O_NONBLOCK);
  if (flag == -1) {
    return false;
  }
  return true;
}

/// @brief Listen on a local port. Any request to this port will be forwarded to
/// the specified remote port.
/// @param local_port The local port to listen on.
/// @param local_addr Pointer to a sockaddr_in structure to hold the local
/// address information.
/// @return The socket file descriptor that listens on the local port, or -1 on
/// error.
static int listen_local(unsigned short local_port,
                        struct sockaddr_in *local_addr) {
  int fd;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    return -1;
  }
  memset(local_addr, 0, sizeof(struct sockaddr_in));
  local_addr->sin_family = AF_INET;
  local_addr->sin_addr.s_addr = INADDR_ANY;
  local_addr->sin_port = htons(local_port);
  if (bind(fd, (struct sockaddr *)local_addr, sizeof(*local_addr)) == -1) {
    return -1;
  }
  if (!set_non_blocking(fd)) {
    return -1;
  }
  if (listen(fd, 32) == -1) {
    return -1;
  }
  return fd;
}

int main(int argc, char *argv[]) {
  if (argc < 4) {
    print_help_msg();
    return 1;
  }
  unsigned short local_port, remote_port;
  if (!get_port(argv[1], &local_port)) {
    print_help_msg();
    return 1;
  }
  if (!get_port(argv[3], &remote_port)) {
    print_help_msg();
    return 1;
  }
  int local_fd;
  struct sockaddr_in local_addr;
  local_fd = listen_local(local_port, &local_addr);
  if (local_fd == -1) {
    print_last_error();
    return 1;
  }
  int epfd;
  epfd = epoll_create(1);
  if (epfd == -1) {
    print_last_error();
    return 1;
  }
  struct epoll_event ev;
  // For a listening socket, handle EPOLLIN events (new client connections).
  ev.events = EPOLLIN;
  ev.data.fd = local_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, local_fd, &ev) == -1) {
    print_last_error();
    return 1;
  }
  int nfds, i, client_fd, socklen, remote_fd, err, read_size;
  struct epoll_event events[MAX_EVENTS];
  struct sockaddr_in client_addr, remote_addr;
  const char *remote_ip = argv[2];
  socklen_t err_len = sizeof(err);
  sessions head;
  struct session *session;
  socklen = sizeof(client_addr);
  char buf[BUF_SIZE];
  memset(buf, 0, BUF_SIZE);
  for (;;) {
    nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    for (int i = 0; i < nfds; i++) {
      // Handle new client connections.
      if (events[i].data.fd == local_fd) {
        client_fd = accept(local_fd, (struct sockaddr *)&client_addr, &socklen);
        if (client_fd == -1) {
          print_last_error();
          return 1;
        }
        if (!set_non_blocking(client_fd)) {
          print_last_error();
          return 1;
        }
        // Monitor client fd for read and disconnect events.
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
        ev.data.fd = client_fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
        printf("[+] new client accepted,fd:%d\n", client_fd);
        // Connect to the remote address.
        remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_fd == -1) {
          print_last_error();
          return 1;
        }
        if (!set_non_blocking(remote_fd)) {
          print_last_error();
          return 1;
        }
        printf("[+] connecting to remote socket,fd:%d\n", remote_fd);
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(remote_port);
        inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr);
        int result = connect(remote_fd, (struct sockaddr *)&remote_addr,
                             sizeof(remote_addr));
        // because we set the remote_fd to non-blocking,so we might get an
        // errno(but this is not an error).
        // the errno will be EINPROGRESS,mean the connection is still in
        // progress,we could handle it properly like below.
        if (result == -1) {
          if (errno != EINPROGRESS) {
            print_last_error();
            close(remote_fd);
          }
        }
        ev.events = EPOLLOUT;
        ev.data.fd = remote_fd;
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, remote_fd, &ev) == -1) {
          print_last_error();
          return 1;
        }
        // bind client_fd and remote_fd,any data to one of the two fd will be
        // forwarded to another fd.
        add_session(&head, client_fd, remote_fd);
        continue;
      }
      // handle EINPROGRESS event which remote_fd returns .
      // When the connection is finished no matter success or failure,
      // the remote_fd will poll a EPOLLOUT event,means it is writable.
      // we use getsockopt to detect whether the connection is successful,if
      // success, modify the events of remote_fd to EPOLLIN | EPOLLRDHUP |
      // EPOLLHUP like client_fd did,monitors only read or disconnection events.
      if (events[i].events & EPOLLOUT) {
        session = query_remote_session(&head, events[i].data.fd);
        if (getsockopt(events[i].data.fd, SOL_SOCKET, SO_ERROR, &err,
                       &err_len) == -1) {
          close(session->client_fd);
          close(events[i].data.fd);
        } else {
          printf("[+] remote socket is connected,fd:%d\n", session->remote_fd);
          printf("[+] port forwarding tunnel is opened now,client socket "
                 "fd:%d,remote socket fd:%d\n",
                 session->client_fd, session->remote_fd);
          session->ready = true;
          ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
          ev.data.fd = events[i].data.fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
        }
        continue;
      }
      // EPOLLRDHUP | EPOLLHUP events means a socket is disconnected.
      // we don't know whether it is a client fd or a remote fd that triggers
      // this event,so we need to use query_client_session or
      // query_remote_session and check the returned value is not NULL to find
      // out the associated session,then free both client socket and remote
      // socket which the session manages.
      if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
        printf("[-] socket disconnected event,fd:%d,event:%d\n",
               events[i].data.fd, events[i].events);
        session = query_client_session(&head, events[i].data.fd);
        if (session != NULL) {
          free_session(session, &head, epfd);
          continue;
        }
        session = query_remote_session(&head, events[i].data.fd);
        free_session(session, &head, epfd);
        continue;
      }
      // EPOLLIN means a socket fd is ready to be read,we could read it to
      // buffer now.
      // we don't know whether it is a client fd or a remote fd that triggers
      // this event,so we need to use query_client_session or
      // query_remote_session and check the returned value is not NULL to find
      // out the associated session,then write data to another fd.
      if (events[i].events & EPOLLIN) {
        session = query_client_session(&head, events[i].data.fd);
        if (session != NULL) {
          if (!session->ready) {
            continue;
          }
          read_size = read(events[i].data.fd, buf, BUF_SIZE);
          write(session->remote_fd, buf, read_size);
          continue;
        }
        session = query_remote_session(&head, events[i].data.fd);
        read_size = read(events[i].data.fd, buf, BUF_SIZE);
        write(session->client_fd, buf, read_size);
        continue;
      }
    }
  }
  return 0;
}

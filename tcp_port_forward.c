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
  printf("usage:\n  ./tcp_port_forward [local_port] [remote_ip] [report_port]");
}

struct session {
  int client_fd;
  int remote_fd;
  bool ready;
  struct session* next;
};

typedef struct session* sessions;

static struct session* add_session(sessions* head, int client_fd,
                                   int remote_fd) {
  struct session* new_session = (struct session*)malloc(sizeof(struct session));
  new_session->client_fd = client_fd;
  new_session->remote_fd = remote_fd;
  new_session->ready = false;
  new_session->next = NULL;
  if (*head == NULL) {
    *head = new_session;
  } else {
    struct session* p = *head;
    while (p->next != NULL) {
      p = p->next;
    }
    p->next = new_session;
  }
  return new_session;
}

static void del_session(sessions* head, int client_fd) {
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

static struct session* query_client_session(sessions* head, int remote_fd) {
  struct session* p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->remote_fd == remote_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

static struct session* query_remote_session(sessions* head, int client_fd) {
  struct session* p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->client_fd == client_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

static void print_last_error() { fprintf(stderr, strerror(errno)); }
static bool get_port(const char* src, unsigned short* port) {
  char* end;
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

static bool set_non_blocking(int sockfd) {
  int flag;
  flag = fcntl(sockfd, F_GETFL, 0);
  if (flag == -1) {
    return false;
  }
  flag = fcntl(sockfd, F_SETFL, flag | O_NONBLOCK);
  if (flag == -1) {
    return false;
  }
  return true;
}

static int listen_local(unsigned short local_port,
                        struct sockaddr_in* local_addr) {
  int fd;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) {
    return -1;
  }
  memset(local_addr, 0, sizeof(struct sockaddr_in));
  local_addr->sin_family = AF_INET;
  local_addr->sin_addr.s_addr = INADDR_ANY;
  local_addr->sin_port = htons(local_port);
  if (bind(fd, (struct sockaddr*)local_addr, sizeof(*local_addr)) == -1) {
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

static void free_session(struct session* session, sessions* head, int epfd) {
  epoll_ctl(epfd, EPOLL_CTL_DEL, session->remote_fd, NULL);
  epoll_ctl(epfd, EPOLL_CTL_DEL, session->client_fd, NULL);
  close(session->remote_fd);
  close(session->client_fd);
  printf("closing fd:%d %d\n", session->remote_fd, session->client_fd);
  del_session(head, session->client_fd);
}

#define LOG_EPOLL_EVENT(fd_id, event_id)         \
  do {                                           \
    printf("fd:%d event:%d\n", fd_id, event_id); \
  } while (0)

int main(int argc, char* argv[]) {
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
  ev.events = EPOLLIN | EPOLLOUT;
  ev.data.fd = local_fd;
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, local_fd, &ev) == -1) {
    print_last_error();
    return 1;
  }
  printf("local fd is : %d\n", local_fd);
  int nfds, i, client_fd, socklen, remote_fd, err, read_size;
  struct epoll_event events[MAX_EVENTS];
  struct sockaddr_in client_addr, remote_addr;
  const char* remote_ip = argv[2];
  socklen_t err_len = sizeof(err);
  sessions head;
  struct session* session;
  socklen = sizeof(client_addr);
  char buf[BUF_SIZE];
  memset(buf, 0, BUF_SIZE);
  for (;;) {
    nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
    for (int i = 0; i < nfds; i++) {
      LOG_EPOLL_EVENT(events[i].data.fd, events[i].events);
      if (events[i].data.fd == local_fd) {
        client_fd = accept(local_fd, (struct sockaddr*)&client_addr, &socklen);
        if (client_fd == -1) {
          print_last_error();
          return 1;
        }
        if (!set_non_blocking(client_fd)) {
          print_last_error();
          return 1;
        }
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
        ev.data.fd = client_fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
        remote_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_fd == -1) {
          print_last_error();
          return 1;
        }
        if (!set_non_blocking(remote_fd)) {
          print_last_error();
          return 1;
        }
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(remote_port);
        inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr);
        int result = connect(remote_fd, (struct sockaddr*)&remote_addr,
                             sizeof(remote_addr));
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
        add_session(&head, client_fd, remote_fd);
        continue;
      }
      if (events[i].events & EPOLLOUT) {
        session = query_client_session(&head, events[i].data.fd);
        if (getsockopt(events[i].data.fd, SOL_SOCKET, SO_ERROR, &err,
                       &err_len) == -1) {
          close(session->client_fd);
          close(events[i].data.fd);
        } else {
          session->ready = true;
          ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
          ev.data.fd = events[i].data.fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, events[i].data.fd, &ev);
        }
        continue;
      }
      if (events[i].events & (EPOLLRDHUP | EPOLLHUP)) {
        session = query_remote_session(&head, events[i].data.fd);
        if (session != NULL) {
          free_session(session, &head, epfd);
          continue;
        }
        session = query_client_session(&head, events[i].data.fd);
        free_session(session, &head, epfd);
        continue;
      }
      if (events[i].events & EPOLLIN) {
        session = query_remote_session(&head, events[i].data.fd);
        if (session != NULL) {
          if (!session->ready) {
            continue;
          }
          read_size = read(events[i].data.fd, buf, BUF_SIZE);
          write(session->remote_fd, buf, read_size);
          continue;
        }
        session = query_client_session(&head, events[i].data.fd);
        read_size = read(events[i].data.fd, buf, BUF_SIZE);
        write(session->client_fd, buf, read_size);
        continue;
      }
    }
  }
  return 0;
}

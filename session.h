#ifndef __SESSION_H__
#define __SESSION_H__

#include <stdbool.h>
#include <stddef.h>

struct session {
  int client_fd;
  int remote_fd;
  bool ready;
  struct session *next;
};

typedef struct session *sessions;

struct session *add_session(sessions *head, int client_fd, int remote_fd);
void del_session(sessions *head, int client_fd);
struct session *query_remote_session(sessions *head, int remote_fd);
struct session *query_client_session(sessions *head, int client_fd);

#endif
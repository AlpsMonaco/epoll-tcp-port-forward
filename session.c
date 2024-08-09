#include "session.h"

#include <stdlib.h>

struct session *add_session(sessions *head, int client_fd, int remote_fd) {
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

void del_session(sessions *head, int client_fd) {
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

struct session *query_remote_session(sessions *head, int remote_fd) {
  struct session *p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->remote_fd == remote_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

struct session *query_client_session(sessions *head, int client_fd) {
  struct session *p = NULL;
  p = *head;
  while (p != NULL) {
    if (p->client_fd == client_fd) {
      return p;
    }
    p = p->next;
  }
  return NULL;
}

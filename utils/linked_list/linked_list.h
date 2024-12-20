#ifndef LINKED_LIST_H
#define LINKED_LIST_H


typedef struct node {
    void *data;
    struct node *next;
} node_t;

node_t *create_node(void *data);
node_t *add_node(node_t *head, void *data);
node_t* add_node_end(node_t *head, void *data);
node_t *remove_node(node_t *head);
void free_list(node_t *head);
void free_list_nodes_only(node_t *head);

#endif
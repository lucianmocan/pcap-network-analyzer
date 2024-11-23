#include "linked_list.h"
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Create a node object
 * 
 * @param data 
 * @return node_t* 
 */
node_t*
create_node(void *data)
{
    node_t *node = (node_t*)malloc(sizeof(node_t));
    if (node == NULL){
        fprintf(stderr, "Failed to allocate memory for node\n");
        exit(EXIT_FAILURE);
    }
    node->data = data;
    node->next = NULL;
    return node;
}

/**
 * @brief Add a node to the beginning to 
 * an existing linked list or NULL head
 * 
 * @param head 
 * @param data 
 * @return node_t* 
 */
node_t*
add_node(node_t *head, void *data)
{
    node_t *new_node = create_node(data);
    if (new_node == NULL){
        return NULL;
    }
    new_node->next = head;
    return new_node;
}

/**
 * @brief Remove a node from a linked list (pop)
 * 
 * @param head 
 * @param data 
 * @return node_t* 
 */
node_t*
remove_node(node_t *head)
{
    if (head == NULL){
        return NULL;
    }
    node_t *next = head->next;
    free(head->data);
    free(head);
    return next;
}

/**
 * @brief Free a linked list, leave the data untouched
 * 
 * @param head 
 */
void 
free_list_nodes_only(node_t *head)
{
    node_t *current = head;
    while (current != NULL){
        node_t *next = current->next;
        free(current);
        current = next;
    }
}

/**
 * @brief Free a linked list along with the data on the nodes
 * 
 * @param head 
 */
void 
free_list(node_t *head)
{
    node_t *current = head;
    while (current != NULL){
        node_t *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
}
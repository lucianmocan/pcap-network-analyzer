#include "linked_list.h"
#include <stdlib.h>

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
        return NULL;
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
remove_node(node_t *head, void *data)
{
    if (head == NULL){
        return NULL;
    }
    node_t *next = head->next;
    free(head);
    return next;
}

/**
 * @brief Free a linked list
 * 
 * @param head 
 */
void 
free_list(node_t *head)
{
    node_t *current = head;
    while (current != NULL){
        node_t *next = current->next;
        free(current);
        current = next;
    }
}
#include "linked_list.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void 
test_create_node()
{
    int data = 42;
    node_t *node = create_node(&data);
    assert(node != NULL && "Failed to create node");
    assert(node->data == &data && "Failed to set data");
    assert(node->next == NULL && "Node next should be NULL");
    free_list_nodes_only(node);
}

void
test_add_node()
{
    int data = 42;
    node_t *head = add_node(NULL, &data);
    assert(head != NULL && "Failed to add node");
    assert(head->data == &data && "Failed to set data");
    assert(head->next == NULL && "Head node next should be NULL");

    int data1 = 43;
    node_t *new_head = add_node(head, &data1);
    assert(new_head != NULL && "Failed to add node");
    assert(new_head->data == &data1 && "Failed to set data");
    assert(new_head->next == head && "Head node next pointer is incorrect");
    free_list_nodes_only(new_head);
}

void 
test_remove_node()
{   
    int *data = (malloc(sizeof(int)));
    *data = 42;
    node_t *head = add_node(NULL, data);
    int *data1 = (malloc(sizeof(int)));
    *data1 = 43;
    node_t *new_head = add_node(head, data1);
    node_t *next = remove_node(new_head);
    assert(next == head && "Incorrect node removed");
    node_t *next1 = remove_node(next);
    assert(next1 == NULL && "Failed to remove node");
}

int
main(int argc, char** argv)
{
    test_create_node();
    test_add_node();
    test_remove_node();
    return 0;
}
/*
 * yaml_parser.c
 *
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <yaml.h>
#include "yaml_parser.h"

static config_node*
_create_new_node(const char* name, const char* type,
                 const char* tag, config_node* parent)
 {
    config_node* anode = (config_node*) malloc(sizeof(config_node));
    memset(anode, 0, sizeof(config_node));
    if(name != NULL && strlen(name)) {
        strcpy(anode->node_name, name);
    }
    if(type != NULL && strlen(type)) {
        strcpy(anode->node_type, type);
    }
    if(tag != NULL && strlen(tag)) {
        strcpy(anode->node_tag, tag);
    }

    anode->parent = parent;

    return anode;
 }

static void
_append_node(config_node* anode, config_node* achild)
 {
    if(anode->node_value.seq_value.start == NULL) {
        anode->node_value.seq_value.start = achild;
        anode->node_value.seq_value.end = achild;
    } else {
        anode->node_value.seq_value.end->next = achild;
        anode->node_value.seq_value.end = achild;
    }
 }

void
walk (config_node* root)
{
    config_node* anode = root;
    config_node* start = anode->node_value.seq_value.start;
    config_node* ptr = NULL;
    if(strcmp(root->node_type, "SCALAR") == 0) {
        //printf("%s: %s=%s\n", root->node_type,
          //     root->node_name, root->node_value.str_value);
    } else {
     //   printf("%s: %s: %s \n", root->node_name, root->node_type, root->node_tag);
        for(ptr = start; ptr != NULL; ptr = ptr->next) {
            walk(ptr);
        }
    }
}

static void
_process_event(yaml_parser_t* parser, yaml_event_type_t parent_event_type,
              config_node* parent_node)
{
    config_node* anode = NULL;
    char* attribute = NULL;
    yaml_event_t event;
    int done = 0;
    int error = 0;

    while (!done) {
        /* Get the next event. */
        if (!yaml_parser_parse(parser, &event)) {
            error = 1;
            break;
        }
        switch(parent_event_type) {
            case YAML_NO_EVENT:
                if(event.type == YAML_STREAM_START_EVENT) {
                    _process_event(parser, event.type, parent_node);
                    done = 1;
                } else {
                    //printf("Error: unexpected event %d\n", event.type);
                }
                break;
            case YAML_STREAM_START_EVENT:
                if(event.type == YAML_DOCUMENT_START_EVENT) {
                    anode = _create_new_node("document", "DOC",
                                             (char*)event.data.scalar.tag, parent_node);
                    _append_node(parent_node, anode);
                    _process_event(parser, event.type, anode);
                }  else if(event.type == YAML_STREAM_END_EVENT) {
                    done = 1;
                } else {
                    //printf("Error: unexpected event %d\n", event.type);
                }
                break;
            case YAML_DOCUMENT_START_EVENT:
                if(event.type == YAML_SCALAR_EVENT) {
                    strcpy(parent_node->node_type, "SCALAR");
                    parent_node->node_value.str_value = strdup((char*)event.data.scalar.value);
                } else if(event.type == YAML_SEQUENCE_START_EVENT) {
                    strcpy(parent_node->node_type, "SEQ");
                    _process_event(parser, event.type, parent_node);
                } else if(event.type == YAML_MAPPING_START_EVENT) {
                    strcpy(parent_node->node_type, "MAP");
                    _process_event(parser, event.type, parent_node);
                }  else if(event.type == YAML_DOCUMENT_END_EVENT) {
                    done = 1;
                } else {
                    // printf("Error: unexpected event %d\n", event.type);
                }
            break;
            case YAML_SEQUENCE_START_EVENT:
                if(event.type == YAML_SCALAR_EVENT) {
                    anode = _create_new_node("", "SCALAR",
                                             (char*)event.data.scalar.tag, parent_node);
                    anode->node_value.str_value = strdup((char*) event.data.scalar.value);
                    _append_node(parent_node, anode);
                } else if(event.type == YAML_SEQUENCE_START_EVENT) {
                    anode = _create_new_node("", "SEQ",
                                             (char*)event.data.scalar.tag, parent_node);
                    _append_node(parent_node, anode);
                    _process_event(parser, event.type, anode);
                } else if(event.type == YAML_MAPPING_START_EVENT) {
                    anode = _create_new_node("", "MAP",
                                             (char*)event.data.scalar.tag, parent_node);
                    _append_node(parent_node, anode);
                    _process_event(parser, event.type, anode);
                }  else if(event.type == YAML_SEQUENCE_END_EVENT) {
                    done = 1;
                } else {
                    //printf("Error: unexpected event %d\n", event.type);
                }
            break;
            case YAML_MAPPING_START_EVENT:
                if(event.type == YAML_SCALAR_EVENT) {
                    if(attribute) {
                        anode = _create_new_node(attribute, "SCALAR",
                                                 (char*)event.data.scalar.tag, parent_node);
                        anode->node_value.str_value = strdup((char*)event.data.scalar.value);
                        _append_node(parent_node, anode);
                        free(attribute);
                        attribute = NULL;
                    } else {
                        attribute = strdup((char*)event.data.scalar.value);
                    }
                } else if(event.type == YAML_SEQUENCE_START_EVENT) {
                    assert(attribute);
                    anode = _create_new_node(attribute, "SEQ",
                                             (char*)event.data.scalar.tag, parent_node);
                    _append_node(parent_node, anode);
                    free(attribute);
                    attribute = NULL;
                    _process_event(parser, event.type, anode);
                } else if(event.type == YAML_MAPPING_START_EVENT) {
                    assert(attribute);
                    anode = _create_new_node(attribute, "MAP",
                                             (char*)event.data.scalar.tag, parent_node);
                    _append_node(parent_node, anode);
                    free(attribute);
                    attribute = NULL;
                    _process_event(parser, event.type, anode);
                } else if(event.type == YAML_MAPPING_END_EVENT) {
                    done = 1;
                } else {
                    //printf("Error: unexpected event %d\n", event.type);
                }
            break;
            default:
            break;
                //printf("Unexpected event %d\n", event.type);
        }
        /* The application is responsible for destroying the event object. */
        yaml_event_delete(&event);
    }
}

config_node*
parse_file(const char* path)
{
    yaml_parser_t parser;
    FILE *infile;
    config_node* stream_node = _create_new_node("all", "STREAM", "", NULL);

    /* Create the Parser object. */
    yaml_parser_initialize(&parser);
    /* Set a file input. */
    infile = fopen(path, "rb");
    yaml_parser_set_input_file(&parser, infile);
    /* Read the event sequence. */
    _process_event(&parser, YAML_NO_EVENT, stream_node);
    yaml_parser_delete(&parser);
    fclose(infile);

    return(stream_node);

}


/*
 * yaml_parser.h
 *
 */

#ifndef YAML_PARSER_H_
#define YAML_PARSER_H_

#include <yaml.h>

typedef struct _node* p_node;

typedef struct _sequence {
	p_node start;
	p_node end;
} node_sequence;

typedef struct _node {
	char node_name[1024];
	char node_type[16];
	char node_tag[256];
	union {
		char* str_value;
		node_sequence seq_value;
	} node_value;
	p_node parent;
	p_node next;
} config_node;

config_node* parse_file(const char* path);

void walk (config_node* root);

#endif /* YAML_PARSER_H_ */


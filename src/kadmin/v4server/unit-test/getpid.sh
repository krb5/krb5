#!/bin/sh

# tcl sucks big fat hairy rocks

$PS_ALL | awk "/$1/"' && !/awk/ && !/getpid/ && !/expect/ && !/kadmind4/ { print $2 }'

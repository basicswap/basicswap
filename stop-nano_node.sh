#!/bin/sh

kill $(cat "$HOME/.basicswap/nano/nano_node.pid")
rm "$HOME/.basicswap/nano/nano_node.pid"

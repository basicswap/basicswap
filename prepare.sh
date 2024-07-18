#!/usr/bin/env bash

# TODO deduplicate with python.sh
# nix-build . -A nur.repos.milahu.basicswap.bindir
export DEFAULT_TEST_BINDIR='/nix/store/3pnazf7d26wlk2w90mymqjpywck627p0-basicswap-bindir'

basicswap_dir="$HOME/.basicswap"

particld_pid_file="$basicswap_dir/particl/particl.pid"

nano_node_pid_file="$basicswap_dir/nano/nano_node.pid"



# start particl daemon

if [ -e "$particld_pid_file" ]; then
  :
  # TODO check if particl daemon is running
  # otherwise delete $particld_pid_file
fi

if ! [ -e "$particld_pid_file" ]; then
  echo "starting particl daemon ..."
  args=(
    "$DEFAULT_TEST_BINDIR/particl/particld"
    -daemon
    -daemonwait
    -datadir="$basicswap_dir/particl"
    -pid="$particld_pid_file"
    -rpccookiefile="$basicswap_dir/particl/.cookie"
  )
  printf ">"; printf " %q" "${args[@]}"; printf "\n"
  "${args[@]}"
  particld_pid=$(< "$particld_pid_file")
  echo "starting particl daemon done. pid $particld_pid"
  echo "to stop the particl daemon: kill \$(cat ${particld_pid_file@Q})"
fi



# start nano_node daemon

if [ -e "$nano_node_pid_file" ]; then
  nano_node_pid=$(< "$nano_node_pid_file")
  if [ -z "$nano_node_pid" ]; then
    echo "deleting empty pidfile $nano_node_pid_file"
    rm "$nano_node_pid_file"
  fi
  # TODO check if nano_node daemon is running
  # otherwise delete $nano_node_pid_file
fi

if ! [ -e "$nano_node_pid_file" ]; then
  echo "starting nano_node daemon ..."
  # see also bin/basicswap_prepare.py
  args=(
    "$DEFAULT_TEST_BINDIR/nano/nano_node"
    --daemon
    --data_path "$basicswap_dir/nano"
    --config rpc.enable=true
    --rpcconfig enable_control=true
    --config logging.log_rpc=false
  )
  logfile="$basicswap_dir/nano/log/log_$(date --utc +%F_%H-%M-%S_%N).log"
  printf ">"; printf " %q" "${args[@]}"; printf " &> %s\n" "$logfile"
  "${args[@]}" &> "$logfile" &
  nano_node_pid=$!
  echo $nano_node_pid > "$nano_node_pid_file"
  echo "starting nano_node daemon done. pid $nano_node_pid"
  echo "to stop the nano_node daemon: kill \$(cat ${nano_node_pid_file@Q}); rm ${nano_node_pid_file@Q}"

fi



# move old config files
# otherwise bin/basicswap_prepare.py fails

move_paths=(
  "$basicswap_dir/basicswap.json"
  "$basicswap_dir/particl/particl.conf"
  "$basicswap_dir/monero/monerod.conf"
  "$basicswap_dir/monero/monero_wallet.conf"
  "$basicswap_dir/nano/nano.conf"
)

t=$(date --utc +%Y%m%dT%H%M%SZ)

for path in "${move_paths[@]}"; do
  mv -v "$path" "$path.bak.$t"
done



# run bin/basicswap_prepare.py

withcoin=monero,nano
withcoin=nano

# TODO run particl manually: "manage_daemon": false

withoutcoin=
# no. particl is required
#withoutcoin=particl # debug: start faster

dont_manage_daemons=particl,nano

args=(
  ./python.sh
  bin/basicswap_prepare.py
  --withcoin=$withcoin
  --withoutcoin=$withoutcoin
  --dont_manage_daemons=$dont_manage_daemons
)
printf ">"; printf " %q" "${args[@]}"; printf "\n"
"${args[@]}"

#!/bin/zsh

# get script dir
SCRIPT_DIR="${0:A:h}"

source "$SCRIPT_DIR/../scripts/setup_env.sh"

SYNC_WITH_PIONEER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sync-with-pioneer)
      if [[ -n "$2" && "$2" != --* ]]; then
        SYNC_WITH_PIONEER="$2"
        shift 2
      else
        echo "Error: --sync-with-pioneer requires a node argument"
        exit 1
      fi
      ;;
    --help)
      echo "Usage: delayed_init_enclave.sh [--sync-with-pioneer <node>]"
      exit 0
      ;;      
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

get_latest_block_height() {
    local pioneer_node="$1"
    local block_height=0
    
    if [[ -n "$pioneer_node" ]] ; then
        block_height=$(qadenad_alias --node "http://$pioneer_node:26657" status | jq -r ".sync_info.latest_block_height")
        if [[ $? != 0 ]] ; then
            echo "[delayed_init_enclave - E] Could not get latest block height from $pioneer_node" >&2
            return 1
        fi
        echo "$block_height"
        return 0
    fi
    return 1
}

# try 10 times to make sure qadenad is running
MAX_COUNTER=10
COUNTER=1
while true ; do
    qadenad_alias status > /dev/null 2> /dev/null
    RET=$?
    if [[ $RET != 0 ]] ; then
        echo "[delayed_init_enclave - E] Could not detect that qadenad is running waiting...$COUNTER / $MAX_COUNTER"
    else
        echo "[delayed_init_enclave - I] qadenad is running"
        break
    fi
    COUNTER=$((COUNTER+1))
    if [[ $COUNTER -ge $MAX_COUNTER ]] ; then
        echo "[delayed_init_enclave - E] Could not detect that qadenad is running $COUNTER / $MAX_COUNTER"
        exit 1
    fi
    sleep 1
done

if [[ $SYNC_WITH_PIONEER = "" ]] ; then
    # detect if we're in catching up mode
    CATCHING_UP=$(qadenad_alias status | jq -r '.sync_info.catching_up')
    if [[ $CATCHING_UP == "true" ]] ; then
        echo "[delayed_init_enclave - I] qadenad is still catching up, but SYNC_WITH_PIONEER is not set"
        # get it from config.toml
        SYNC_WITH_PIONEER=$(dasel -f $QADENAHOME/config/config.toml '.p2p.persistent_peers' | tr -d "'" | tr -d ' ')
        if [[ $SYNC_WITH_PIONEER != "" ]] ; then
            SYNC_WITH_PIONEER=${SYNC_WITH_PIONEER%%,*}
            if [[ $SYNC_WITH_PIONEER == *"@"* ]] ; then
                SYNC_WITH_PIONEER=${SYNC_WITH_PIONEER##*@}
            fi
            SYNC_WITH_PIONEER=${SYNC_WITH_PIONEER#tcp://}
            SYNC_WITH_PIONEER=${SYNC_WITH_PIONEER%%:*}
        else
            echo "[delayed_init_enclave - E] SYNC_WITH_PIONEER is not set and config.toml p2p.persistent_peers is empty"
            $qadenascripts/stop_qadena.sh --all > /dev/null 2>&1
            exit 1
        fi
    fi
fi

LATEST_BLOCK_HEIGHT=0
if [[ $SYNC_WITH_PIONEER != "" ]] ; then
    LATEST_BLOCK_HEIGHT=$(get_latest_block_height "$SYNC_WITH_PIONEER")
    if [[ $? != 0 ]] ; then
        echo "[delayed_init_enclave - E] Could not get latest block height from $SYNC_WITH_PIONEER"
        exit 1
    fi
fi

# check if qadenad is running and caught up

TMP_FILE_NAME=$(mktemp)
echo "[delayed_init_enclave - I] Will store qadenad status in $TMP_FILE_NAME"
COUNTER=1
MAX_COUNTER=90
LAST_BLOCK_HEIGHT=0

while true ; do
    qadenad_alias status > $TMP_FILE_NAME 2> /dev/null
    RET=$?
    if [[ $RET != 0 ]] ; then
        echo "[delayed_init_enclave - E] qadenad must have died!"
        exit 1
    fi
    if [ "$(jq -r '.sync_info.catching_up' "$TMP_FILE_NAME")" = "false" ]; then
        CURRENT_BLOCK_HEIGHT=$(jq -r '.sync_info.latest_block_height' "$TMP_FILE_NAME")
        echo "[delayed_init_enclave - I] qadenad block height: $CURRENT_BLOCK_HEIGHT"
        #if CURRENT_BLOCK_HEIGHT is less than 4, wait
        if [[ $CURRENT_BLOCK_HEIGHT -lt 4 ]] ; then
            echo "[delayed_init_enclave - I] qadenad is caught up, but waiting for block height to be at least 4..."
            sleep 1
            continue
        fi
        echo "[delayed_init_enclave - I] qadenad is caught up and running!"
        break
    else
        if [[ $SYNC_WITH_PIONEER != "" ]] ; then
            CURRENT_BLOCK_HEIGHT=$(jq -r '.sync_info.latest_block_height' "$TMP_FILE_NAME")
            echo "[delayed_init_enclave - I] qadenad is not yet caught up, waiting...$CURRENT_BLOCK_HEIGHT / $LATEST_BLOCK_HEIGHT"
            
            # Check progress every 10 seconds
            if [[ $((COUNTER % 10)) -eq 0 ]]; then
                if [[ $COUNTER -gt 10 && $CURRENT_BLOCK_HEIGHT -le $LAST_BLOCK_HEIGHT ]]; then
                    echo "[delayed_init_enclave - E] No progress in block height after 10 seconds"
                    echo "[delayed_init_enclave - E] Previous height: $LAST_BLOCK_HEIGHT, Current height: $CURRENT_BLOCK_HEIGHT"
                    echo "[delayed_init_enclave - E] Stopping qadenad due to sync stall"
                    $qadenascripts/stop_qadena.sh --chain --enclave
                    exit 1
                else
                    echo "[delayed_init_enclave - I] qadenad is still catching up, making progress..."
                fi
                LAST_BLOCK_HEIGHT=$CURRENT_BLOCK_HEIGHT
            fi
            
            # Update latest block height from pioneer every 100 iterations
            if [[ $((COUNTER % 100)) -eq 0 ]]; then
                LATEST_BLOCK_HEIGHT=$(get_latest_block_height "$SYNC_WITH_PIONEER")
                if [[ $? != 0 ]] ; then
                    exit 1
                fi
            fi
            COUNTER=$((COUNTER+1))
        else
            echo "[delayed_init_enclave - I] qadenad is not yet caught up, waiting...$COUNTER / $MAX_COUNTER"
            COUNTER=$((COUNTER+1))
            if [[ $COUNTER -ge $MAX_COUNTER ]] ; then
                echo "[delayed_init_enclave - E] Could not detect that qadenad is caught up $COUNTER / $MAX_COUNTER"
                echo "[delayed_init_enclave - E] Will stop it"
                $qadenascripts/stop_qadena.sh --chain --enclave
                exit 1
            fi
        fi
        sleep 1
    fi
done

rm -f "$TMP_FILE_NAME"

$qadenascripts/init_enclave.sh

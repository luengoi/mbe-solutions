#!/bin/bash

function usage {
    echo "usage: $1 [options] [log] [up | dwn] <user> <host> [<source>]"
    echo
    echo "Commands:"
    echo "log       Log in as <user>, if up or dwn are also specified, the log in"
    echo "          process will take place after the file transfering"
    echo "up        Copy <source> file into /tmp/<source> on the warzone server"
    echo "dwn       Copy <source> from the warzone server into the current working directory."
    echo
    echo "Options:"
    echo "-f, --file FILE    Use this file as the password file"
    echo "-h, --help         Shows this information and exits"
    exit 0
}


function getpassword {

    local password=$(cat $1 | grep $2 | head -n1 | cut -d" " -f3)

    if [ "$password" = "" ]; then
        echo "[!] Error: No password found for $2. Make sure you have stored it correctly in $1."
        exit 1
    fi

    PASS=$password
}

function log_in {
    local user="$1"
    local host="$2"
    local pass="$3"

    echo "========================"
    echo "[+] Logging in as $user"
    echo "========================"

    sshpass -p "$pass" ssh $user@$host
}

function upload {
    local user="$1"
    local host="$2"
    local pass="$3"
    local locl="$4"
    local remt=""
    local login="$5"

    # Check whether the local file exists
    if [ ! -f "$locl" ]; then
        echo "[!] Error: $locl file does not exist."
        exit 1
    fi

    remt=/tmp${locl#$(dirname "$locl")}

    sshpass -p "$pass" scp "$locl" "$user"@"$host":"$remt" > /dev/null
    # Check if the command succeded
    if [ $? -ne 0 ]; then
        echo "[!] Error: scp command failed."
        exit 1
    fi

    echo "[+] Copied $locl to $remt"

    if [ "$login" = "Y" ];then
        log_in $user $host $pass
    fi
}

function dwnload {
    local user="$1"
    local host="$2"
    local pass="$3"
    local locl=""
    local remt="$4"
    local login="$5"

    locl=${remt#$(dirname "$remt")/}

    sshpass -p "$pass" scp "$user"@"$host":"$remt" "$locl" > /dev/null
    # Check if the command succeded
    if [ $? -ne 0 ]; then
        echo "[!] Error: scp command failed."
        exit 1
    fi

    echo "[+] Copied $remt to $locl"

    if [ "$login" = "Y" ]; then
        log_in $user $host $pass
    fi
}

# Check program arguments

if [ $# -lt 2 ]; then
    usage $0
fi

PASSFILE=""
LOGIN="N"
UP="N"
DWN="N"
POSITIONAL=()   # Positional arguments (user, host, [src/dst])
while [ $# -gt 0 ]
do
    op="$1"

    case $op in
        -f|--file)
            PASSFILE="$2"
            shift
            shift
            ;;
        log)
            LOGIN="Y"
            shift
            ;;
        up)
            if [ $DWN = "Y" ]; then
                echo "[!] Error: You can't upload or download a file."
                exit 1
            fi
            UP="Y"
            shift
            ;;
        dwn)
            if [ $UP = "Y" ]; then
                echo "[!] Error: You can't upload or download a file."
                exit 1
            fi
            DWN="Y"
            shift
            ;;
        -h|--help)
            usage $0
            ;;
        -*)
            echo "[!] Error: Unknown option $op."
            exit 1
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL[@]}"
USER="$1"
HOST="$2"
SRC="$3"

if [ "$UP" = "Y" ] || [ "$DWN" = "Y" ]; then
    if [ "$SRC" = "" ]; then
        echo "[!] Error: You must specify a source in order to upload/download."
        exit 1
    fi
fi

if [ "$USER" = "" ] || [ "$HOST" = "" ]; then
    echo "[!] Error: You must specify a username and a host where the VM is running."
    exit 1
fi

if [ "$PASSFILE" = "" ]; then
    # Try to get the password file from the environmental variable
    if [ "$WARZONE_PASSWORD_FILE" = "" ]; then
        echo "[!] Error: A password file is needed, either passed with -f or stored in WARZONE_PASSWORD_FILE environment variable."
        exit 1
    fi
    PASSFILE="$WARZONE_PASSWORD_FILE"
fi

if [ ! -f "$PASSFILE" ]; then
    echo "[!] Error: $PASSFILE does not exist."
    exit 1
fi

PASS=""
getpassword $PASSFILE $USER

if [ "$UP" = "Y" ]; then
    upload $USER $HOST $PASS $SRC $LOGIN
elif [ "$DWN" = "Y" ]; then
    dwnload $USER $HOST $PASS $SRC $LOGIN
else
    log_in $USER $HOST $PASS
fi


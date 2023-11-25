#!/bin/sh
# check root
if [ ! "$(id -u)" -eq 0 ]; then
    echo "E: you must be root."
    exit 1
fi

# check args
print_help(){
    echo "Usage: {start|stop} {path to wg-quick config file}"
    exit 1
}

if [ -z "${1}" ] || [ -z "${2}" ]; then
    print_help
fi

config_path="${2}"

if [ ! -f "${config_path}" ]; then
    echo "E: specified wg-quick config file does not exist."
    exit 1
fi

# parse
actual_endpoint="$(awk '/actual_endpoint/{print $3}' "${config_path}")"
wgquick_path="$(awk '/wgquick_path/{print $3}' "${config_path}")"
udp2raw_path="$(awk '/udp2raw_path/{print $3}' "${config_path}")"
udp2raw_port="$(awk '/udp2raw_port/{print $3}' "${config_path}")"
udp2raw_pass="$(awk '/udp2raw_pass/{print $3}' "${config_path}")"

if [ -z "${actual_endpoint}" ]; then
    echo "E: actual endpoint was not specified."
    exit 1
fi

if [ -z "${wgquick_path}" ]; then
    echo "E: wg-quick path was not specified."
    exit 1
fi

if [ -z "${udp2raw_path}" ]; then
    echo "E: udp2raw path was not specified."
    exit 1
fi

if [ -z "${udp2raw_port}" ]; then
    echo "E: udp2raw port was not specified."
    exit 1
fi

if [ -z "${udp2raw_pass}" ]; then
    echo "E: upd2raw password was not specified."
    exit 1
fi

for i in "${wgquick_path}" "${udp2raw_path}"; do
    if [ ! -f "${i}" ]; then
       echo "E: ${i} does not exist."
       exit 1
    fi
done

# set route vars
default_route_line="$(ip route list match 0 table all scope global)"
wan_gateway="$(echo "${default_route_line}" | awk '{print $3}')"
wan_iface="$(echo "${default_route_line}" | awk '{print $5}')"

# action
preup(){
    echo "I: adding main table ruke."
    ip rule add from all lookup main pref 1 \
        >/dev/null 2>&1 || true

    echo "I: adding static route to ${actual_endpoint}."
    ip route add "${actual_endpoint}" via "${wan_gateway}" dev "${wan_iface}" \
        >/dev/null 2>&1 || true

    echo "I: starting udp2raw."
    "${udp2raw_path}" -c \
        -l 127.0.0.1:50001 \
        -r "${actual_endpoint}":"${udp2raw_port}" \
        -k "${udp2raw_pass}" -a \
        >>udp2raw.log 2>&1 &

    echo "I: calling wg-quick."
    "${wgquick_path}" up "${config_path}" \
        >>wg_quick.log 2>&1 || true
}

postdown(){
    echo "I: deleting main table ruke."
    ip rule del from all lookup main pref 1 \
        >/dev/null 2>&1 || true

    echo "I: deleting static route to ${actual_endpoint}."
    ip route del "${actual_endpoint}" via "${wan_gateway}" dev "${wan_iface}" \
        >/dev/null 2>&1 || true

    echo "I: deleting wireguard interface"
    "${wgquick_path}" down "${config_path}" \
        >>wg_quick.log 2>&1 || true

    echo "I: killing udp2raw."
    pkill -15 udp2raw \
        >/dev/null 2>&1 || true
}

case "${1}" in
    start)
        preup
    ;;
    stop)
        postdown
    ;;
    *)
        print_help
esac

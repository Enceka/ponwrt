#!/bin/sh
set -eu

peer=${1:-./gre-peer}
test -x "$peer" || { echo "missing executable: $peer" >&2; exit 1; }
left=gre-l-$$
right=gre-r-$$
created_left=0
created_right=0
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$created_right" = 1 ]; then ip netns del "$right" || status=1; fi
	if [ "$created_left" = 1 ]; then ip netns del "$left" || status=1; fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

ip netns add "$left"
created_left=1
ip netns add "$right"
created_right=1
ip -n "$left" link add wire type veth peer name wire netns "$right"

outer_l=192.0.2.1
outer_r=192.0.2.2
inner_l=198.51.100.1
first=198.51.100.2
second=198.51.100.3
setup_end() {
	ip -n "$1" link set lo up
	ip -n "$1" addr add "$2/30" dev wire
	ip -n "$1" link set wire up
	ip -n "$1" tunnel add gre1 mode gre local "$2" remote "$3" ttl 63
	ip -n "$1" link set gre1 up
}
setup_end "$left" "$outer_l" "$outer_r"
setup_end "$right" "$outer_r" "$outer_l"
ip -n "$left" addr add "$inner_l/32" dev lo
ip -n "$right" route add "$inner_l/32" dev gre1
for addr in "$first" "$second"; do
	ip -n "$right" addr add "$addr/32" dev lo
	ip -n "$left" route add "$addr/32" dev gre1
done

forward() {
	"$peer" "$1" "/var/run/netns/$left" "/var/run/netns/$right" "$inner_l" "$2" "$outer_l" "$outer_r"
}
reverse() {
	"$peer" exchange "/var/run/netns/$right" "/var/run/netns/$left" "$second" "$inner_l" "$outer_r" "$outer_l"
}
forward exchange "$first"
forward exchange "$second"
reverse
ip -n "$left" route del "$first/32" dev gre1
forward noroute "$first"
forward exchange "$second"
reverse
ip -n "$left" route add "$first/32" dev gre1
forward exchange "$first"
echo 'PASS: 6 UDP/wire exchanges, shared tunnel, route withdrawal and restoration'

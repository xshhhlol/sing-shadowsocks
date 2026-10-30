# Compatible server hardening

This fork preserves the Shadowsocks wire format and supported client ciphers.
Server changes apply automatically when a consumer builds with this library.

- Traditional AEAD rejects recent authenticated salt replays and reflected server
  responses. An exact FIFO stores at most 65,536 salts per service, including
  responses, across TCP and UDP. Entries are scoped by master key and transport.
  User refreshes retain history. Capacity eviction and process restarts limit
  protection; this is not permanent replay prevention.
- SS2022 records TCP salts only after the entire authenticated request header is
  valid, rechecks timestamps before registration, retains salts for 61 seconds,
  and clamps UDP cache age to at least 61 seconds to cover timestamp rounding.
  Invalid UDP semantic headers
  do not advance the replay window. Cached multi-user UDP sessions are bound to
  their user key.
- Traditional AEAD multi-user authentication checks the encrypted length before
  allocating a full payload reader. Authentication still scans user keys.
  UDP NAT entries are scoped by user, master key and source address.
- TCP authentication uses a read deadline of 30 seconds, shortened by an earlier
  context deadline. Failed requests drain until that deadline, a read error, or
  peer EOF. At most 4,096 pending handshakes are admitted across all services,
  before parsing any request; overload rejects all new connections equally. Successful requests
  clear the handshake deadline before application routing. Transports without
  read-deadline support retain their previous behavior. SS2022 keeps its required
  single-read initial header check. No website fallback is added.
- Optional TCP downlink shaping splits actual payload into legal records, with
  a finite randomized record budget and no sleeps or dummy application bytes.
  The first response salt/header and payload remain coalesced. Normal, vector,
  buffered and copy paths share the policy. Mixed-size vector ordering, final
  read-with-EOF handling, short writes and concurrent first responses are covered.
- Optional SS2022 UDP padding covers small packets on all target ports. The
  default policy adds 1–256 bytes when there is room within a 1,280-byte outer
  IP packet budget, counting base IP/UDP headers and full SS response overhead.
  Oversized original datagrams are left unpadded. Extra path encapsulation/IP
  options require reserving additional budget. Disabling restores legacy DNS-only
  padding. Traditional AEAD UDP is unchanged.
- Multi-user updates validate parallel argument lengths and expose a synchronized
  `Contains` lookup. Consumers must separately manage already-routed connections
  when revoking users.

`go test -race ./...` covers native client TCP/UDP compatibility, large bidirectional
transfers, authenticated replay, concurrent TCP replay, malformed fixed/variable
headers, response reflection, user refreshes, failure deadlines, UDP replay-window
poisoning, identity isolation, source reuse and key rotation.

Call `WithServerOptions` before passing a context to `NewConnection` or
`NewPacket`. `ServerOptions` provides a handshake timeout (default 30 seconds,
maximum 5 minutes), `TrafficShaping` and `UDPPadding`. Shaping and the extended
UDP padding policy are opt-in; constructor signatures remain compatible.

Real loopback TCP tests cover failure deadlines, reset behavior, half-close,
capacity admission and application reads after authentication. UDP codec tests
cover IPv4/IPv6, domains and MTU boundaries. The legacy NAT adapter's empty-packet
EOF behavior is outside the end-to-end compatibility claim. Packet captures and
traffic-classifier evaluation were not performed.

Random-looking first flights, packet sizes, timing, direction and native UDP
boundaries remain observable. These changes do not provide forward secrecy,
traffic camouflage, or a guarantee against traffic classifiers. Arbitrary new
padding fields require coordinated client changes and are intentionally absent;
UDP padding uses the existing SS2022 field only.

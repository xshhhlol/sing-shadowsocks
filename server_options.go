package shadowsocks

import (
	"context"
	"errors"
	"time"
)

// ServerOptions configures server behavior without changing the wire format.
// Options are copied into the context before accepting connections.
type ServerOptions struct {
	HandshakeTimeout time.Duration
	TrafficShaping   TrafficShapingOptions
	UDPPadding       UDPPaddingOptions
}

// UDPPaddingOptions budgets padding within the whole IP packet, including IP,
// UDP and SS headers via MaxPacketSize.
// Disabling the new policy restores the original DNS-only padding behavior.
type UDPPaddingOptions struct {
	Enabled         bool
	MaxPacketSize   int
	MaxPaddingBytes int
}

type TrafficShapingOptions struct {
	Enabled       bool
	MinRecordSize int
	MaxRecordSize int
	MinRecords    int
	MaxRecords    int
}

type serverOptionsKey struct{}

func WithServerOptions(ctx context.Context, options ServerOptions) (context.Context, error) {
	if options.HandshakeTimeout < 0 || options.HandshakeTimeout > 5*time.Minute {
		return nil, errors.New("shadowsocks handshake timeout must be between 0 and 5 minutes")
	}
	if options.HandshakeTimeout == 0 {
		options.HandshakeTimeout = DefaultHandshakeTimeout
	}
	shaping, err := NormalizeTrafficShaping(options.TrafficShaping)
	if err != nil {
		return nil, err
	}
	options.TrafficShaping = shaping
	padding, err := NormalizeUDPPadding(options.UDPPadding)
	if err != nil {
		return nil, err
	}
	options.UDPPadding = padding
	return context.WithValue(ctx, serverOptionsKey{}, options), nil
}

func NormalizeUDPPadding(options UDPPaddingOptions) (UDPPaddingOptions, error) {
	if !options.Enabled {
		return UDPPaddingOptions{}, nil
	}
	if options.MaxPacketSize == 0 {
		options.MaxPacketSize = 1280
	}
	if options.MaxPaddingBytes == 0 {
		options.MaxPaddingBytes = 256
	}
	if options.MaxPacketSize < 512 || options.MaxPacketSize > 65535 {
		return options, errors.New("shadowsocks UDP IP packet budget must be between 512 and 65535 bytes")
	}
	if options.MaxPaddingBytes < 1 || options.MaxPaddingBytes > 900 {
		return options, errors.New("shadowsocks UDP padding must be between 1 and 900 bytes")
	}
	return options, nil
}

func ServerOptionsFromContext(ctx context.Context) ServerOptions {
	if options, ok := ctx.Value(serverOptionsKey{}).(ServerOptions); ok {
		return options
	}
	return ServerOptions{HandshakeTimeout: DefaultHandshakeTimeout}
}

func NormalizeTrafficShaping(options TrafficShapingOptions) (TrafficShapingOptions, error) {
	if !options.Enabled {
		return TrafficShapingOptions{}, nil
	}
	if options.MinRecordSize == 0 {
		options.MinRecordSize = 512
	}
	if options.MaxRecordSize == 0 {
		options.MaxRecordSize = 2048
	}
	if options.MinRecords == 0 {
		options.MinRecords = 8
	}
	if options.MaxRecords == 0 {
		options.MaxRecords = 16
	}
	if options.MinRecordSize < 64 || options.MaxRecordSize > 16383 || options.MinRecordSize > options.MaxRecordSize {
		return options, errors.New("shadowsocks record sizes must satisfy 64 <= min <= max <= 16383")
	}
	if options.MinRecords < 1 || options.MaxRecords > 64 || options.MinRecords > options.MaxRecords {
		return options, errors.New("shadowsocks record counts must satisfy 1 <= min <= max <= 64")
	}
	return options, nil
}

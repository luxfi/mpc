package messaging

import (
	"time"

	"github.com/avast/retry-go"
	"github.com/nats-io/nats.go"

	"github.com/luxfi/mpc/pkg/logger"
)

type DirectMessaging interface {
	Listen(target string, handler func(data []byte)) (Subscription, error)
	Send(target string, data []byte) error
}

type natsDirectMessaging struct {
	natsConn *nats.Conn
}

func NewNatsDirectMessaging(natsConn *nats.Conn) DirectMessaging {
	return &natsDirectMessaging{
		natsConn: natsConn,
	}
}

func (d *natsDirectMessaging) Send(id string, message []byte) error {
	var retryCount = 0
	err := retry.Do(
		func() error {
			_, err := d.natsConn.Request(id, message, 3*time.Second)
			if err != nil {
				return err
			}
			return nil
		},
		retry.Attempts(3),
		retry.Delay(50*time.Millisecond),
		retry.DelayType(retry.FixedDelay),
		retry.OnRetry(func(n uint, err error) {
			logger.Error("Failed to send direct message message", err, "retryCount", retryCount)
		}),
	)

	return err
}

func (d *natsDirectMessaging) Listen(id string, handler func(data []byte)) (Subscription, error) {
	sub, err := d.natsConn.Subscribe(id, func(m *nats.Msg) {
		handler(m.Data)
		if err := m.Respond([]byte("OK")); err != nil {
			logger.Error("Failed to respond to message", err)
		}
	})
	if err != nil {
		return nil, err
	}

	return &natsSubscription{subscription: sub}, nil
}

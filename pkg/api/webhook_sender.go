package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/hanzoai/orm"

	"github.com/luxfi/mpc/pkg/db"
)

func (s *Server) fireWebhook(ctx context.Context, orgID, event string, data interface{}) {
	webhooks, err := orm.TypedQuery[db.Webhook](s.db.ORM).
		Filter("orgId=", orgID).
		Filter("enabled=", true).
		GetAll(ctx)
	if err != nil {
		return
	}

	payload := map[string]interface{}{
		"event":     event,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	for _, wh := range webhooks {
		// Only fire for webhooks that include this event
		for _, e := range wh.Events {
			if e == event {
				go deliverWebhook(wh.URL, wh.Secret, payload)
				break
			}
		}
	}
}

func deliverWebhook(url, secret string, payload interface{}) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}

	// HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	req.Header.Set("X-Webhook-Timestamp", time.Now().UTC().Format(time.RFC3339))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

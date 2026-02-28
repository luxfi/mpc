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
)

func (s *Server) fireWebhook(ctx context.Context, orgID, event string, data interface{}) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT url, secret FROM webhooks
		 WHERE org_id = $1 AND enabled = true AND $2 = ANY(events)`,
		orgID, event)
	if err != nil {
		return
	}
	defer rows.Close()

	payload := map[string]interface{}{
		"event":     event,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	for rows.Next() {
		var url, secret string
		if err := rows.Scan(&url, &secret); err != nil {
			continue
		}
		go deliverWebhook(url, secret, payload)
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

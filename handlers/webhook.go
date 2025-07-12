package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
)

func (h *Handlers) webhookPost(guid, old_ip, new_ip string) error {
	if h.webhook == "" {
		return nil
	}

	body := map[string]string{
		"guid":   guid,
		"old_ip": old_ip,
		"new_ip": new_ip,
	}
	json_body, err := json.Marshal(body)
	if err != nil {
		return err
	}

	_, err = http.Post(h.webhook, "application/json", bytes.NewBuffer(json_body))
	return err
}

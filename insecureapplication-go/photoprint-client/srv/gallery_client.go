package srv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// photosResponse decodes gallery-idp's GET /photos/me?access_token=...
// response, matching the {"images":[...]} shape resolveGalleryUsername's
// "me" branch produces.
type photosResponse struct {
	Images []galleryImage `json:"images"`
}

// fetchMyPhotos mirrors app.js's GET /selectphotos handler: a GET to
// {tokenHost}/photos/me with the access token passed as a query parameter
// (not a bearer header) -- gallery.json's documented "photos" path. Unlike
// the original node-rest-client call (which ignores its response callback's
// error argument entirely), this adds minimal error handling so a
// gallery-idp outage surfaces as an error page instead of a hang -- a
// robustness fix unrelated to the OAuth threat model.
func (s *Server) fetchMyPhotos(accessToken string) ([]galleryImage, error) {
	v := url.Values{}
	v.Set("access_token", accessToken)
	req, err := http.NewRequest(http.MethodGet, s.Config.TokenHost+"/photos/me?"+v.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gallery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gallery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading gallery response: %w", err)
	}
	var out photosResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decoding gallery response: %w", err)
	}
	return out.Images, nil
}

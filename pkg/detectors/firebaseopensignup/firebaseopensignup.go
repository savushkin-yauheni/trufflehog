package firebaseopensignup

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	client = common.SaneHttpClient()

	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"firebase"}) + `\b(AIzaSy[0-9a-zA-Z-_]{33})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"firebase"}
}

// FromData will find and optionally verify Beebole secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_FirebaseOpenSignup,
			Raw:          []byte(resMatch),
		}

		if verify {
			api_url := fmt.Sprintf("https://www.googleapis.com/identitytoolkit/v3/relyingparty/signupNewUser?key=%s", resMatch)
			payload := strings.NewReader(`{"email": "savik@wearehackerone.com","password": "ngx.zyj@enw!MAK2wza","returnSecureToken":true}`)
			req, err := http.NewRequestWithContext(ctx, "POST", api_url, payload)
			if err != nil {
				continue
			}

			req.Header.Add("Content-Type", "application/json")
			res, err := client.Do(req)
			if err == nil {
				defer res.Body.Close()

				bodyBytes, err := io.ReadAll(res.Body)
				if err != nil {
					continue
				}
				body := string(bodyBytes)

				if strings.Contains(body, "idToken") && strings.Contains(body, "expiresIn") {
					s1.Verified = true
					extraData := map[string]string{
                       "email": "savik@wearehackerone.com","password": "ngx.zyj@enw!MAK2wza",
                       "api_key": resMatch,
                    }
					s1.ExtraData = extraData
				}
			}
		}

		results = append(results, s1)
	}

	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_FirebaseOpenSignup
}

func (s Scanner) Description() string {
	return ""
}

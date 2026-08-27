package modules

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Murmur3_32 calculates standard MurmurHash3 32-bit hash on input bytes with a given seed.
func Murmur3_32(data []byte, seed uint32) int32 {
	h := seed
	length := len(data)
	nblocks := length / 4

	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		k *= 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k *= 0x1b873593

		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}

	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= 0xcc9e2d51
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= 0x1b873593
		h ^= k1
	}

	h ^= uint32(length)
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return int32(h)
}

// CalculateFaviconMMH3 calculates the Shodan-standard Favicon Murmur3 32-bit hash.
func CalculateFaviconMMH3(faviconBytes []byte) int32 {
	if len(faviconBytes) == 0 {
		return 0
	}
	b64 := base64.StdEncoding.EncodeToString(faviconBytes)
	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteString("\n")
	}
	return Murmur3_32([]byte(sb.String()), 0)
}

// FaviconSignatures maps Shodan MMH3 hash integers to known framework/technology names.
var FaviconSignatures = map[int32]string{
	116323821:   "springboot",
	81586312:    "jenkins",
	-1064506548: "jenkins",
	-684126933:  "grafana",
	1379564268:  "grafana",
	1278323681:  "gitlab",
	-1996500306: "gitlab",
	1409930906:  "phpmyadmin",
	-902919139:  "phpmyadmin",
	-144450386:  "wordpress",
	-525287600:  "drupal",
	-1308035673: "tomcat",
	1585721998:  "pfsense",
	-1286018301: "cpanel",
	1150530777:  "webmin",
	-1510255850: "elasticsearch",
	-305179312:  "jira",
	-1205397092: "apache",
}

// DetectFaviconTech discovers favicon link or fetches /favicon.ico and matches against MMH3 signatures.
func DetectFaviconTech(bodyStr, baseURLStr string, client *http.Client) (int32, string) {
	if client == nil || baseURLStr == "" {
		return 0, ""
	}

	faviconURL := ""
	// 1. Search for <link rel="icon"...> or <link rel="shortcut icon"...>
	re := regexp.MustCompile(`(?i)<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']`)
	if m := re.FindStringSubmatch(bodyStr); len(m) > 1 {
		href := m[1]
		if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
			faviconURL = href
		} else if strings.HasPrefix(href, "//") {
			faviconURL = "http:" + href
		} else if strings.HasPrefix(href, "/") {
			if u, err := url.Parse(baseURLStr); err == nil {
				faviconURL = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, href)
			}
		} else {
			faviconURL = strings.TrimRight(baseURLStr, "/") + "/" + href
		}
	}

	// 2. Default fallback: /favicon.ico
	if faviconURL == "" {
		if u, err := url.Parse(baseURLStr); err == nil {
			faviconURL = fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)
		}
	}

	if faviconURL == "" {
		return 0, ""
	}

	req, err := http.NewRequest("GET", faviconURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SpecterRecon/0.8.0")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0, ""
	}
	defer resp.Body.Close()

	// Max 64KB favicon
	favBytes, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil || len(favBytes) < 8 {
		return 0, ""
	}

	hash := CalculateFaviconMMH3(favBytes)
	if tech, found := FaviconSignatures[hash]; found {
		return hash, tech
	}

	return hash, ""
}

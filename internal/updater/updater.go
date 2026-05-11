// Package updater checks for and applies TunnelDeck binary updates from
// GitHub releases. It deliberately uses TWO signals to decide whether an
// update is available:
//
//  1. Release tag vs. the version baked into the current binary. Catches
//     the normal case: we cut v0.2.0 and bump main.version.
//  2. SHA256 of the release's binary asset vs. SHA256 of the local
//     /usr/local/bin/tunneldeck. Catches the "replaced the asset in an
//     existing release without bumping the tag" case — which happens a
//     lot during MVP iteration.
//
// Either signal triggers "update available". Status.Reason records which
// one fired so the UI banner can explain why.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Release is the subset of the GitHub /releases/latest response we parse.
type Release struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Assets      []Asset   `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Status is the result of a Check call.
type Status struct {
	// CurrentVersion is the version string compiled into this binary
	// (main.version — e.g. "v0.1.0"). Informational.
	CurrentVersion string
	// CurrentSHA is the sha256 of the currently-running binary on disk.
	CurrentSHA string

	// RemoteTag is the tag of the latest release.
	RemoteTag string
	// RemoteSHA is the sha256 of the binary asset in the latest release,
	// pulled from the release's SHA256SUMS.txt. Empty string if we
	// couldn't fetch it.
	RemoteSHA string
	// RemotePublishedAt is when the release was (last) published.
	RemotePublishedAt time.Time

	// UpdateAvailable is the final answer.
	UpdateAvailable bool
	// Reason explains UpdateAvailable. One of:
	//   "up-to-date"
	//   "new tag: <tag>"
	//   "binary changed (same tag): <tag>"
	//   "check failed: <err>"
	Reason string

	// DownloadURL and AssetName point at the binary we'd download for this
	// host's GOOS/GOARCH in an Apply() call. Empty string if no matching
	// asset was found.
	DownloadURL string
	AssetName   string
}

// Check hits the GitHub releases API and compares with the running binary.
// repo is "owner/name". binaryPath is the path to the running binary (we
// sha256 it). currentVersion is what main.version was set to at build time.
func Check(ctx context.Context, repo, binaryPath, currentVersion string) Status {
	s := Status{CurrentVersion: currentVersion}

	if sha, err := sha256File(binaryPath); err == nil {
		s.CurrentSHA = sha
	}

	rel, err := fetchLatestRelease(ctx, repo)
	if err != nil {
		s.Reason = "check failed: " + err.Error()
		return s
	}
	s.RemoteTag = rel.TagName
	s.RemotePublishedAt = rel.PublishedAt

	asset := pickAssetForHost(rel.Assets)
	if asset != nil {
		s.DownloadURL = asset.BrowserDownloadURL
		s.AssetName = asset.Name
	}

	if sha, err := fetchSHA256SumFor(ctx, rel.Assets, s.AssetName); err == nil {
		s.RemoteSHA = sha
	}

	switch {
	case s.CurrentVersion != "" && s.RemoteTag != "" && s.CurrentVersion != s.RemoteTag:
		s.UpdateAvailable = true
		s.Reason = "new tag: " + s.RemoteTag
	case s.RemoteSHA != "" && s.CurrentSHA != "" && s.RemoteSHA != s.CurrentSHA:
		s.UpdateAvailable = true
		s.Reason = "binary changed (same tag): " + s.RemoteTag
	default:
		s.UpdateAvailable = false
		s.Reason = "up-to-date"
	}
	return s
}

// ApplyResult is returned by Apply for logging / UI.
type ApplyResult struct {
	DownloadedPath string
	BackupPath     string
	NewBinaryPath  string
	NewSHA         string
}

// Apply downloads the binary for this host, verifies its sha256 against the
// release's SHA256SUMS.txt, then atomically swaps /usr/local/bin/tunneldeck
// (or whatever binaryPath points at). The caller is responsible for
// restarting the systemd service afterward.
//
// Linux file-replace semantics let us overwrite the currently-running
// binary safely: the kernel holds the old inode open until the running
// process exits, so a concurrent `systemctl restart` will pick up the new
// file on the next fork.
func Apply(ctx context.Context, repo, binaryPath string) (ApplyResult, error) {
	rel, err := fetchLatestRelease(ctx, repo)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("fetch release: %w", err)
	}
	asset := pickAssetForHost(rel.Assets)
	if asset == nil {
		return ApplyResult{}, fmt.Errorf("no binary asset for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, rel.TagName)
	}

	expectedSHA, err := fetchSHA256SumFor(ctx, rel.Assets, asset.Name)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("fetch SHA256SUMS.txt: %w", err)
	}
	if expectedSHA == "" {
		return ApplyResult{}, errors.New("SHA256SUMS.txt did not list the binary; refusing to apply")
	}

	// Download next to the target so atomic rename is on the same filesystem.
	dir := filepath.Dir(binaryPath)
	newPath := filepath.Join(dir, filepath.Base(binaryPath)+".new")
	if err := downloadTo(ctx, asset.BrowserDownloadURL, newPath); err != nil {
		return ApplyResult{}, fmt.Errorf("download: %w", err)
	}
	gotSHA, err := sha256File(newPath)
	if err != nil {
		_ = os.Remove(newPath)
		return ApplyResult{}, fmt.Errorf("hash downloaded file: %w", err)
	}
	if gotSHA != expectedSHA {
		_ = os.Remove(newPath)
		return ApplyResult{}, fmt.Errorf("sha256 mismatch: got %s, want %s", gotSHA, expectedSHA)
	}
	if err := os.Chmod(newPath, 0o755); err != nil {
		_ = os.Remove(newPath)
		return ApplyResult{}, fmt.Errorf("chmod: %w", err)
	}

	backupPath := binaryPath + ".old"
	// Best-effort: rename current to .old so we can roll back manually.
	// If the current binary doesn't exist (first install via Apply? unlikely)
	// we don't care.
	_ = os.Remove(backupPath) // remove stale .old if any
	_ = os.Rename(binaryPath, backupPath)

	if err := os.Rename(newPath, binaryPath); err != nil {
		// Try to restore the .old. If that also fails, the user's binary
		// is gone — we surface both errors so they can recover manually.
		restoreErr := os.Rename(backupPath, binaryPath)
		if restoreErr != nil {
			return ApplyResult{}, fmt.Errorf("swap failed (%w) AND rollback also failed (%v) — binary at %s is missing", err, restoreErr, binaryPath)
		}
		return ApplyResult{}, fmt.Errorf("swap failed, rolled back: %w", err)
	}

	return ApplyResult{
		DownloadedPath: newPath,
		BackupPath:     backupPath,
		NewBinaryPath:  binaryPath,
		NewSHA:         gotSHA,
	}, nil
}

// --- internals -----------------------------------------------------------

func fetchLatestRelease(ctx context.Context, repo string) (Release, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "tunneldeck-updater")

	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Release{}, fmt.Errorf("github api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return Release{}, err
	}
	return rel, nil
}

// pickAssetForHost picks "tunneldeck-linux-amd64" / "-arm64" etc.
// Returns nil if no matching asset was published.
func pickAssetForHost(assets []Asset) *Asset {
	want := fmt.Sprintf("tunneldeck-%s-%s", runtime.GOOS, runtime.GOARCH)
	for i := range assets {
		if assets[i].Name == want {
			return &assets[i]
		}
	}
	return nil
}

// fetchSHA256SumFor pulls SHA256SUMS.txt from the release and returns the
// expected sha256 for the given asset name. Returns "" without error if
// the file exists but doesn't list the asset.
func fetchSHA256SumFor(ctx context.Context, assets []Asset, name string) (string, error) {
	var sumAsset *Asset
	for i := range assets {
		if assets[i].Name == "SHA256SUMS.txt" {
			sumAsset = &assets[i]
			break
		}
	}
	if sumAsset == nil {
		return "", errors.New("SHA256SUMS.txt not attached to release")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumAsset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "tunneldeck-updater")
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("SHA256SUMS.txt HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", err
	}
	return parseSHA256SumsFor(string(body), name), nil
}

// parseSHA256SumsFor reads `sha256sum` output format — "<hex>  name" or
// "<hex> *name" — and returns the hex for the matching file, else "".
func parseSHA256SumsFor(body, want string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == want {
			return fields[0]
		}
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func downloadTo(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "tunneldeck-updater")
	resp, err := newHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 60 * time.Second}
}
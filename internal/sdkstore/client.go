// Package sdkstore resolves and downloads SDK archives from the Canonical SDK Store.
package sdkstore

import (
	"archive/tar"
	"context"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
)

const (
	DefaultServerURL = "https://api.pkg.store"
	DefaultCacheDir  = "/tmp/latra/cache"
	maxArchiveBytes  = int64(256 << 20)
)

// Config configures the Store client. Its zero value uses production defaults.
type Config struct {
	BaseURL      string
	CacheDir     string
	HTTPClient   *http.Client
	Architecture string
}

// Client resolves Store revisions and materializes verified SDK archives.
type Client struct {
	base         *url.URL
	cacheDir     string
	http         *http.Client
	architecture string
}

// NewClient constructs a Store client.
func NewClient(config Config) (*Client, error) {
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = os.Getenv("SDK_STORE_URL")
	}
	if baseURL == "" {
		baseURL = DefaultServerURL
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid SDK Store URL %q", baseURL)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return nil, fmt.Errorf("unsupported SDK Store URL scheme %q", base.Scheme)
	}
	cacheDir := config.CacheDir
	if cacheDir == "" {
		cacheDir = DefaultCacheDir
	}
	if !filepath.IsAbs(cacheDir) {
		return nil, fmt.Errorf("SDK cache path must be absolute: %q", cacheDir)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 2 * time.Minute}
	}
	architecture := config.Architecture
	if architecture == "" {
		architecture, err = dpkgArchitecture(runtime.GOARCH)
		if err != nil {
			return nil, err
		}
	}
	return &Client{base: base, cacheDir: cacheDir, http: httpClient, architecture: architecture}, nil
}

type resolveRequest struct {
	Packages []resolvePackage `json:"packages"`
}

type resolvePackage struct {
	InstanceKey string   `json:"instance-key"`
	Namespace   string   `json:"namespace"`
	Name        string   `json:"name"`
	Channel     string   `json:"channel"`
	Platform    platform `json:"platform"`
}

type platform struct {
	Name         string `json:"name"`
	Channel      string `json:"channel"`
	Architecture string `json:"architecture"`
}

type resolveResponse struct {
	PackageResults []packageResult `json:"package-results"`
	Errors         []apiError      `json:"error-list"`
}

type packageResult struct {
	InstanceKey string    `json:"instance-key"`
	Status      string    `json:"status"`
	Error       *apiError `json:"error,omitempty"`
	Name        string    `json:"name"`
	ID          string    `json:"id"`
	Result      struct {
		Channel struct {
			Effective string `json:"effective-channel"`
		} `json:"channel"`
		Revision struct {
			Revision int `json:"revision"`
			Download struct {
				URL    string `json:"url"`
				Size   int64  `json:"size"`
				Digest string `json:"sha3-384"`
			} `json:"download"`
		} `json:"revision"`
	} `json:"result"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type resolvedArchive struct {
	Name, PackageID, Channel, Digest string
	Revision                         int
	Size                             int64
}

// Resolve implements source.StoreResolver.
func (c *Client) Resolve(ctx context.Context, request source.StoreRequest, limits sdk.Limits) (*sdk.SDK, error) {
	resolved, err := c.resolve(ctx, request)
	if err != nil {
		var resolutionError *source.ResolutionError
		if errors.As(err, &resolutionError) {
			return nil, err
		}
		return nil, resolutionFailure(sdk.StateNotResolved, "store-resolve-failed", "resolve", err)
	}
	root, err := c.materialize(ctx, resolved, limits)
	if err != nil {
		var resolutionError *source.ResolutionError
		if errors.As(err, &resolutionError) {
			return nil, err
		}
		return nil, resolutionFailure(sdk.StateDownloadFailed, "store-cache-failed", "cache", err)
	}
	result, err := sdk.Read(root, request.Name, limits)
	if err != nil {
		return nil, resolutionFailure(sdk.StateInvalidArtifact, "store-artifact-analysis-failed", "analyze", fmt.Errorf("analyze downloaded SDK: %w", err))
	}
	result.Source = sdk.SourceStore
	result.Channel = resolved.Channel
	result.Digest = resolved.Digest
	return result, nil
}

func (c *Client) resolve(ctx context.Context, request source.StoreRequest) (resolvedArchive, error) {
	baseName, baseChannel, ok := strings.Cut(request.Base, "@")
	if !ok || baseName == "" || baseChannel == "" {
		return resolvedArchive{}, fmt.Errorf("invalid Workshop base %q", request.Base)
	}
	channel := request.Channel
	if channel == "" {
		channel = "stable"
	}
	platforms := []platform{
		{Name: baseName, Channel: baseChannel, Architecture: c.architecture},
		{Name: "all", Channel: "all", Architecture: c.architecture},
		{Name: baseName, Channel: baseChannel, Architecture: "all"},
		{Name: "all", Channel: "all", Architecture: "all"},
	}
	packages := make([]resolvePackage, 0, len(platforms))
	for index, candidate := range platforms {
		packages = append(packages, resolvePackage{
			InstanceKey: fmt.Sprintf("latra-%d", index), Namespace: "sdk",
			Name: request.Name, Channel: channel, Platform: candidate,
		})
	}
	var response resolveResponse
	if err := c.doJSON(ctx, http.MethodPost, c.endpoint("v2", "revisions", "resolve"), resolveRequest{Packages: packages}, &response); err != nil {
		return resolvedArchive{}, err
	}
	if len(response.Errors) > 0 {
		return resolvedArchive{}, fmt.Errorf("SDK Store resolve: %s", response.Errors[0].Message)
	}
	var best *packageResult
	var failures []string
	for index := range response.PackageResults {
		candidate := &response.PackageResults[index]
		if candidate.Status == "error" || candidate.Error != nil {
			if candidate.Error != nil {
				failures = append(failures, candidate.Error.Message)
			}
			continue
		}
		if best == nil || candidate.Result.Revision.Revision > best.Result.Revision.Revision {
			best = candidate
		}
	}
	if best == nil {
		message := strings.Join(failures, "; ")
		if message == "" {
			message = "no compatible revision returned"
		}
		return resolvedArchive{}, resolutionFailure(sdk.StateUnsupportedPlatform, "store-sdk-unsupported-platform", "resolve",
			fmt.Errorf("SDK Store did not resolve %q: %s", request.Name, message))
	}
	download := best.Result.Revision.Download
	if best.ID == "" || best.Result.Revision.Revision <= 0 || download.Digest == "" || download.Size <= 0 {
		return resolvedArchive{}, fmt.Errorf("SDK Store returned incomplete revision data for %q", request.Name)
	}
	if _, err := hex.DecodeString(download.Digest); err != nil || len(download.Digest) != sha3.New384().Size()*2 {
		return resolvedArchive{}, fmt.Errorf("SDK Store returned invalid SHA3-384 for %q", request.Name)
	}
	if download.Size > maxArchiveBytes {
		return resolvedArchive{}, fmt.Errorf("SDK archive exceeds %d bytes", maxArchiveBytes)
	}
	effectiveChannel := best.Result.Channel.Effective
	if effectiveChannel == "" {
		effectiveChannel = channel
	}
	return resolvedArchive{Name: request.Name, PackageID: best.ID, Channel: effectiveChannel,
		Revision: best.Result.Revision.Revision, Digest: strings.ToLower(download.Digest), Size: download.Size}, nil
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, body, target any) error {
	reader, writer := io.Reader(nil), &strings.Builder{}
	if body != nil {
		if err := json.NewEncoder(writer).Encode(body); err != nil {
			return err
		}
		reader = strings.NewReader(writer.String())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Latra/dev")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("SDK Store request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("SDK Store request failed: %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(target); err != nil {
		return fmt.Errorf("decode SDK Store response: %w", err)
	}
	return nil
}

func (c *Client) endpoint(parts ...string) string {
	copy := *c.base
	copy.Path = strings.TrimSuffix(copy.Path, "/") + "/" + strings.Join(parts, "/")
	return copy.String()
}

func (c *Client) materialize(ctx context.Context, archive resolvedArchive, limits sdk.Limits) (string, error) {
	if err := sdk.ValidateName(archive.Name); err != nil {
		return "", fmt.Errorf("invalid SDK cache name: %w", err)
	}
	if err := sdk.ValidateChannel(archive.Channel); err != nil {
		return "", fmt.Errorf("invalid SDK cache channel: %w", err)
	}
	channelDir := filepath.Join(c.cacheDir, archive.Name, filepath.FromSlash(archive.Channel))
	extractDir := filepath.Join(channelDir, strconv.Itoa(archive.Revision))
	archivePath := extractDir + ".sdk"
	if info, err := os.Stat(extractDir); err == nil && info.IsDir() {
		if file, openErr := os.Open(archivePath); openErr == nil {
			verifyErr := verifyArchive(file, archive)
			file.Close()
			if verifyErr == nil {
				return extractDir, nil
			}
		}
	}
	if err := os.MkdirAll(channelDir, 0o700); err != nil {
		return "", err
	}
	if err := c.download(ctx, archive, archivePath); err != nil {
		return "", err
	}
	temporary, err := os.MkdirTemp(channelDir, ".extract-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	if err := extractArchive(archivePath, temporary, limits); err != nil {
		return "", resolutionFailure(sdk.StateInvalidArtifact, "store-artifact-extraction-failed", "extract", err)
	}
	if err := replaceExtractedCache(temporary, extractDir); err != nil {
		return "", err
	}
	return extractDir, nil
}

func replaceExtractedCache(source, target string) error {
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		return os.Rename(source, target)
	} else if err != nil {
		return err
	}

	placeholder, err := os.CreateTemp(filepath.Dir(target), ".stale-")
	if err != nil {
		return err
	}
	stale := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		return err
	}
	if err := os.Remove(stale); err != nil {
		return err
	}
	if err := os.Rename(target, stale); err != nil {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		if _, statErr := os.Stat(target); statErr == nil {
			_ = os.RemoveAll(stale)
			return nil
		}
		_ = os.Rename(stale, target)
		return err
	}
	return os.RemoveAll(stale)
}

func (c *Client) download(ctx context.Context, archive resolvedArchive, target string) error {
	if file, err := os.Open(target); err == nil {
		valid := verifyArchive(file, archive)
		file.Close()
		if valid == nil {
			return nil
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".download-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	defer temporary.Close()
	filename := url.PathEscape(archive.PackageID + "_" + fmt.Sprint(archive.Revision) + ".sdk")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("api", "v1", "sdks", "download", filename), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Latra/dev")
	resp, err := c.http.Do(req)
	if err != nil {
		return resolutionFailure(sdk.StateDownloadFailed, "store-download-failed", "download", fmt.Errorf("download SDK: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return resolutionFailure(sdk.StateDownloadFailed, "store-download-failed", "download", fmt.Errorf("download SDK: %s", resp.Status))
	}
	if resp.ContentLength > maxArchiveBytes || (archive.Size > 0 && resp.ContentLength >= 0 && resp.ContentLength != archive.Size) {
		return resolutionFailure(sdk.StateDigestMismatch, "store-artifact-size-mismatch", "verify", fmt.Errorf("SDK archive size does not match resolve response"))
	}
	limited := io.LimitReader(resp.Body, maxArchiveBytes+1)
	if _, err := io.Copy(temporary, limited); err != nil {
		return resolutionFailure(sdk.StateDownloadFailed, "store-download-failed", "download", err)
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := verifyArchive(temporary, archive); err != nil {
		return resolutionFailure(sdk.StateDigestMismatch, "store-artifact-digest-mismatch", "verify", err)
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, target)
}

func verifyArchive(file *os.File, archive resolvedArchive) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxArchiveBytes || (archive.Size > 0 && info.Size() != archive.Size) {
		return fmt.Errorf("SDK archive size mismatch")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hash := sha3.New384()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != archive.Digest {
		return fmt.Errorf("SDK archive SHA3-384 mismatch")
	}
	return nil
}

func extractArchive(archivePath, target string, limits sdk.Limits) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	root, err := os.OpenRoot(target)
	if err != nil {
		return err
	}
	defer root.Close()
	decoder, err := zstd.NewReader(file,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(uint64(maxArchiveBytes)),
	)
	if err != nil {
		return fmt.Errorf("open Zstandard SDK archive: %w", err)
	}
	defer decoder.Close()
	reader := tar.NewReader(decoder)
	var files, total int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read SDK archive: %w", err)
		}
		name := filepath.ToSlash(filepath.Clean(header.Name))
		if name == "." {
			continue
		}
		if filepath.IsAbs(header.Name) || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\x00') {
			return fmt.Errorf("unsafe SDK archive path %q", header.Name)
		}
		if depth := len(strings.Split(name, "/")); depth > limits.MaxDepth {
			return fmt.Errorf("SDK archive path exceeds maximum depth")
		}
		files++
		if files > limits.MaxFiles {
			return fmt.Errorf("SDK archive exceeds maximum file count")
		}
		if header.Size < 0 || header.Size > limits.MaxFileSize {
			return fmt.Errorf("SDK archive entry %q exceeds size limit", name)
		}
		total += header.Size
		if total > limits.MaxTotalBytes {
			return fmt.Errorf("SDK archive exceeds total size limit")
		}
		parent := filepath.ToSlash(filepath.Dir(name))
		if parent != "." {
			if err := root.MkdirAll(parent, 0o700); err != nil {
				return fmt.Errorf("create archive directory: %w", err)
			}
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, os.FileMode(header.Mode)&0o777|0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			output, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(header.Mode)&0o777|0o600)
			if err != nil {
				return fmt.Errorf("create archive entry %q: %w", name, err)
			}
			_, copyErr := io.CopyN(output, reader, header.Size)
			closeErr := output.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			targetPath := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(name), header.Linkname)))
			if filepath.IsAbs(header.Linkname) || targetPath == ".." || strings.HasPrefix(targetPath, "../") {
				return fmt.Errorf("unsafe SDK archive symlink %q -> %q", name, header.Linkname)
			}
			if err := root.Symlink(header.Linkname, name); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported SDK archive entry type for %q", name)
		}
	}
	return nil
}

func dpkgArchitecture(goarch string) (string, error) {
	architectures := map[string]string{"amd64": "amd64", "arm64": "arm64", "386": "i386", "arm": "armhf", "ppc64le": "ppc64el", "s390x": "s390x", "riscv64": "riscv64"}
	architecture, ok := architectures[goarch]
	if !ok {
		return "", fmt.Errorf("unsupported architecture %q", goarch)
	}
	return architecture, nil
}

func resolutionFailure(state sdk.ResolutionState, code, phase string, err error) error {
	return &source.ResolutionError{
		State: state,
		Diagnostic: sdk.Diagnostic{
			Code: code, Severity: sdk.SeverityError, Phase: phase, Message: err.Error(),
		},
		Err: err,
	}
}

var _ source.StoreResolver = (*Client)(nil)

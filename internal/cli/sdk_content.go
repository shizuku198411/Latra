package cli

import (
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/source"
)

const maxDisplayedFileBytes = int64(128 << 20)

type contentOptions struct {
	sdk      string
	target   string
	channel  string
	revision int
	project  string
}

func runFile(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	options, err := parseContentOptions("file", "FILE", args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	entry, err := resolveContentSDK(dependencies, options)
	if err != nil {
		fmt.Fprintf(stderr, "latra: file: %v\n", err)
		return exitError
	}
	file, info, err := sdkcache.OpenFile(entry, options.target)
	if err != nil {
		var skipped *sdkcache.ContentSkippedError
		if errors.As(err, &skipped) {
			if writeErr := writeSkippedFile(stdout, skipped.File, "not extracted", &entry); writeErr != nil {
				fmt.Fprintf(stderr, "latra: file: %v\n", writeErr)
				return exitError
			}
			return exitOK
		}
		fmt.Fprintf(stderr, "latra: file: SDK %q file %q: %v\n", options.sdk, options.target, err)
		return exitError
	}
	defer file.Close()
	if err := writeCachedFile(stdout, file, info); err != nil {
		fmt.Fprintf(stderr, "latra: file: %v\n", err)
		return exitError
	}
	return exitOK
}

func runHook(args []string, stdout, stderr io.Writer, dependencies Dependencies) int {
	options, err := parseContentOptions("hook", "HOOK", args)
	if err != nil {
		return usageError(stderr, "%v", err)
	}
	if !isHookName(options.target) {
		return usageError(stderr, "unknown Workshop hook %q", options.target)
	}
	entry, err := resolveContentSDK(dependencies, options)
	if err != nil {
		fmt.Fprintf(stderr, "latra: hook: %v\n", err)
		return exitError
	}
	file, info, err := openHook(entry, options.target)
	if err != nil {
		fmt.Fprintf(stderr, "latra: hook %q was not found in SDK %q: %v\n", options.target, options.sdk, err)
		return exitError
	}
	defer file.Close()
	if err := writeCachedFile(stdout, file, info); err != nil {
		fmt.Fprintf(stderr, "latra: hook: %v\n", err)
		return exitError
	}
	return exitOK
}

func parseContentOptions(command, targetName string, args []string) (contentOptions, error) {
	var options contentOptions
	var positionals []string
	optionsEnded := false
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case !optionsEnded && argument == "--":
			optionsEnded = true
		case !optionsEnded && argument == "--channel":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--channel requires a value")
			}
			options.channel = args[index]
		case !optionsEnded && strings.HasPrefix(argument, "--channel="):
			options.channel = strings.TrimPrefix(argument, "--channel=")
		case !optionsEnded && argument == "--revision":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--revision requires a value")
			}
			value, err := strconv.Atoi(args[index])
			if err != nil || value <= 0 {
				return options, fmt.Errorf("invalid revision %q", args[index])
			}
			options.revision = value
		case !optionsEnded && argument == "--project":
			index++
			if index >= len(args) {
				return options, fmt.Errorf("--project requires a value")
			}
			options.project = args[index]
		case !optionsEnded && strings.HasPrefix(argument, "--project="):
			options.project = strings.TrimPrefix(argument, "--project=")
		case !optionsEnded && strings.HasPrefix(argument, "--revision="):
			text := strings.TrimPrefix(argument, "--revision=")
			value, err := strconv.Atoi(text)
			if err != nil || value <= 0 {
				return options, fmt.Errorf("invalid revision %q", text)
			}
			options.revision = value
		case !optionsEnded && strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown %s option %q", command, argument)
		default:
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) != 2 {
		return options, fmt.Errorf("%s requires exactly SDK and %s", command, targetName)
	}
	options.sdk, options.target = positionals[0], positionals[1]
	return options, nil
}

func resolveContentSDK(dependencies Dependencies, options contentOptions) (sdkcache.Entry, error) {
	cacheRoot := dependencies.CacheRoot
	if cacheRoot == "" {
		cacheRoot = sdkcache.DefaultRoot
	}
	if options.channel != "" {
		return sdkcache.Resolve(cacheRoot, sdkcache.Selection{
			SDK: options.sdk, Channel: options.channel, Revision: options.revision,
		})
	}
	project := options.project
	if project == "" {
		project = dependencies.WorkingDirectory
		if project == "" {
			project = "."
		}
	}
	reference, err := source.ResolveSDKReference(project, options.sdk)
	if err != nil {
		return sdkcache.Entry{}, fmt.Errorf("resolve SDK from Workshop project: %w", err)
	}
	switch reference.Source {
	case sdk.SourceProject:
		if options.revision != 0 {
			return sdkcache.Entry{}, fmt.Errorf("--revision cannot select a project SDK")
		}
		return sdkcache.ResolveProject(project, options.sdk)
	case sdk.SourceStore:
		return sdkcache.Resolve(cacheRoot, sdkcache.Selection{
			SDK: options.sdk, Channel: reference.Channel, Revision: options.revision,
		})
	default:
		return sdkcache.Entry{}, fmt.Errorf("SDK %q uses unsupported source %q", options.sdk, reference.Source)
	}
}

func isHookName(name string) bool {
	for _, candidate := range sdk.HookNames {
		if name == string(candidate) {
			return true
		}
	}
	return false
}

func openHook(entry sdkcache.Entry, hook string) (io.ReadCloser, fs.FileInfo, error) {
	var selected io.ReadCloser
	var selectedInfo fs.FileInfo
	var selectedPath string
	for _, candidate := range []string{"hooks/" + hook, "sdk/hooks/" + hook} {
		file, info, err := sdkcache.OpenFile(entry, candidate)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return nil, nil, err
		}
		if selected != nil {
			file.Close()
			selected.Close()
			return nil, nil, fmt.Errorf("hook exists at both %q and %q", selectedPath, candidate)
		}
		selected, selectedInfo, selectedPath = file, info, candidate
	}
	if selected == nil {
		return nil, nil, fs.ErrNotExist
	}
	return selected, selectedInfo, nil
}

func writeCachedFile(writer io.Writer, reader io.Reader, info fs.FileInfo) error {
	if info.Size() > maxDisplayedFileBytes {
		hasher := sha3.New384()
		size, err := io.Copy(hasher, reader)
		if err != nil {
			return err
		}
		return writeSkippedFile(writer, sdk.File{
			Type: sdk.FileRegular, Size: size, Digest: "sha3-384:" + hex.EncodeToString(hasher.Sum(nil)),
			SkipReason: "display-size-limit",
		}, "not displayed", nil)
	}
	content, err := io.ReadAll(io.LimitReader(reader, maxDisplayedFileBytes+1))
	if err != nil {
		return err
	}
	if int64(len(content)) > maxDisplayedFileBytes {
		return fmt.Errorf("file exceeds display limit of %d bytes", maxDisplayedFileBytes)
	}
	if sdk.IsTextContent(content) {
		_, err := writer.Write(content)
		return err
	}
	digest := sha3.Sum384(content)
	_, err = fmt.Fprintf(writer, "Binary file\nType: %s\nMIME: %s\nSize: %d bytes\nSHA3-384: %s\n",
		describeBinary(content), http.DetectContentType(content), len(content), hex.EncodeToString(digest[:]))
	return err
}

func writeSkippedFile(writer io.Writer, file sdk.File, status string, entry *sdkcache.Entry) error {
	if _, err := fmt.Fprintf(writer, "File content %s\nReason: %s\nType: %s\nSize: %d bytes\nSHA3-384: %s\n",
		status, file.SkipReason, file.Type, file.Size, strings.TrimPrefix(file.Digest, "sha3-384:")); err != nil {
		return err
	}
	if entry != nil && entry.Channel != "" {
		_, err := fmt.Fprintf(writer, "Channel: %s\nRevision: %d\n", entry.Channel, entry.Revision)
		return err
	}
	return nil
}

func describeBinary(content []byte) string {
	if len(content) >= 6 && string(content[:4]) == "\x7fELF" {
		class := map[byte]string{1: "32-bit", 2: "64-bit"}[content[4]]
		endian := map[byte]string{1: "LSB", 2: "MSB"}[content[5]]
		return strings.TrimSpace("ELF " + class + " " + endian)
	}
	typeName := http.DetectContentType(content)
	if semicolon := strings.IndexByte(typeName, ';'); semicolon >= 0 {
		typeName = typeName[:semicolon]
	}
	return typeName
}

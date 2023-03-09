package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
)

func main() {
	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var opt struct {
	NoCache bool
}

var cmd = &cobra.Command{
	Use:                   "awsexec [profile] [flags] -- [command]",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run:                   run,
}

func init() {
	cmd.Flags().BoolVar(&opt.NoCache, "no-cache", false, "disable credentials cache")
}

func run(cmd *cobra.Command, args []string) {
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	creds, err := getCredentials(ctx, args[0], !opt.NoCache)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if len(args) > 1 {
		execCommand(ctx, args[1:], creds)
	}
}

func execCommand(ctx context.Context, cmd []string, creds aws.Credentials) {
	cc := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	cc.Env = append(
		os.Environ(),
		"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
		"AWS_SESSION_TOKEN="+creds.SessionToken,
	)
	cc.Stdin = os.Stdin
	cc.Stdout = os.Stdout
	cc.Stderr = os.Stderr
	_ = cc.Run()
}

func getCredentials(ctx context.Context, profile string, useCache bool) (aws.Credentials, error) {
	var cacheFilename string
	if useCache {
		cacheFilename = credentialCacheFilename(profile)
	}

	if creds, err := loadCachedCredentials(cacheFilename); err != nil {
		return aws.Credentials{}, err
	} else if creds.HasKeys() {
		return creds, err
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to load a configuration: %w", err)
	}

	sc, err := config.LoadSharedConfigProfile(ctx, profile)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to load a profile: %w", err)
	}

	creds, err := aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), sc.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sc.RoleSessionName
		o.Duration = aws.ToDuration(sc.RoleDurationSeconds)
		if s := sc.ExternalID; s != "" {
			o.ExternalID = aws.String(sc.ExternalID)
		}
		if s := sc.MFASerial; s != "" {
			o.SerialNumber = aws.String(s)
			o.TokenProvider = stscreds.StdinTokenProvider
		}
	})).Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to assume role: %w", err)
	}

	if err := storeCachedCredentials(cacheFilename, creds); err != nil {
		return aws.Credentials{}, err
	}

	return creds, nil
}

type credentialCache struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken,omitempty"`
	Expiration      string `json:"Expiration,omitempty"`
}

func credentialCacheFilename(profile string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".aws", "exec", "cache", profile+".json")
}

func loadCachedCredentials(filename string) (aws.Credentials, error) {
	if filename == "" {
		return aws.Credentials{}, nil
	}

	b, err := os.ReadFile(filename)
	if errors.Is(err, syscall.ENOENT) {
		return aws.Credentials{}, nil
	}
	if err != nil {
		return aws.Credentials{}, err
	}

	var c credentialCache
	if err := json.Unmarshal(b, &c); err != nil {
		return aws.Credentials{}, nil
	}

	creds := aws.Credentials{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SessionToken:    c.SessionToken,
		CanExpire:       c.Expiration != "",
		Expires:         time.Time{},
	}
	if s := c.Expiration; s != "" {
		t, err := time.Parse(time.RFC3339, c.Expiration)
		if err != nil {
			return aws.Credentials{}, nil
		}
		creds.Expires = t
	}
	return creds, nil
}

func storeCachedCredentials(filename string, creds aws.Credentials) error {
	if filename == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		return fmt.Errorf("failed to create a cache directory: %w", err)
	}

	b, err := json.Marshal(&credentialCache{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      creds.Expires.Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to serialize a credentials cache: %s", err)
	}

	if err := os.WriteFile(filename, b, 0600); err != nil {
		return fmt.Errorf("failed to write a credentials cache file: %s", err)
	}

	return nil
}

// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

var unsafeHostnameCharacters = regexp.MustCompile(`[^a-zA-Z0-9-\.]`)

const (
	crtSuffix = ".crt"
	keySuffix = ".key"
)

type certProvider interface {
	// TLSConfig creates a new TLS config suitable for net/http.Server servers.
	//
	// The returned Config must have a GetCertificate function set and that
	// function must return a unique *tls.Certificate for each call. The
	// returned *tls.Certificate will be mutated by the caller to append to the
	// (*tls.Certificate).Certificate field.
	TLSConfig() *tls.Config
	// HTTPHandler handle ACME related request, if any.
	HTTPHandler(fallback http.Handler) http.Handler
}

func certProviderByCertMode(mode, dir, hostname string) (certProvider, error) {
	if dir == "" {
		return nil, errors.New("missing required --certdir flag")
	}
	switch mode {
	case "letsencrypt":
		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache(dir),
		}
		if hostname == "derp.tailscale.com" {
			certManager.HostPolicy = prodAutocertHostPolicy
			certManager.Email = "security@tailscale.com"
		}
		return certManager, nil
	case "manual":
		return NewManualCertManager(dir, hostname)
	default:
		return nil, fmt.Errorf("unsupport cert mode: %q", mode)
	}
}

type manualCertManager struct {
	cert           *tls.Certificate
	certdir        string
	hostname       string
	filesChanged   bool
	filesChangedMu sync.RWMutex
	certMu         sync.RWMutex
}

// NewManualCertManager returns a cert provider which read certificate by given hostname on create.
func NewManualCertManager(certdir, hostname string) (certProvider, error) {
	cert, err := loadCertificate(certdir, hostname)
	if err != nil {
		return nil, err
	}

	mgr := &manualCertManager{
		cert:     cert,
		certdir:  certdir,
		hostname: hostname,
	}

	// Start a routine to monitor for changes to the certificate
	// and key files.
	initChan := make(chan error, 1)
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			initChan <- err
		} else if err := watcher.Add(certdir); err != nil {
			initChan <- err
		} else {
			initChan <- nil
			for {
				select {
				case event := <-watcher.Events:
					if event.Op&fsnotify.Write == fsnotify.Write {
						_, f := filepath.Split(event.Name)
						if strings.HasSuffix(f, crtSuffix) || strings.HasSuffix(f, keySuffix) {
							mgr.filesChangedMu.Lock()
							if mgr.filesChanged == false {
								mgr.filesChanged = true
							}
							mgr.filesChangedMu.Unlock()
						}
					}
				case err = <-watcher.Errors:
					fmt.Printf("fsnotify watcher error while monitoring certificate: %v\n", err)
				}
			}
		}
	}()

	// Wait for fsnotify.Watcher to initialize
	if err = <-initChan; err != nil {
		mgr = nil
		err = fmt.Errorf("failed to start fsnotify watcher: %v", err)
	}

	return mgr, err
}

func loadCertificate(certdir, hostname string) (*tls.Certificate, error) {
	baseFN := unsafeHostnameCharacters.ReplaceAllString(hostname, "")
	crtPath := filepath.Join(certdir, baseFN+crtSuffix)
	keyPath := filepath.Join(certdir, baseFN+keySuffix)

	fmt.Printf("derper loading key pair: %s, %s\n", crtPath, keyPath)

	cert, err := tls.LoadX509KeyPair(crtPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("can not load x509 key pair for hostname %q: %w", baseFN, err)
	}
	// ensure hostname matches with the certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("can not load cert: %w", err)
	}
	if err := x509Cert.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("cert invalid for hostname %q: %w", hostname, err)
	}
	return &cert, nil
}

// shouldReload checks filesChanged to determine if the certificate
// should be reloaded from disk.
func (m *manualCertManager) shouldReload() bool {
	m.filesChangedMu.RLock()
	defer m.filesChangedMu.RUnlock()
	return m.filesChanged
}

func (m *manualCertManager) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: nil,
		NextProtos: []string{
			"http/1.1",
		},
		GetCertificate: m.getCertificate,
	}
}

func (m *manualCertManager) getCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hi.ServerName != m.hostname {
		return nil, fmt.Errorf("cert mismatch with hostname: %q", hi.ServerName)
	}

	// Return a shallow copy of the cert so the caller can append to its
	// Certificate field.
	var certCopy *tls.Certificate
	copyCert := func() {
		certCopy = new(tls.Certificate)
		*certCopy = *m.cert
		certCopy.Certificate = certCopy.Certificate[:len(certCopy.Certificate):len(certCopy.Certificate)]
	}

	if m.shouldReload() {
		cert, err := loadCertificate(m.certdir, m.hostname)
		if err != nil {
			// Log and use last known good certificate
			fmt.Printf("derper had error while reloading certificate: %v\n", err)
		} else if cert != nil {
			// Use latest certificate
			fmt.Printf("derper is reloading certificate after change\n")
			m.certMu.Lock()
			m.cert = cert
			copyCert()
			m.filesChanged = false
			m.certMu.Unlock()
		}
	}

	if certCopy == nil {
		m.certMu.RLock()
		copyCert()
		m.certMu.RUnlock()
	}

	return certCopy, nil
}

func (m *manualCertManager) HTTPHandler(fallback http.Handler) http.Handler {
	return fallback
}

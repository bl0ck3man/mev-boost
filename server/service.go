package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSlot      = errors.New("invalid slot")
	errInvalidHash      = errors.New("invalid hash")
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")

	errServerAlreadyRunning = errors.New("server already running")
)

var nilHash = types.Hash{}

// HTTPServerTimeouts are various timeouts for requests to the mev-boost HTTP server
type HTTPServerTimeouts struct {
	Read       time.Duration // Timeout for body reads. None if 0.
	ReadHeader time.Duration // Timeout for header reads. None if 0.
	Write      time.Duration // Timeout for writes. None if 0.
	Idle       time.Duration // Timeout to disconnect idle client connections. None if 0.
}

// NewDefaultHTTPServerTimeouts creates default server timeouts
func NewDefaultHTTPServerTimeouts() HTTPServerTimeouts {
	return HTTPServerTimeouts{
		Read:       4 * time.Second,
		ReadHeader: 2 * time.Second,
		Write:      6 * time.Second,
		Idle:       10 * time.Second,
	}
}

// BoostService TODO
type BoostService struct {
	listenAddr string
	relays     []RelayEntry
	log        *logrus.Entry
	srv        *http.Server

	builderSigningDomain types.Domain
	serverTimeouts       HTTPServerTimeouts

	httpClient http.Client

	collectorURL string
}

// NewBoostService created a new BoostService
func NewBoostService(listenAddr string, relays []RelayEntry, log *logrus.Entry, genesisForkVersionHex string, relayRequestTimeout time.Duration, mevBoostCollectorURL string) (*BoostService, error) {
	if len(relays) == 0 {
		return nil, errors.New("no relays")
	}

	builderSigningDomain, err := ComputeDomain(types.DomainTypeAppBuilder, genesisForkVersionHex, types.Root{}.String())
	if err != nil {
		return nil, err
	}

	return &BoostService{
		listenAddr: listenAddr,
		relays:     relays,
		log:        log.WithField("module", "service"),

		builderSigningDomain: builderSigningDomain,
		serverTimeouts:       NewDefaultHTTPServerTimeouts(),
		httpClient:           http.Client{Timeout: relayRequestTimeout},
		collectorURL:         mevBoostCollectorURL,
	}, nil
}

func (m *BoostService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", m.handleRoot)

	r.HandleFunc(pathStatus, m.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, m.handleRegisterValidator).Methods(http.MethodPost)
	r.HandleFunc(pathGetHeader, m.handleGetHeader).Methods(http.MethodGet)
	r.HandleFunc(pathGetPayload, m.handleGetPayload).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))
	loggedRouter := httplogger.LoggingMiddlewareLogrus(m.log, r)
	return loggedRouter
}

// StartHTTPServer starts the HTTP server for this boost service instance
func (m *BoostService) StartHTTPServer() error {
	if m.srv != nil {
		return errServerAlreadyRunning
	}

	m.srv = &http.Server{
		Addr:    m.listenAddr,
		Handler: m.getRouter(),

		ReadTimeout:       m.serverTimeouts.Read,
		ReadHeaderTimeout: m.serverTimeouts.ReadHeader,
		WriteTimeout:      m.serverTimeouts.Write,
		IdleTimeout:       m.serverTimeouts.Idle,
	}

	err := m.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (m *BoostService) handleRoot(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

func (m *BoostService) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{}`)
}

// RegisterValidatorV1 - returns 200 if at least one relay returns 200
func (m *BoostService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "registerValidator")
	log.Info("registerValidator")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, registration := range payload {
		if len(registration.Message.Pubkey) != 48 {
			http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
			return
		}

		if len(registration.Signature) != 96 {
			http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
			return
		}

		ok, err := types.VerifySignature(registration.Message, m.builderSigningDomain, registration.Message.Pubkey[:], registration.Signature[:])
		if err != nil {
			log.WithError(err).WithField("registration", registration).Error("error verifying registerValidator signature")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			log.WithError(err).WithField("registration", registration).Error("failed to verify registerValidator signature")
			http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
			return
		}
	}

	numSuccessRequestsToRelay := 0
	var mu sync.Mutex

	// Call the relays
	var wg sync.WaitGroup
	for _, relay := range m.relays {
		wg.Add(1)
		go func(relayAddr string) {
			defer wg.Done()
			url := relayAddr + pathRegisterValidator
			log := log.WithField("url", url)

			err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodPost, url, payload, nil)
			if err != nil {
				log.WithError(err).Warn("error in registerValidator to relay")
				return
			}

			mu.Lock()
			defer mu.Unlock()
			numSuccessRequestsToRelay++
		}(relay.Address)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if numSuccessRequestsToRelay > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{}`)
	} else {
		w.WriteHeader(http.StatusBadGateway)
	}
}

// GetHeaderV1 TODO
func (m *BoostService) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot := vars["slot"]
	parentHashHex := vars["parent_hash"]
	pubkey := vars["pubkey"]
	log := m.log.WithFields(logrus.Fields{
		"method":     "getHeader",
		"slot":       slot,
		"parentHash": parentHashHex,
		"pubkey":     pubkey,
	})
	log.Info("getHeader")

	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
		http.Error(w, errInvalidSlot.Error(), http.StatusBadRequest)
		return
	}

	if len(pubkey) != 98 {
		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(parentHashHex) != 66 {
		http.Error(w, errInvalidHash.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetHeaderResponse)
	var mu sync.Mutex

	// Call the relays
	var wg sync.WaitGroup
	for _, relay := range m.relays {
		wg.Add(1)
		go func(relayAddr string, relayPubKey types.PublicKey) {
			defer wg.Done()
			url := fmt.Sprintf("%s/eth/v1/builder/header/%s/%s/%s", relayAddr, slot, parentHashHex, pubkey)
			log := log.WithField("url", url)
			responsePayload := new(types.GetHeaderResponse)
			err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodGet, url, nil, responsePayload)

			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}

			// Skip if invalid payload
			if responsePayload.Data == nil || responsePayload.Data.Message == nil || responsePayload.Data.Message.Header == nil || responsePayload.Data.Message.Header.BlockHash == nilHash {
				return
			}

			log = log.WithFields(logrus.Fields{
				"blockNumber": responsePayload.Data.Message.Header.BlockNumber,
				"blockHash":   responsePayload.Data.Message.Header.BlockHash,
				"txRoot":      responsePayload.Data.Message.Header.TransactionsRoot.String(),
				"value":       responsePayload.Data.Message.Value.String(),
			})

			// Verify the relay signature in the relay response
			ok, err := types.VerifySignature(responsePayload.Data.Message, m.builderSigningDomain, relayPubKey[:], responsePayload.Data.Signature[:])
			if err != nil {
				log.WithError(err).Error("error verifying relay signature")
				return
			}
			if !ok {
				log.WithError(errInvalidSignature).Error("failed to verify relay signature")
				return
			}

			// Compare value of header, skip processing this result if lower fee than current
			mu.Lock()
			defer mu.Unlock()

			if responsePayload != nil && m.collectorURL != "" {
				var wgCollector sync.WaitGroup
				type CustomRelayPayload struct {
					SlotNumber       uint64 `json:"slot"`
					BlockHash        string `json:"block_hash"`
					BlockNumber      uint64 `json:"block_number"`
					FeeRecipient     string `json:"fee_recipient"`
					TransactionsRoot string `json:"transactions_root"`
					Pubkey           string `json:"pubkey"`
					Signature        string `json:"signature"`
					RelayAddr        string `json:"relay_adr"`
					RelayTimestamp   string `json:"timestamp"`
				}

				wgCollector.Add(1)
				go func(slot string, headerResponse *types.GetHeaderResponse, relayURL string) {
					defer wg.Done()

					slotNumber, err := strconv.ParseUint(slot, 10, 32)
					if err != nil {
						log.WithFields(logrus.Fields{
							`slot`:  slot,
							`relay`: relayAddr,
						}).Warning(`Could not convert slot from string to UINT`)

						return
					}

					mevBoostPayload := CustomRelayPayload{
						SlotNumber:       slotNumber,
						BlockHash:        headerResponse.Data.Message.Header.BlockHash.String(),
						BlockNumber:      headerResponse.Data.Message.Header.BlockNumber,
						FeeRecipient:     headerResponse.Data.Message.Header.FeeRecipient.String(),
						TransactionsRoot: headerResponse.Data.Message.Header.TransactionsRoot.String(),
						Pubkey:           headerResponse.Data.Message.Pubkey.String(),
						Signature:        headerResponse.Data.Signature.String(),
						RelayAddr:        relayURL,
						RelayTimestamp:   strconv.FormatUint(headerResponse.Data.Message.Header.Timestamp, 10),
					}
					if err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodPost, m.collectorURL, mevBoostPayload, nil); err != nil {
						log.WithError(err).Warn("error making request to mev-boost-collector")
					}

				}(slot, responsePayload, relayAddr)
				wgCollector.Wait()
			}

			// Skip if not a higher value
			if result.Data != nil && responsePayload.Data.Message.Value.Cmp(&result.Data.Message.Value) < 1 {
				return
			}

			// Use this relay's response as mev-boost response because it's most profitable
			*result = *responsePayload
			log.Info("successfully got more valuable payload header")
		}(relay.Address, relay.PublicKey)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if result.Data == nil || result.Data.Message == nil || result.Data.Message.Header == nil || result.Data.Message.Header.BlockHash == nilHash {
		log.Warn("no successful relay response")
		http.Error(w, "no successful relay response", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (m *BoostService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		http.Error(w, errInvalidSignature.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetPayloadResponse)
	requestCtx, requestCtxCancel := context.WithCancel(context.Background())
	defer requestCtxCancel()
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, relay := range m.relays {
		wg.Add(1)
		go func(relayAddr string) {
			defer wg.Done()
			url := fmt.Sprintf("%s%s", relayAddr, pathGetPayload)
			log := log.WithField("url", url)
			responsePayload := new(types.GetPayloadResponse)
			err := SendHTTPRequest(requestCtx, m.httpClient, http.MethodPost, url, payload, responsePayload)

			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}

			if responsePayload.Data == nil || responsePayload.Data.BlockHash == nilHash {
				log.Warn("invalid response")
				return
			}

			// Lock before accessing the shared payload
			mu.Lock()
			defer mu.Unlock()

			if requestCtx.Err() != nil { // request has been cancelled (or deadline exceeded)
				return
			}

			// Ensure the response blockhash matches the request
			if payload.Message.Body.ExecutionPayloadHeader.BlockHash != responsePayload.Data.BlockHash {
				log.WithFields(logrus.Fields{
					"payloadBlockHash":  payload.Message.Body.ExecutionPayloadHeader.BlockHash,
					"responseBlockHash": responsePayload.Data.BlockHash,
				}).Warn("requestBlockHash does not equal responseBlockHash")
				return
			}

			// Received successful response. Now cancel other requests and return immediately
			requestCtxCancel()
			*result = *responsePayload
			log.WithFields(logrus.Fields{
				"blockHash":   responsePayload.Data.BlockHash,
				"blockNumber": responsePayload.Data.BlockNumber,
			}).Info("getPayload: received payload from relay")
		}(relay.Address)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if result.Data == nil || result.Data.BlockHash == nilHash {
		log.Warn("getPayload: no valid response from relay")
		http.Error(w, "no valid getPayload response", http.StatusBadGateway)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// CheckRelays sends a request to each one of the relays previously registered to get their status
func (m *BoostService) CheckRelays() bool {
	for _, relay := range m.relays {
		m.log.WithField("relay", relay).Info("Checking relay")

		err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodGet, relay.Address+pathStatus, nil, nil)
		if err != nil {
			m.log.WithError(err).WithField("relay", relay).Error("relay check failed")
			return false
		}
	}

	return true
}

func (m *BoostService) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			fields := logrus.Fields{
				"remote":      r.RemoteAddr,
				"host":        r.Host,
				"url":         r.URL,
				"request_uri": r.RequestURI,
				"method":      r.Method,
			}
			for key, _ := range r.Header {
				fields[key] = r.Header.Get(key)
			}

			m.log.WithFields(fields).Info(`incoming request`)
		}()

		h.ServeHTTP(w, r)
	})
}

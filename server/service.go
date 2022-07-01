package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSlot               = errors.New("invalid slot")
	errInvalidHash               = errors.New("invalid hash")
	errInvalidPubkey             = errors.New("invalid pubkey")
	errInvalidSignature          = errors.New("invalid signature")
	errNoSuccessfulRelayResponse = errors.New("no successful relay response")

	errServerAlreadyRunning = errors.New("server already running")
)

var nilHash = types.Hash{}
var nilResponse = struct{}{}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// BoostService TODO
type BoostService struct {
	listenAddr string
	relays     []RelayEntry
	log        *logrus.Entry
	srv        *http.Server

	builderSigningDomain types.Domain
	httpClient           http.Client
	collectorURL         string
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
		httpClient:           http.Client{Timeout: relayRequestTimeout},
		collectorURL:         mevBoostCollectorURL,
	}, nil
}

func (m *BoostService) respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := httpErrorResp{code, message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		m.log.WithField("response", resp).WithError(err).Error("Couldn't write error response")
		http.Error(w, "", http.StatusInternalServerError)
	}
}

func (m *BoostService) respondOK(w http.ResponseWriter, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		m.log.WithField("response", response).WithError(err).Error("Couldn't write OK response")
		http.Error(w, "", http.StatusInternalServerError)
	}
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

		ReadTimeout:       0,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
	}

	err := m.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (m *BoostService) handleRoot(w http.ResponseWriter, req *http.Request) {
	m.respondOK(w, nilResponse)
}

// handleStatus sends calls to the status endpoint of every relay.
// It returns OK if at least one returned OK, and returns KO otherwise.
func (m *BoostService) handleStatus(w http.ResponseWriter, req *http.Request) {
	var wg sync.WaitGroup
	var numSuccessRequestsToRelay uint32

	for _, r := range m.relays {
		wg.Add(1)

		go func(relay RelayEntry) {
			defer wg.Done()

			log := m.log.WithField("relay", relay.Address)
			log.Debug("Checking relay status")

			url := relay.Address + pathStatus
			err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodGet, url, nil, nil)

			if err != nil {
				log.WithError(err).Error("failed to retrieve relay status")
				return
			}
			atomic.AddUint32(&numSuccessRequestsToRelay, 1)
		}(r)
	}

	// At the end, we wait for every routine and return status according to relay's ones.
	wg.Wait()

	if numSuccessRequestsToRelay == 0 {
		m.respondError(w, http.StatusServiceUnavailable, "all relays are unavailable")
	} else {
		m.respondOK(w, nilResponse)
	}
}

// RegisterValidatorV1 - returns 200 if at least one relay returns 200
func (m *BoostService) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "registerValidator")
	log.Info("registerValidator")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		m.respondError(w, http.StatusBadRequest, err.Error())
		return
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
		m.respondOK(w, nilResponse)
	} else {
		m.respondError(w, http.StatusBadGateway, errNoSuccessfulRelayResponse.Error())
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
		m.respondError(w, http.StatusBadRequest, errInvalidSlot.Error())
		return
	}

	if len(pubkey) != 98 {
		m.respondError(w, http.StatusBadRequest, errInvalidPubkey.Error())
		return
	}

	if len(parentHashHex) != 66 {
		m.respondError(w, http.StatusBadRequest, errInvalidHash.Error())
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
		m.respondError(w, http.StatusBadGateway, errNoSuccessfulRelayResponse.Error())
		return
	}

	m.respondOK(w, result)
}

func (m *BoostService) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	log := m.log.WithField("method", "getPayload")
	log.Info("getPayload")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		m.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(payload.Signature) != 96 {
		m.respondError(w, http.StatusBadRequest, errInvalidSignature.Error())
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
		m.respondError(w, http.StatusBadGateway, errNoSuccessfulRelayResponse.Error())
		return
	}

	m.respondOK(w, result)
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

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
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

var (
	errInvalidSlot      = errors.New("invalid slot")
	errInvalidHash      = errors.New("invalid hash")
	errInvalidPubkey    = errors.New("invalid pubkey")
	errInvalidSignature = errors.New("invalid signature")

	errServerAlreadyRunning = errors.New("server already running")

	pathStatus            = "/eth/v1/builder/status"
	pathRegisterValidator = "/eth/v1/builder/validators"
	pathGetHeader         = "/eth/v1/builder/header/{slot:[0-9]+}/{parent_hash:0x[a-fA-F0-9]+}/{pubkey:0x[a-fA-F0-9]+}"
	pathGetPayload        = "/eth/v1/builder/blinded_blocks"
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

	serverTimeouts HTTPServerTimeouts

	httpClient http.Client
}

// NewBoostService created a new BoostService
func NewBoostService(listenAddr string, relays []RelayEntry, log *logrus.Entry, relayRequestTimeout time.Duration) (*BoostService, error) {
	// TODO: validate relays
	if len(relays) == 0 {
		return nil, errors.New("no relays")
	}

	return &BoostService{
		listenAddr: listenAddr,
		relays:     relays,
		log:        log.WithField("module", "service"),

		serverTimeouts: NewDefaultHTTPServerTimeouts(),
		httpClient:     http.Client{Timeout: relayRequestTimeout},
	}, nil
}

func (m *BoostService) getRouter() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/", m.handleRoot)

	r.Use(m.Middleware)
	r.HandleFunc(pathStatus, m.handleStatus).Methods(http.MethodGet)
	r.HandleFunc(pathRegisterValidator, m.handleRegisterValidator).Methods(http.MethodPost)

	r.HandleFunc(pathGetHeader, m.handleGetHeader).Methods(http.MethodGet)

	r.HandleFunc(pathGetPayload, m.handleGetPayload).Methods(http.MethodPost)

	r.Use(mux.CORSMethodMiddleware(r))

	// loggedRouter := httplogger.LoggingMiddlewareLogrus(m.log, r)
	return r
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
	log := m.log.WithFields(logrus.Fields{
		"method": "registerValidator",
	})
	log.Info("handleRegisterValidator is called ")

	payload := []types.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		log.Error(`registerValidator_error`, fmt.Sprintf(`Could not decode request`))

		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for _, registration := range payload {
		if len(registration.Message.Pubkey) != 48 {

			log.WithFields(logrus.Fields{
				"registration": fmt.Sprintf(`%+v`, registration),
			}).
				Error(`registerValidator_error`, fmt.Errorf(`len(registration.Message.Pubkey) != 48 %w`, errInvalidPubkey))

			http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
			return
		}

		if len(registration.Signature) != 96 {
			log.WithFields(logrus.Fields{
				"registration": fmt.Sprintf(`%+v`, registration),
			}).
				Error(`registerValidator_error`, fmt.Errorf(`len(registration.Signature) != 96 %w`, errInvalidSignature))

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
			log := log.WithFields(logrus.Fields{
				`relayAddr`: url,
				`payload`:   fmt.Sprintf(`%+v`, payload),
			})

			log.Info(`registerValidator: Sending request to relay`)
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

		log.WithFields(logrus.Fields{
			"numSuccessRequestsToRelay": numSuccessRequestsToRelay,
		}).
			Info(`registerValidator: Registered in relay`)

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
	log.Info("handleGetHeader is called")

	if _, err := strconv.ParseUint(slot, 10, 64); err != nil {
		log.Error(`handleGetHeader`, fmt.Errorf(`invalid slot %w`, errInvalidSlot))

		http.Error(w, errInvalidSlot.Error(), http.StatusBadRequest)
		return
	}

	if len(pubkey) != 98 {
		log.Error(`handleGetHeader`, fmt.Errorf(`invalid pubkey %w`, errInvalidPubkey))

		http.Error(w, errInvalidPubkey.Error(), http.StatusBadRequest)
		return
	}

	if len(parentHashHex) != 66 {
		log.Error(`handleGetHeader`, fmt.Errorf(`invalid parentHashHex %w`, errInvalidHash))

		http.Error(w, errInvalidHash.Error(), http.StatusBadRequest)
		return
	}

	result := new(types.GetHeaderResponse)
	var mu sync.Mutex

	// Call the relays
	var wg sync.WaitGroup
	for _, relay := range m.relays {
		wg.Add(1)
		go func(relayAddr string) {
			defer wg.Done()
			url := fmt.Sprintf("%s/eth/v1/builder/header/%s/%s/%s", relayAddr, slot, parentHashHex, pubkey)
			log := log.WithFields(logrus.Fields{
				`url`: url,
			})
			responsePayload := new(types.GetHeaderResponse)

			log.Info(`handleGetHeader: Sending request to relay`)
			err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodGet, url, nil, responsePayload)

			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}

			// Compare value of header, skip processing this result if lower fee than current
			mu.Lock()
			defer mu.Unlock()

			// Skip if invalid payload
			if responsePayload.Data == nil || responsePayload.Data.Message == nil || responsePayload.Data.Message.Header == nil || responsePayload.Data.Message.Header.BlockHash == nilHash {
				return
			}

			log.WithFields(logrus.Fields{
				`url`:                url,
				`relayResponse`:      fmt.Sprintf("%+v", responsePayload),
				`result`:             fmt.Sprintf("%+v", result),
				`have to be skipped`: result.Data != nil && responsePayload.Data.Message.Value.Cmp(&result.Data.Message.Value) < 1,
			}).Info(`handleGetHeader: relay response`)
			/*if err := SendHTTPRequest(context.Background(), m.httpClient, http.MethodPost, `http://localhost:8080/payload`, responsePayload, nil); err != nil {
				log.WithError(err).Warn("error making request to mev-boost-collector")
			}*/

			// Skip if not a higher value
			if result.Data != nil && responsePayload.Data.Message.Value.Cmp(&result.Data.Message.Value) < 1 {
				return
			}

			// Use this relay's response as mev-boost response because it's most profitable
			*result = *responsePayload
			log.WithFields(logrus.Fields{
				"blockNumber": result.Data.Message.Header.BlockNumber,
				"blockHash":   result.Data.Message.Header.BlockHash,
				"txRoot":      result.Data.Message.Header.TransactionsRoot.String(),
				"value":       result.Data.Message.Value.String(),
				"url":         relayAddr,
			}).Info("handleGetHeader: successfully got more valuable payload header")
		}(relay.Address)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if result.Data == nil || result.Data.Message == nil || result.Data.Message.Header == nil || result.Data.Message.Header.BlockHash == nilHash {
		log.Warn("handleGetHeader: no successful response from relays")
		http.Error(w, "no valid getHeader response", http.StatusBadGateway)
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
	log.Info("handleGetPayload is called")

	payload := new(types.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(payload); err != nil {
		log.Error(`handleGetPayload: Could not decode payload`, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Signature) != 96 {
		log.Error(`handleGetPayload: len(payload.Signature) != 96`, errInvalidSignature)
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
			log := log.WithFields(logrus.Fields{
				"url":     url,
				"payload": fmt.Sprintf(`"%+v"`, payload),
			})
			responsePayload := new(types.GetPayloadResponse)
			log.Info(`handleGetPayload: sending request to relay`)
			err := SendHTTPRequest(requestCtx, m.httpClient, http.MethodPost, url, payload, responsePayload)

			if err != nil {
				log.WithError(err).Warn("error making request to relay")
				return
			}
			log.WithField(`response`, fmt.Sprintf(`%+v`, responsePayload)).
				Info(`handleGetPayload: response from relay`)

			if responsePayload.Data == nil || responsePayload.Data.BlockHash == nilHash {
				log.Warn("invalid response")
				return
			}

			// Lock before accessing the shared payload
			mu.Lock()
			defer mu.Unlock()

			if requestCtx.Err() != nil { // request has been cancelled (or deadline exceeded)
				log.Warn("handleGetPayload: request has been cancelled (or deadline exceeded)")
				return
			}

			// Ensure the response blockhash matches the request
			if payload.Message.Body.ExecutionPayloadHeader.BlockHash != responsePayload.Data.BlockHash {
				log.WithFields(logrus.Fields{
					"payloadBlockHash":  payload.Message.Body.ExecutionPayloadHeader.BlockHash,
					"responseBlockHash": responsePayload.Data.BlockHash,
				}).Warn("handleGetPayload: requestBlockHash does not equal responseBlockHash")
				return
			}

			// Received successful response. Now cancel other requests and return immediately
			requestCtxCancel()
			*result = *responsePayload
			log.WithFields(logrus.Fields{
				"blockHash":       responsePayload.Data.BlockHash,
				"blockNumber":     responsePayload.Data.BlockNumber,
				"responsePayload": fmt.Sprintf(`"%+v"`, responsePayload),
			}).Info("handleGetPayload: received payload from relay")
		}(relay.Address)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if result.Data == nil || result.Data.BlockHash == nilHash {
		log.Warn("handleGetPayload: no valid response from relay")
		http.Error(w, "no valid getPayload response", http.StatusBadGateway)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

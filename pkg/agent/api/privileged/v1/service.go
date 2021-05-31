package privileged

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/sirupsen/logrus"
	privilegedv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/privileged/v1"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/workload"
	"github.com/spiffe/spire/pkg/agent/endpoints"
	"github.com/spiffe/spire/pkg/agent/manager"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/spiffe/spire/pkg/server/api"
)

// RegisterService registers privileged service on provided server
func RegisterService(s *grpc.Server, service *Service) {
	privilegedv1.RegisterPrivilegedServer(s, service)
}

type Attestor interface {
	Attest(ctx context.Context) ([]*common.Selector, error)
}

type Config struct {
	Log             logrus.FieldLogger
	Manager         manager.Manager
	Attestor        attestor.Attestor
	AuthorizedUsers []string
}

func New(config Config) *Service {
	authorizedUsers := map[string]bool{}

	for _, user := range config.AuthorizedUsers {
		authorizedUsers[user] = true
	}

	return &Service{
		manager:         config.Manager,
		attestor:        endpoints.PeerTrackerAttestor{Attestor: config.Attestor},
		authorizedUsers: authorizedUsers,
	}
}

// Service implements the privileged server
type Service struct {
	privilegedv1.UnsafePrivilegedServer

	manager  manager.Manager
	attestor Attestor

	// Spiffe IDs of users that are authorized to use this API
	authorizedUsers map[string]bool
}

// isCallerAuthorized attests the caller and returns true if its identity is on
// the authorized users map.
func (s *Service) isCallerAuthorized(ctx context.Context) (bool, error) {
	callerSelectors, err := s.attestor.Attest(ctx)
	if err != nil {
		return false, err
	}

	identities := s.manager.MatchingIdentities(callerSelectors)

	for _, identity := range identities {
		id := identity.Entry.SpiffeId

		if _, ok := s.authorizedUsers[id]; ok {
			return true, nil
		}
	}

	return false, nil
}

func (s *Service) FetchX509SVIDBySelectors(req *privilegedv1.FetchX509SVIDBySelectorsRequest, stream privilegedv1.Privileged_FetchX509SVIDBySelectorsServer) error {
	ctx := stream.Context()

	authorized, err := s.isCallerAuthorized(ctx)
	if err != nil {
		return fmt.Errorf("failed to attest caller: %w", err)
	}

	if !authorized {
		return status.Error(codes.PermissionDenied, "no authorized")
	}

	selectors, err := api.SelectorsFromProto(req.Selectors)
	if err != nil {
		return err
	}

	subscriber := s.manager.SubscribeToCacheChanges(selectors)
	defer subscriber.Finish()

	for {
		select {
		case update := <-subscriber.Updates():
			if err := sendX509SVIDResponse(update, stream); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func sendX509SVIDResponse(update *cache.WorkloadUpdate, stream privilegedv1.Privileged_FetchX509SVIDBySelectorsServer) (err error) {
	resp, err := composeX509SVIDBySelectors(update)
	if err != nil {
		//log.WithError(err).Error("Could not serialize X.509 SVID response")
		return status.Errorf(codes.Unavailable, "could not serialize response: %v", err)
	}

	if err := stream.Send(resp); err != nil {
		//log.WithError(err).Error("Failed to send X.509 SVID response")
		return err
	}

	return nil
}

func composeX509SVIDBySelectors(update *cache.WorkloadUpdate) (*privilegedv1.FetchX509SVIDBySelectorsResponse, error) {
	resp := new(privilegedv1.FetchX509SVIDBySelectorsResponse)
	resp.Svids = []*privilegedv1.X509SVID{}

	bundle := marshalBundle(update.Bundle.RootCAs())

	for _, identity := range update.Identities {
		// TODO:  it doesn't work and always prints "false"
		//fmt.Printf("processing id %s, %t\n", identity.Entry.SpiffeId, identity.Entry.Admin)
		// Do not send admin nor downstream SVIDs to the caller
		if identity.Entry.Admin || identity.Entry.Downstream {
			continue
		}

		id, _ := idutil.IDProtoFromString(identity.Entry.SpiffeId)

		keyData, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("marshal key for %v: %w", id, err)
		}

		svid := &privilegedv1.X509SVID{
			Id:          id,
			X509Svid:    x509util.DERFromCertificates(identity.SVID),
			X509SvidKey: keyData,
			Bundle:      bundle,
		}

		resp.Svids = append(resp.Svids, svid)
	}

	// Send federated bundles only if there is any svid
	if len(resp.Svids) != 0 {
		resp.FederatedBundles = make(map[string][]byte)

		for td, federatedBundle := range update.FederatedBundles {
			resp.FederatedBundles[td.IDString()] = marshalBundle(federatedBundle.RootCAs())
		}
	}

	return resp, nil
}

func marshalBundle(certs []*x509.Certificate) []byte {
	bundle := []byte{}
	for _, c := range certs {
		bundle = append(bundle, c.Raw...)
	}
	return bundle
}

//go:build linux

package gatewaybootstrap

import (
	"context"
	"database/sql"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Source-owned maintenance, independent of every SSR/list/cache read. A session
// advisory lease and last observation fence duplicate collectors across engines.
// Only explicitly deployed protected profiles are enumerated, never the ordinary
// account scheduler or its credential/Extra usage projections.
func runPrivateProviderQuota(ctx context.Context, db *sql.DB, c Config, gateway *service.OpenAIGatewayService, custody *service.GatewayNativeCredentialCustody, oauth *privateOAuth) {
	collector := service.NewGatewayProviderQuotaCollector(nil)
	cache := repository.NewGatewayAccountLimitsRepositoryV2(db)
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		seenConsumers := map[string]bool{}
		for _, peer := range c.Peers {
			if peer.Role != "management" || seenConsumers[peer.ConsumerID] {
				continue
			}
			seenConsumers[peer.ConsumerID] = true
			consumerCtx, consumerErr := service.WithGatewayNativeConsumer(ctx, peer.ConsumerID)
			if consumerErr != nil {
				continue
			}
			for _, candidate := range c.CodingPlans {
				rows, err := db.QueryContext(ctx, `SELECT id,created_at,extra->>'gateway_generation_v1',extra->'gateway_credential_scope_v1'->>'consumer',extra->'gateway_credential_scope_v1'->>'owner',extra->'gateway_credential_scope_v1'->>'account'
 FROM accounts WHERE deleted_at IS NULL AND status='active' AND platform='openai' AND type='apikey'
 AND extra->>'gateway_profile_v1'=$1 AND credentials->>'base_url'=$2 AND extra->>'gateway_model_v1'=$3
 AND extra->'gateway_credential_scope_v1'->>'consumer'=$4
 ORDER BY id LIMIT 10000`, candidate.ProfileID, candidate.Profile.BaseURL, candidate.Profile.Model, peer.ConsumerID)
				if err != nil {
					continue
				}
				var accounts []service.GatewayNativeOAuthPhysical
				for rows.Next() {
					var p service.GatewayNativeOAuthPhysical
					if rows.Scan(&p.Route.AccountID, &p.Route.CreatedAt, &p.Route.Generation, &p.Scope.Consumer, &p.Scope.Owner, &p.Scope.Account) != nil {
						continue
					}
					p.Scope.Generation = p.Route.Generation
					p.Scope.Purpose = service.GatewayCredentialPurpose
					p.Route.Profile = candidate.ProfileID
					p.Route.BaseURL = candidate.Profile.BaseURL
					p.Route.Model = candidate.Profile.Model
					accounts = append(accounts, p)
				}
				_ = rows.Close()
				for _, p := range accounts {
					collectPrivateQuotaInfo(ctx, db, p, func(bounded context.Context) (service.GatewayProviderQuotaObservation, error) {
						var observation service.GatewayProviderQuotaObservation
						err := gateway.WithGatewayNativeQuotaCredential(bounded, p.Scope, p.Route, custody, func(key []byte, _ service.GatewayNativeOAuthPhysical) error {
							var e error
							observation, e = collector.FetchWithAccountInfo(bounded, service.GatewayAccountLimitsProviderV2(p.Route.Profile), key)
							return e
						})
						return observation, err
					}, cache)
				}
			}
			if c.Grok != nil && oauth != nil && oauth.grok != nil {
				accounts, err := oauth.grok.ListQuotaAccounts(consumerCtx)
				if err == nil {
					for _, p := range accounts {
						collectPrivateQuota(ctx, db, p, func(bounded context.Context) (service.GatewayAccountLimitsSnapshotV2, time.Time, error) {
							var snapshot service.GatewayAccountLimitsSnapshotV2
							var observed time.Time
							err := oauth.grok.WithQuotaCredential(bounded, p.Scope, p.Route, func(key []byte, current service.GatewayNativeOAuthPhysical) error {
								_ = current
								var e error
								snapshot, observed, e = collector.FetchObserved(bounded, "grok", key)
								return e
							})
							return snapshot, observed, err
						}, cache)
					}
				}
			}
		}
		timer.Reset(time.Minute)
	}
}
func collectPrivateQuota(ctx context.Context, db *sql.DB, p service.GatewayNativeOAuthPhysical, fetch func(context.Context) (service.GatewayAccountLimitsSnapshotV2, time.Time, error), cache service.GatewayAccountLimitsRepositoryV2) {
	collectPrivateQuotaInfo(ctx, db, p, func(ctx context.Context) (service.GatewayProviderQuotaObservation, error) {
		s, at, e := fetch(ctx)
		return service.GatewayProviderQuotaObservation{Limits: s, ObservedAt: at}, e
	}, cache)
}

func collectPrivateQuotaInfo(ctx context.Context, db *sql.DB, p service.GatewayNativeOAuthPhysical, fetch func(context.Context) (service.GatewayProviderQuotaObservation, error), cache service.GatewayAccountLimitsRepositoryV2) {
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := db.Conn(bounded)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	var acquired bool
	if conn.QueryRowContext(bounded, `SELECT pg_try_advisory_lock(219906,$1::integer)`, p.Route.AccountID).Scan(&acquired) != nil || !acquired {
		return
	}
	defer func() {
		release, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_, _ = conn.ExecContext(release, `SELECT pg_advisory_unlock(219906,$1::integer)`, p.Route.AccountID)
	}()
	var due bool
	if conn.QueryRowContext(bounded, `SELECT NOT EXISTS(SELECT 1 FROM gateway_account_limits_v2_snapshots WHERE account_id=$1 AND native_created_at=$2 AND generation=$3 AND (source_observations->>'plan_quota')::timestamptz>clock_timestamp()-interval '1 minute')`, p.Route.AccountID, p.Route.CreatedAt, p.Route.Generation).Scan(&due) != nil || !due {
		return
	}
	bounded, err = service.WithGatewayNativeConsumer(bounded, p.Scope.Consumer)
	if err != nil {
		return
	}
	bounded, err = service.WithGatewayNativeOAuthOwner(bounded, p.Scope.Owner)
	if err != nil {
		return
	}
	composite, ok := cache.(service.GatewayAccountQuotaInfoRepository)
	var order int64
	if p.Route.Profile == service.GatewayGLMCodingResponsesProfile || p.Route.Profile == service.GatewayMiniMaxMPlanResponsesProfile {
		if !ok {
			return
		}
		order, err = composite.ReserveGatewayAccountInfoOrder(bounded)
		if err != nil {
			return
		}
	}
	observation, err := fetch(bounded)
	if err != nil {
		return
	}
	if observation.Info != nil {
		if !ok {
			return
		}
		info := service.GatewayAccountInfoObservation{Source: "plan_quota", Order: order, CredentialRevision: p.CredentialRevision, Fields: *observation.Info}
		_ = composite.StoreGatewayQuotaAndInfo(bounded, p, observation.Limits, observation.ObservedAt, &info)
	} else {
		_ = cache.StoreGatewayAccountLimitsV2(bounded, p, observation.Limits, observation.ObservedAt)
	}
}

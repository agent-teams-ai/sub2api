//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func newEmailOAuthAutoAuthService(
	userRepo UserRepository,
	settings map[string]string,
	quotaRepo UserPlatformQuotaRepository,
) *AuthService {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret:                   "test-secret",
			ExpireHour:               1,
			AccessTokenExpireMinutes: 60,
			RefreshTokenExpireDays:   7,
		},
		Default: config.DefaultConfig{
			UserBalance:     3.5,
			UserConcurrency: 2,
		},
	}

	settingService := NewSettingService(&settingRepoStub{values: settings}, cfg)

	return NewAuthService(
		nil, // entClient — nil, updateUserSignupSource early return
		userRepo,
		nil, // redeemRepo — invitationCode="" 时不触发
		&refreshTokenCacheStub{},
		cfg,
		settingService,
		nil, // emailService
		nil, // turnstileService
		nil, // emailQueueService
		nil, // promoService
		nil, // defaultSubAssigner — nil, assignSubscriptions early return
		nil, // affiliateService — nil, bindOAuthAffiliate early return
		quotaRepo,
	)
}

func TestEmailOAuthAuto_SnapshotsPlatformQuotaDefaults(t *testing.T) {
	userRepo := &userRepoStub{nextID: 88}
	quotaRepo := &userPlatformQuotaRepoStub{}

	svc := newEmailOAuthAutoAuthService(
		userRepo,
		map[string]string{
			SettingKeyRegistrationEnabled:   "true",
			SettingKeyDefaultPlatformQuotas: `{"gemini": {"monthly": 100.0}}`,
		},
		quotaRepo,
	)

	user, err := svc.createEmailOAuthUser(
		context.Background(),
		"newoauth@example.com",
		"newoauth",
		"github",
		"", // invitationCode
		"", // affiliateCode
	)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, int64(88), user.ID)

	require.Len(t, quotaRepo.bulkInsertCalls, 1, "createEmailOAuthUser must snapshot platform quotas via BulkInsertInitial")

	records := quotaRepo.bulkInsertCalls[0]
	require.Len(t, records, 1, "only platforms with a configured limit get a row")
	var geminiRecord *UserPlatformQuotaRecord
	for i := range records {
		if records[i].Platform == "gemini" {
			geminiRecord = &records[i]
			break
		}
	}
	require.NotNil(t, geminiRecord, "expected gemini platform record")
	require.NotNil(t, geminiRecord.MonthlyLimitUSD)
	require.InDelta(t, 100.0, *geminiRecord.MonthlyLimitUSD, 0.0001)
}

func TestEmailOAuthAuto_RespectsDomainQuotaAtCreation(t *testing.T) {
	ctx := context.Background()
	repo := &userRepoStub{nextID: 120, domainCounts: map[string]int{"custom.example": 0}}
	svc := newEmailOAuthAutoAuthService(repo, map[string]string{
		SettingKeyRegistrationEnabled:                 "true",
		SettingKeyRegistrationEmailSuffixWhitelist:    `["@example.com"]`,
		SettingKeyRegistrationEmailDomainQuotaEnabled: "true",
	}, nil)
	first, err := svc.createEmailOAuthUser(ctx, "first@custom.example", "first", "github", "", "")
	require.NoError(t, err)
	require.NotNil(t, first)
	require.Equal(t, 1, repo.domainLimitedCreates, "OAuth creation must use the domain-limited atomic insertion")
	require.Equal(t, 1, repo.guardedCreates)

	// Emulate an existing registration in the same domain as a second identity.
	repo.domainCounts["custom.example"] = 1
	second, err := svc.createEmailOAuthUser(ctx, "second@custom.example", "second", "github", "", "")
	require.Nil(t, second)
	require.ErrorIs(t, err, ErrEmailDomainRegistrationLimit)
	require.Equal(t, 1, repo.guardedCreates)
}

func TestEmailOAuthAuto_RejectsOutsideWhitelistWithoutQuota(t *testing.T) {
	repo := &userRepoStub{nextID: 121}
	svc := newEmailOAuthAutoAuthService(repo, map[string]string{
		SettingKeyRegistrationEnabled:                 "true",
		SettingKeyRegistrationEmailSuffixWhitelist:    `["@example.com"]`,
		SettingKeyRegistrationEmailDomainQuotaEnabled: "false",
	}, nil)
	user, err := svc.createEmailOAuthUser(context.Background(), "first@custom.example", "first", "github", "", "")
	require.Nil(t, user)
	require.ErrorIs(t, err, ErrEmailSuffixNotAllowed)
	require.Empty(t, repo.created)
}

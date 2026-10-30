package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/usagestats"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestUsageUnrestrictedIncludesWeeklyWindowStart(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/usage", nil)

	weeklyWindowStart := time.Date(2026, time.July, 13, 0, 30, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	c.Set(string(middleware.ContextKeySubscription), &service.UserSubscription{
		WeeklyWindowStart: &weeklyWindowStart,
	})

	handler := &GatewayHandler{}
	handler.usageUnrestricted(
		c,
		context.Background(),
		&service.APIKey{Group: &service.Group{
			Name:             "Weekly plan",
			SubscriptionType: service.SubscriptionTypeSubscription,
		}},
		middleware.AuthSubject{},
		nil,
		nil,
		nil,
	)

	require.Equal(t, http.StatusOK, recorder.Code)
	var response struct {
		Subscription struct {
			WeeklyWindowStart *time.Time `json:"weekly_window_start"`
		} `json:"subscription"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.NotNil(t, response.Subscription.WeeklyWindowStart)
	require.True(t, weeklyWindowStart.Equal(*response.Subscription.WeeklyWindowStart))
}

// Embed the repository contract so only the Usage endpoint's three reads need fixtures.
type gatewayUsageContractRepo struct {
	service.UsageLogRepository
	stats     []usagestats.ModelStat
	err       error
	apiKeyID  int64
	startTime time.Time
	endTime   time.Time
}

func (r *gatewayUsageContractRepo) GetAPIKeyDashboardStats(context.Context, int64) (*usagestats.UserDashboardStats, error) {
	return nil, nil
}

func (r *gatewayUsageContractRepo) GetUsageTrendWithFilters(context.Context, time.Time, time.Time, string, int64, int64, int64, int64, string, *int16, *bool, *int8) ([]usagestats.TrendDataPoint, error) {
	return nil, nil
}

func (r *gatewayUsageContractRepo) GetModelStatsWithFilters(_ context.Context, start, end time.Time, _ int64, apiKeyID int64, _ int64, _ int64, _ *int16, _ *bool, _ *int8) ([]usagestats.ModelStat, error) {
	r.apiKeyID, r.startTime, r.endTime = apiKeyID, start, end
	return r.stats, r.err
}

func TestUsageModelStatsContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, quotaLimited := range []bool{false, true} {
		mode := "subscription"
		if quotaLimited {
			mode = "quota"
		}
		for _, tc := range []struct {
			name  string
			stats []usagestats.ModelStat
			err   error
		}{
			{name: "nil result"},
			{name: "empty result", stats: []usagestats.ModelStat{}},
			{name: "populated result", stats: []usagestats.ModelStat{{Model: "test-model", Requests: 3, Cost: 0.5, ActualCost: 0.25}}},
			{name: "query error", err: errors.New("private-database-error")},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				repo := &gatewayUsageContractRepo{stats: tc.stats, err: tc.err}
				handler := &GatewayHandler{usageService: service.NewUsageService(repo, nil, nil, nil)}
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodGet, "/v1/usage?start_date=2026-10-20&end_date=2026-10-20", nil)
				key := &service.APIKey{ID: 73, UserID: 42, Status: service.StatusAPIKeyActive, Group: &service.Group{SubscriptionType: service.SubscriptionTypeSubscription}}
				if quotaLimited {
					key.Quota = 10
				}
				c.Set(string(middleware.ContextKeyAPIKey), key)
				c.Set(string(middleware.ContextKeyUser), middleware.AuthSubject{UserID: key.UserID})
				handler.Usage(c)
				require.Equal(t, key.ID, repo.apiKeyID)
				require.Equal(t, "2026-10-20", repo.startTime.Format("2006-01-02"))
				require.Equal(t, "2026-10-21", repo.endTime.Format("2006-01-02"))
				var response map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
				if tc.err != nil {
					require.Equal(t, http.StatusBadGateway, recorder.Code)
					require.NotContains(t, response, "model_stats")
					require.Contains(t, response, "error")
					require.NotContains(t, recorder.Body.String(), tc.err.Error())
					return
				}
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Contains(t, response, "model_stats")
				if len(tc.stats) == 0 {
					require.JSONEq(t, "[]", string(response["model_stats"]))
				} else {
					var stats []usagestats.ModelStat
					require.NoError(t, json.Unmarshal(response["model_stats"], &stats))
					require.Equal(t, tc.stats, stats)
				}
			})
		}
	}
}

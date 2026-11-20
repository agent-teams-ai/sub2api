package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/adminaccess"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *OpenAIOAuthHandler) scopedOpenAIAllowed(c *gin.Context, id int64, action string, parent bool) bool {
	if adminaccess.RestrictedFromContext(c.Request.Context()) == nil {
		return true
	}
	_, ok := scopedAuthorizedAccount(c, h.adminService, id, action, parent)
	return ok
}

func (h *OpenAIOAuthHandler) scopedOpenAIHasPermission(c *gin.Context, id int64, action string, parent bool) bool {
	_, allowed := scopedAccountPermitted(c.Request.Context(), h.adminService, id, action, parent)
	return allowed
}

func scopedOpenAIError(c *gin.Context, err error) {
	if adminaccess.RestrictedFromContext(c.Request.Context()) != nil {
		if errors.Is(err, service.ErrSparkShadowResetNotSupported) {
			// Permanent shadow-account restriction: do not describe it as a retryable busy state.
			response.Error(c, http.StatusConflict, "影子账户不支持额度重置，请直接操作母账户")
			return
		}
		scopedAdminAccountError(c, err)
		return
	}
	response.ErrorFrom(c, err)
}

func (h *OpenAIOAuthHandler) scopedQuotaDTO(c *gin.Context, id int64, u *service.OpenAIQuotaUsage) *service.OpenAIQuotaUsage {
	if u == nil {
		return nil
	}
	safe := *u
	p := adminaccess.RestrictedFromContext(c.Request.Context())
	if p == nil {
		return &safe
	}
	identity := h.scopedOpenAIHasPermission(c, id, "accounts.identity.read", true)
	if !identity {
		safe.UserID = ""
		safe.AccountID = ""
		safe.Email = ""
		safe.PlanType = ""
	}
	return &safe
}

func (h *OpenAIOAuthHandler) scopedOpenAIQuota(c *gin.Context, refresh bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "账户 ID 无效")
		return
	}
	if !h.scopedOpenAIAllowed(c, id, "openai.quota.read", true) {
		return
	}
	if h.quotaService == nil {
		response.Error(c, 503, "账户额度服务不可用")
		return
	}
	u, err := h.quotaService.QueryUsage(c.Request.Context(), id)
	if err != nil {
		scopedOpenAIError(c, err)
		return
	}
	if u == nil {
		response.Error(c, 502, "账户额度查询失败")
		return
	}
	safe := h.scopedQuotaDTO(c, id, u)
	// 读取只更新展示快照，绝不通知可能消耗重置次数的自动任务。
	if !refresh {
		response.Success(c, safe)
		return
	}
	result := openAIQuotaRefreshResponse{OpenAIQuotaUsage: *safe}
	if err := h.quotaService.CacheCreditsSnapshot(c.Request.Context(), id, safe); err != nil {
		slog.Warn("scoped openai credits snapshot persistence failed", "account_id", id, "error", err)
	} else {
		result.CreditsCachePersisted = true
	}
	if err := h.quotaService.CacheResetCreditsSnapshot(c.Request.Context(), id, safe.RateLimitResetCredits); err != nil {
		slog.Warn("scoped openai reset credits snapshot persistence failed", "account_id", id, "error", err)
	} else {
		result.CachePersisted = true
	}
	response.Success(c, result)
}

func (h *OpenAIOAuthHandler) scopedReferralDTO(c *gin.Context, e *service.OpenAIReferralEligibility) *service.OpenAIReferralEligibility {
	if e == nil || adminaccess.RestrictedFromContext(c.Request.Context()) == nil {
		return e
	}
	// 邀请资格只展示容量和流程字段，不回传上游自由文本及收件人资料。
	return &service.OpenAIReferralEligibility{ShouldShow: e.ShouldShow, RemainingSendCapacity: e.RemainingSendCapacity, RemainingRewardCapacity: e.RemainingRewardCapacity, RequiresExplicitConfirmation: e.RequiresExplicitConfirmation, OfferID: e.OfferID, ProgramID: e.ProgramID, AvailableInvites: e.AvailableInvites, FetchedAt: e.FetchedAt}
}

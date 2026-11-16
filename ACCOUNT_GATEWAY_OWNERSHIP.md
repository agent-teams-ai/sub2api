# Account Gateway ownership rules

This fork is the single owner of provider logic for Account Gateway.

- Provider HTTP, parsing, protocol codecs, model catalogs and request admission live here. The Gateway (`agent-teams-ai/account-gateway`) keeps contracts, identity, fences and policy; ReviewRouter only consumes contracts.
- Reuse existing Sub2API code (`backend/internal/pkg/*`, `backend/internal/service/*`) before writing new code. The Gateway and ReviewRouter must not copy provider logic; if a capability is missing, extend this fork.
- Each protected profile has exactly one qualified model catalog source here. A model joins a catalog only with evidence it belongs to the plan (provider documentation or real qualification), never because an upstream list returned it.
- The private dispatch seam is the only credential decode boundary. Catalog reads never decrypt keys.

Design and rationale: [ReviewRouter doc 64](https://github.com/777genius/review-router-ai/blob/main/ai-docs/architecture/64-gateway-native-ownership-and-model-catalog.md).

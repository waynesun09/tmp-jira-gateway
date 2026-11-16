// Package apierr lists every error the gateway returns. Each has a fixed
// status, a stable code and a fixed message; none carries request or
// upstream content. The body is {"error": Message, "code": Code}.
package apierr

// E is one gateway error.
type E struct {
	Status  int
	Code    string
	Message string
}

// Stable codes. Callers branch on these, not on the message.
const (
	CodeUnauthenticated    = "unauthenticated"
	CodeNotGranted         = "not_granted"
	CodeEndpointNotAllowed = "endpoint_not_allowed"
	CodeQueryNotAllowed    = "query_not_allowed"
	CodeJQLGrammar         = "jql_grammar"
	CodeBodyNotAllowed     = "body_not_allowed"
	CodeUpstreamAuth       = "upstream_auth"
	CodeUpstreamError      = "upstream_error"
)

var (
	Unauthenticated = E{401, CodeUnauthenticated, "unauthorized"}
	// NotGranted covers every grant refusal: no grant, another cloud id,
	// a project outside the grant, a read grant on a write call, and a
	// pre-flight that fails or finds the issue elsewhere (a moved issue
	// cannot be told from one that was never granted).
	NotGranted         = E{403, CodeNotGranted, "not granted"}
	EndpointNotAllowed = E{403, CodeEndpointNotAllowed, "endpoint not allowed"}
	QueryNotAllowed    = E{403, CodeQueryNotAllowed, "query not allowed"}
	JQLGrammar         = E{403, CodeJQLGrammar, "jql outside the accepted grammar"}
	BodyNotAllowed     = E{403, CodeBodyNotAllowed, "request body not allowed"}
	RequestTooLarge    = E{413, CodeBodyNotAllowed, "request too large"}

	// UpstreamAuth: Atlassian refused the gateway's own credential (the
	// token endpoint rejected the client, or Jira answered 401 twice).
	// Retrying does not help.
	UpstreamAuth        = E{502, CodeUpstreamAuth, "upstream authentication failed"}
	UpstreamUnavailable = E{502, CodeUpstreamError, "upstream unavailable"}
	UpstreamTooLarge    = E{502, CodeUpstreamError, "upstream response too large"}
	UpstreamRedirect    = E{502, CodeUpstreamError, "upstream redirect"}
	UpstreamUndecodable = E{502, CodeUpstreamError, "upstream response not decodable"}
	UpstreamRefused     = E{502, CodeUpstreamError, "upstream refused the call"}
	// GatewayBusy: no response-filter slot freed up in time.
	GatewayBusy = E{503, CodeUpstreamError, "gateway busy"}
	// UpstreamFailed replaces a Jira 5xx.
	UpstreamFailed = E{502, CodeUpstreamError, "upstream error"}
)

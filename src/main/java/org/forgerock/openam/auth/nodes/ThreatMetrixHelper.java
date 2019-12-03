package org.forgerock.openam.auth.nodes;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;

class ThreatMetrixHelper {
    static final String ORG_ID = "org_id";
    static final String API_KEY = "api_key";
    static final String SESSION_ID = "session_id";
    static final String SERVICE_TYPE = "service_type";
    static final String EVENT_TYPE = "event_type";
    static final String POLICY = "policy";
    static final String SESSION_QUERY_RESPONSE = "session_query_response";
    static final String UPDATE_RESPONSE = "update_response";
    static final String REVIEW_STATUS = "review_status";
    static final String POLICY_SCORE = "policy_score";
    static final String REASON_CODE = "reason_code";
    static final String NONE_TRIGGERED = "None Triggered";
    static final String TMX_SESSION_QUERY_PARAMETERS = "tmx_session_query_parameters";
    static final String REQUEST_ID = "request_id";
    static final String FINAL_REVIEW_STATUS = "final_review_status";
    static final String ACTION = "action";
    static final String UPDATE_REVIEW_STATUS = "update_review_status";
    static final String NOTES = "notes";
    static final String TAG_NAME = "tag_name";
    static final String TAG_CONTEXT = "tag_context";
    static final String LINE_OF_BUSINESS = "line_of_business";

    static JsonValue getSessionQueryResponse(TreeContext context) throws NodeProcessException {
        if (!context.sharedState.isDefined(SESSION_QUERY_RESPONSE)) {
            throw new NodeProcessException("Unable to find ThreatMetrix" + SESSION_QUERY_RESPONSE +
                                                   " in sharedState. Does the ThreatMetrix Session Query node precede" +
                                                   " this node and return a successful response?");
        }
        return context.sharedState.get(SESSION_QUERY_RESPONSE);
    }
}

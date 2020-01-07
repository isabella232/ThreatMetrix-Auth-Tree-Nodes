/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.http.protocol.Responses.noopExceptionFunction;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.ACTION;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.API_KEY;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.FINAL_REVIEW_STATUS;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.LINE_OF_BUSINESS;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.NOTES;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.ORG_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.REQUEST_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.TAG_CONTEXT;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.TAG_NAME;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.UPDATE_RESPONSE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.UPDATE_REVIEW_STATUS;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import org.apache.commons.lang.StringUtils;
import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;

import java.net.URISyntaxException;
import javax.inject.Inject;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = ThreatMetrixUpdateReviewNode.Config.class)
public class ThreatMetrixUpdateReviewNode extends SingleOutcomeNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;
    private final HttpClientHandler clientHandler;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The TMX API Key
         */
        @Attribute(order = 100)
        @Password
        char[] apiKey();

        /**
         * Indicates the value of the new status that the transaction should be updated to.
         */
        @Attribute(order = 200)
        default FinalReviewStatus finalReviewStatus() {
            return FinalReviewStatus.PASS;
        }

        /**
         * An optional notes parameter that allows you to append any notes such as why the review status is being
         * updated.
         */
        @Attribute(order = 300)
        default String notes() {
            return "";
        }

        /**
         * The Trust Tag Name from one of ThreatMetrix's predefined set of Global Trust Tags.
         */
        @Attribute(order = 400)
        default TrustTagName trustTagName() {
            return TrustTagName.NONE;
        }

        /**
         * The Trust Tag Context from one of ThreatMetrix's Predefined set of Contexts. This is mandatory if the tag
         * name is passed.
         */
        @Attribute(order = 500)
        default TrustTagContext trustTagContext() {
            return TrustTagContext.NONE;
        }

        /**
         * The Line of Business as specified by the customer
         */
        @Attribute(order = 600)
        default String lineOfBusiness() {
            return "";
        }

        /**
         * Update URI
         */
        @Attribute(order = 700)
        default String uri() {
            return "https://h-api.online-metrix.net/api/update";
        }


    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public ThreatMetrixUpdateReviewNode(@Assisted Config config, HttpClientHandler client) {
        this.config = config;
        this.clientHandler = client;
    }

    /**
     * A {@link Function} that handles a {@link Response} from an TMX Server
     * that returns the HTTP entity content as JsonValue, and throws an {@link NodeProcessException} if
     * the response is not successful (200 family status code).
     *
     * @return response entity as a JsonValue.
     */
    private static Function<Response, JsonValue, NodeProcessException> mapToJsonValue() {
        return response -> {
            try {
                if (!response.getStatus().isSuccessful()) {
                    throw response.getCause();
                }
                return json(response.getEntity().getJson());
            } catch (Exception e) {
                throw new NodeProcessException("Unable to process request. " + response.getEntity().toString(), e);
            }
        };
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;
        Request request;
        if (!sharedState.isDefined(ORG_ID) || !sharedState.isDefined(REQUEST_ID)) {
            throw new NodeProcessException(
                    "Either the TMX Org ID or the Request ID is not present in shared state. Please check " +
                            "configuration");
        }
        String requestId = sharedState.get(REQUEST_ID).asString();
        try {
            request = new Request().setUri(config.uri() + "?output_format=json");
        } catch (URISyntaxException e) {
            throw new NodeProcessException(e);
        }
        final Form form = new Form();
        form.add(ORG_ID, sharedState.get(ORG_ID).asString());
        form.add(API_KEY, String.valueOf(config.apiKey()));
        form.add(REQUEST_ID, requestId);
        form.add(ACTION, UPDATE_REVIEW_STATUS);
        if (!FinalReviewStatus.NONE.equals(config.finalReviewStatus())) {
            form.add(FINAL_REVIEW_STATUS, config.finalReviewStatus().toString());
        }
        if (StringUtils.isNotEmpty(config.notes())) {
            form.add(NOTES, config.notes());
        }
        if (config.trustTagName() != TrustTagName.NONE) {
            if (config.trustTagContext() == TrustTagContext.NONE) {
                throw new NodeProcessException(
                        "Trust Tag Name set to a value other than None, but Trust Tag Context is set to None. Please " +
                                "set a value for Trust Tag Context");
            }
            form.add(TAG_NAME, config.trustTagName().toString());
            form.add(TAG_CONTEXT, config.trustTagContext().toString());
        }
        if (StringUtils.isNotEmpty(config.lineOfBusiness())) {
            form.add(LINE_OF_BUSINESS, config.lineOfBusiness());
        }
        form.toRequestEntity(request);
        clientHandler.handle(new RootContext(), request)
                     .thenAlways(closeSilentlyAsync(request))
                     .then(closeSilently(mapToJsonValue()), noopExceptionFunction())
                     .then(storeResponse(sharedState));
        return goToNext().replaceSharedState(sharedState).build();
    }

    /**
     * Stores all the information received from an authentication or authorization server.
     *
     * @param sharedState JsonValue to store the response
     * @return Void when storage is complete.
     */
    private Function<JsonValue, Void, NodeProcessException> storeResponse(final JsonValue sharedState) {
        return response -> {
            // store the token response in the jwt token
            sharedState.put(UPDATE_RESPONSE, response);
            return null;
        };
    }

    /**
     * Restricts which output fields are returned based on the level of access that a customer has.
     * The service type is linked to an API Key and verified during a call. Generally, the most common service type
     * is session-policy
     */
    public enum ServiceType {
        /**
         * Returns IP and device related attributes in addition to policy details.
         */
        SESSION_POLICY("session-policy"),
        /**
         * Returns only device related attributes and values.
         */
        DEVICE("device"),
        /**
         * Returns only the device identifier.
         */
        DID("did"),
        /**
         * Returns only IP related attributes and values.
         */
        IP("ip"),
        /**
         * Returns device related attributes but no ip related attributes or policy information.
         */
        SESSION("session"),
        /**
         * Returns almost all of the above. Please note that All does not return every single attribute.
         */
        ALL("All"),
        /**
         * Returns almost all of the above. Please note that All does not return every single attribute.
         */
        THREE_DS("3ds");

        private String serviceType;

        ServiceType(String serviceType) {
            this.serviceType = serviceType;
        }

        @Override
        public String toString() {
            return serviceType;
        }
    }


    /**
     * Indicates the value of the new status that the transaction should be updated to.
     */
    public enum FinalReviewStatus {
        NONE("none"),
        PASS("pass"),
        REVIEW("review"),
        REJECT("reject");
        private String finalReviewStatus;

        FinalReviewStatus(String finalReviewStatus) {
            this.finalReviewStatus = finalReviewStatus;
        }

        @Override
        public String toString() {
            return finalReviewStatus;
        }
    }

    /**
     * The Trust Tag Name from one of ThreatMetrix's predefined set of Global Trust Tags.
     */
    public enum TrustTagName {
        NONE("NONE"),
        _LOGIN_PASSED("_LOGIN_PASSED"),
        _LOGIN_FAILED("_LOGIN_FAILED"),
        _AUTH_PASSED("_AUTH_PASSED"),
        _AUTH_FAILED("_AUTH_FAILED"),
        _ACCEPTED("_ACCEPTED"),
        _REJECTED("_REJECTED"),
        _FALSE_POSITIVE("_FALSE_POSITIVE"),
        _FALSE_NEGATIVE("_FALSE_NEGATIVE"),
        _REVIEWED("_REVIEWED"),
        _REVIEW_PASSED("_REVIEW_PASSED"),
        _REVIEW_FAILED("_REVIEW_FAILED"),
        _CHALLENGED("_CHALLENGED"),
        _CHALLENGE_FAILED("_CHALLENGE_FAILED"),
        _CHALLENGE_PASSED("_CHALLENGE_PASSED"),
        _FRAUD_PAYMENT("_FRAUD_PAYMENT"),
        _FRAUD_IDENTITY("_FRAUD_IDENTITY"),
        _FRAUD_BREACH("_FRAUD_BREACH"),
        _FRAUD_MONEY_LAUNDERING("_FRAUD_MONEY_LAUNDERING"),
        _FRAUD_MONEY_TRANSFER("_FRAUD_MONEY_TRANSFER"),
        _FRAUD_INTERNAL("_FRAUD_INTERNAL"),
        _FRAUD_MOTO("_FRAUD_MOTO"),
        _WATCH("_WATCH"),
        _COMPROMISED("_COMPROMISED"),
        _TRUSTED("_TRUSTED"),
        _PRIVILEGED("_PRIVILEGED"),
        _THREAT("_THREAT"),
        _LOCK("_LOCK"),
        _SELF_EXCLUDED("_SELF_EXCLUDED"),
        _FRAUD_CONF("_FRAUD_CONF"),
        _FRAUD_PROB("_FRAUD_PROB"),
        _TRUSTED_CONF("_TRUSTED_CONF"),
        _TRUSTED_PROB("_TRUSTED_PROB"),
        _LOAN_APP("_LOAN_APP"),
        _LOAN_FUND("_LOAN_FUND"),
        _LOAN_DEPOSIT("_LOAN_DEPOSIT");
        private String trustTagName;

        TrustTagName(String trustTagName) {
            this.trustTagName = trustTagName;
        }

        @Override
        public String toString() {
            return trustTagName;
        }
    }

    /**
     * The Trust Tag Context from one of ThreatMetrix's Predefined set of Contexts. This is mandatory if the tag name
     * is passed.
     */
    public enum TrustTagContext {
        NONE("NONE"),
        _A_CAPCH("_A_CAPCH"),
        _A_URPWD("_A_URPWD"),
        _A_BANK("_A_BANK"),
        _A_SMS("_A_SMS"),
        _A_VOICE("_A_VOICE"),
        _A_OTPS("_A_OTPS"),
        _A_OTPH("_A_OTPH"),
        _A_KBAMN("_A_KBAMN"),
        _A_KBAAV("_A_KBAAV"),
        _A_KBAMX("_A_KBAMX"),
        _A_BIOV("_A_BIOV"),
        _A_BIOF("_A_BIOF"),
        _A_BIO("_A_BIO"),
        _A_DOCUM("_A_DOCUM"),
        _A_EMAIL("_A_EMAIL"),
        _A_ADDRS("_A_ADDRS"),
        _A_CELL("_A_CELL"),
        _A_IDVER("_A_IDVER"),
        _A_ANLYS("_A_ANLYS"),
        _A_PAYMT("_A_PAYMT"),
        _A_SOC("_A_SOC"),
        _A_GEO("_A_GEO"),
        _I_BANK("_I_BANK"),
        _I_BROK("_I_BROK"),
        _I_NBFI("_I_NBFI"),
        _I_TELC("_I_TELC"),
        _I_UTIL("_I_UTIL"),
        _I_RESO("_I_RESO"),
        _I_SOCL("_I_SOCL"),
        _I_TRVL("_I_TRVL"),
        _I_ACCOM("_I_ACCOM"),
        _I_GAME("_I_GAME"),
        _I_DIGT("_I_DIGT"),
        _I_AUCT("_I_AUCT"),
        _I_CLSFD("_I_CLSFD"),
        _I_MRKT("_I_MRKT"),
        _I_ACCT("_I_ACCT"),
        _I_LEGAL("_I_LEGAL"),
        _I_HLTH("_I_HLTH"),
        _I_SAAS("_I_SAAS"),
        _I_GOV("_I_GOV"),
        _I_EDU("_I_EDU"),
        _P_ADDR("_P_ADDR"),
        _P_CARD("_P_CARD"),
        _P_FUNDS("_P_FUNDS"),
        _T_TOR("_T_TOR"),
        _T_BOT("_T_BOT"),
        _T_IPADD("_T_IPADD"),
        _T_GEOSP("_T_GEOSP"),
        _T_IDSPF("_T_IDSPF"),
        _T_DIDSP("_T_DIDSP"),
        _T_MALW("_T_MALW"),
        _T_MITM("_T_MITM");


        private String trustTagContext;

        TrustTagContext(String trustTagContext) {
            this.trustTagContext = trustTagContext;
        }

        @Override
        public String toString() {
            return trustTagContext;
        }
    }
}

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
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.API_KEY;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.EVENT_TYPE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.ORG_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.POLICY;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.REQUEST_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.SERVICE_TYPE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.SESSION_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.SESSION_QUERY_RESPONSE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.TMX_SESSION_QUERY_PARAMETERS;
import static org.forgerock.util.CloseSilentlyFunction.closeSilently;
import static org.forgerock.util.Closeables.closeSilentlyAsync;

import java.net.URISyntaxException;
import java.util.Map;

import javax.inject.Inject;

import org.forgerock.http.handler.HttpClientHandler;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutputState;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.services.context.RootContext;
import org.forgerock.util.Function;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;
import com.google.inject.assistedinject.Assisted;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = ThreatMetrixSessionQueryNode.Config.class, tags = {"risk"})
public class ThreatMetrixSessionQueryNode extends SingleOutcomeNode {

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
        @Attribute(order = 200)
        @Password
        char[] apiKey();

        /**
         * Restricts which output fields are returned based on the level of access that a customer has.
         * The service type is linked to an API Key and verified during a call. Generally, the most common service type
         * is session-policy
         */
        @Attribute(order = 300)
        default ServiceType serviceType() {
            return ServiceType.SESSION_POLICY;
        }

        /**
         * Specifies the type of transaction or event.
         */
        @Attribute(order = 400)
        default EventType eventType() {
            return EventType.LOGIN;
        }

        /**
         * Selects a policy to be used for the query.
         */
        @Attribute(order = 500)
        default String policy() {
            return "default";
        }

        /**
         * Session query URI
         */
        @Attribute(order = 600)
        default String uri() {
            return "https://h-api.online-metrix.net/api/session-query";
        }

        /**
         * Should shared state variables be added to request
         */
        @Attribute(order = 700)
        default boolean addSharedStateVariablesToRequest() {
            return false;
        }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     * @param config The service config.
     */
    @Inject
    public ThreatMetrixSessionQueryNode(@Assisted Config config, HttpClientHandler client) {
        this.config = config;
        this.clientHandler = client;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        JsonValue sharedState = context.sharedState;
        String sessionId = sharedState.get(SESSION_ID).asString();
        if (!sharedState.isDefined(ORG_ID) || !sharedState.isDefined(SESSION_ID)) {
            throw new NodeProcessException(
                    "Either the TMX Org ID or the Session ID is not present in shared state. Please check " +
                            "configuration");
        }
        Request request;
        try {
            request = new Request().setUri(config.uri() + "?output_format=json");
        } catch (URISyntaxException e) {
            throw new NodeProcessException(e);
        }
        final Form form = new Form();
        form.add(ORG_ID, sharedState.get(ORG_ID).asString());
        form.add(API_KEY, String.valueOf(config.apiKey()));
        form.add(SESSION_ID, sessionId);
        form.add(SERVICE_TYPE, config.serviceType().toString());
        form.add(EVENT_TYPE, config.eventType().toString());
        form.add(POLICY, config.policy());
        if (config.addSharedStateVariablesToRequest()) {
            Map<String, String> parameters = sharedState.get(TMX_SESSION_QUERY_PARAMETERS).asMap(String.class);
            for (Map.Entry<String, String> entry : parameters.entrySet()){
                form.add(entry.getKey(), entry.getValue());
            }
        }
        form.toRequestEntity(request);
        Promise tmxResponse = clientHandler.handle(new RootContext(), request)
                                           .thenAlways(closeSilentlyAsync(request))
                                           .then(closeSilently(mapToJsonValue()), noopExceptionFunction())
                                           .then(storeResponse(sharedState));

        try {
            tmxResponse.getOrThrow();
        } catch (Exception e) {
            logger.error("Unable to get TMX response for session: " + sessionId);
            throw new NodeProcessException(e);
        }

        return goToNext().replaceSharedState(sharedState).build();
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

    /**
     * Stores all the information received from an authentication or authorization server.
     *
     * @param sharedState JsonValue to store the response
     * @return Void when storage is complete.
     */
    private Function<JsonValue, Void, NodeProcessException> storeResponse(final JsonValue sharedState) {
        return response -> {
            // store the token response in the jwt token
            sharedState.put(SESSION_QUERY_RESPONSE, response);
            sharedState.put(REQUEST_ID, response.get(REQUEST_ID));
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

        private final String serviceType;
        ServiceType(String serviceType) {
            this.serviceType = serviceType;
        }

        @Override
        public String toString(){
            return serviceType;
        }
    }


    /**
     * Specifies the type of transaction or event.
     */
    public enum EventType {
        LOGIN("LOGIN"),
        PAYMENT("PAYMENT"),
        ACCOUNT_CREATION("ACCOUNT_CREATION"),
        TRANSFER("TRANSFER"),
        TRANSACTION_OTHER("TRANSACTION_OTHER"),
        AUCTION_BID("AUCTION_BID"),
        DETAILS_CHANGE("DETAILS_CHANGE"),
        ADD_LISTING("ADD_LISTING"),
        ACCOUNT_BALANCE("ACCOUNT_BALANCE"),
        TRANSACTION_HISTORY("TRANSACTION_HISTORY"),
        DIGITAL_DOWNLOAD("DIGITAL_DOWNLOAD"),
        DIGITAL_STREAM("DIGITAL_STREAM"),
        FAILED_LOGIN("FAILED_LOGIN"),
        DEPOSIT("DEPOSIT"),
        LOAN_ACCEPTANCE("LOAN_ACCEPTANCE"),
        CUSTOM_EVENT_TYPE("CUSTOM_EVENT_TYPE"),
        DEVICE_REGISTRATION("DEVICE_REGISTRATION"),
        AUTH_TOKEN("AUTH_TOKEN"),
        PASSWORD_RESET("PASSWORD_RESET"),
        INIT_AUTH("INIT_AUTH"),
        PRE_AUTHENTICATION("PRE_AUTHENTICATION"),
        ADD_PAYMENT_INSTRUMENT("ADD_PAYMENT_INSTRUMENT"),
        MANAGE_PAYMENT_INSTRUMENT("MANAGE_PAYMENT_INSTRUMENT"),
        VERIFY_PAYMENT_INSTRUMENT("VERIFY_PAYMENT_INSTRUMENT");
        private final String eventType;
        EventType(String eventType) {
            this.eventType = eventType;
        }

        @Override
        public String toString(){
            return eventType;
        }
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[]{new InputState(SESSION_ID, true), new InputState(ORG_ID, true), new InputState(
                TMX_SESSION_QUERY_PARAMETERS, false)};
    }

    @Override
    public OutputState[] getOutputs() {
        return new OutputState[]{new OutputState(SESSION_QUERY_RESPONSE, ImmutableMap.of("outcome", true)),
                new OutputState(REQUEST_ID, ImmutableMap.of("outcome", true))};
    }
}

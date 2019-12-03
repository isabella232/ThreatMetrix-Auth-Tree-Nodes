package org.forgerock.openam.auth.nodes;


import static java.util.Collections.emptyList;
import static org.forgerock.openam.auth.node.api.Action.goTo;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.NONE_TRIGGERED;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.REASON_CODE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.getSessionQueryResponse;

import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.inject.assistedinject.Assisted;

import java.util.List;
import java.util.stream.Collectors;
import javax.inject.Inject;

@Node.Metadata(outcomeProvider = ThreatMetrixReasonCodeNode.ThreatMetrixReasonCodeOutcomeProvider.class,
        configClass = ThreatMetrixReasonCodeNode.Config.class)
public class ThreatMetrixReasonCodeNode implements Node {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ThreatMetrixReasonCodeNode";
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The list of possible outcomes.
         *
         * @return The possible outcomes.
         */
        @Attribute(order = 100)
        List<String> reasonCodeOutcomes();

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public ThreatMetrixReasonCodeNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        JsonValue sessionQueryResponse = getSessionQueryResponse(context);
        List<String> reasonCodes = sessionQueryResponse.get(REASON_CODE).asList(String.class);
        if (null == reasonCodes) {
            return goTo(NONE_TRIGGERED).build();
        }
        List<String> outcomes = config.reasonCodeOutcomes();
        for (String outcome : outcomes) {
            if (reasonCodes.contains(outcome)) {
                return goTo(outcome).build();
            }
        }
        return goTo(NONE_TRIGGERED).build();
    }


    /**
     * Defines the possible outcomes from this ThreatMetrix Reason Code Node.
     */
    public static class ThreatMetrixReasonCodeOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            try {
                List<Outcome> outcomes = nodeAttributes.get("reasonCodeOutcomes").required()
                                                       .asList(String.class)
                                                       .stream()
                                                       .map(outcome -> new Outcome(outcome, outcome))
                                                       .collect(Collectors.toList());
                outcomes.add(new Outcome(NONE_TRIGGERED, NONE_TRIGGERED));
                return outcomes;
            } catch (JsonValueException e) {
                return emptyList();
            }
        }
    }
}

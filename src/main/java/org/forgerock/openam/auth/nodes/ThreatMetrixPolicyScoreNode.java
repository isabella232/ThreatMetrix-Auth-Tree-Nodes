package org.forgerock.openam.auth.nodes;


import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.POLICY_SCORE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.getSessionQueryResponse;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;

import java.util.List;
import java.util.ResourceBundle;
import javax.inject.Inject;

@Node.Metadata(outcomeProvider = ThreatMetrixPolicyScoreNode.ThreatMetrixPolicyScoreOutcomeProvider.class,
        configClass = ThreatMetrixPolicyScoreNode.Config.class)
public class ThreatMetrixPolicyScoreNode implements Node {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ThreatMetrixPolicyScoreNode";
    private Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * Policy Score Threshold
         */
        @Attribute(order = 100)
        default int policyScoreThreshold() {
            return 0;
        }

    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public ThreatMetrixPolicyScoreNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        JsonValue sessionQueryResponse = getSessionQueryResponse(context);
        int policyScore = Integer.parseInt(sessionQueryResponse.get(POLICY_SCORE).asString());
        if (policyScore >= config.policyScoreThreshold()) {
            return Action.goTo(ThreatMetrixPolicyScoreOutcome.GREATER_THAN_OR_EQUAL.name()).build();
        }
        return Action.goTo(ThreatMetrixPolicyScoreOutcome.LESS_THAN.name()).build();

    }


    /**
     * The possible outcomes for the ThreatMetrix Policy Score Node.
     */
    private enum ThreatMetrixPolicyScoreOutcome {
        GREATER_THAN_OR_EQUAL,
        LESS_THAN;
    }


    /**
     * Defines the possible outcomes from this ThreatMetrix Policy Score Node
     */
    public static class ThreatMetrixPolicyScoreOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       ThreatMetrixPolicyScoreNode.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(ThreatMetrixPolicyScoreOutcome.GREATER_THAN_OR_EQUAL.name(),
                                bundle.getString("greaterThanOrEqualOutcome")),
                    new Outcome(ThreatMetrixPolicyScoreOutcome.LESS_THAN.name(), bundle.getString("lessThanOutcome")));
        }
    }
}

package org.forgerock.openam.auth.nodes;


import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.REVIEW_STATUS;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.SESSION_QUERY_RESPONSE;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.getSessionQueryResponse;

import org.apache.commons.lang.StringUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.util.i18n.PreferredLocales;

import com.google.common.collect.ImmutableList;

import java.util.List;
import java.util.ResourceBundle;

@Node.Metadata(outcomeProvider = ThreatMetrixReviewStatusNode.ThreatMetrixReviewStatusOutcomeProvider.class,
        configClass = ThreatMetrixReviewStatusNode.Config.class)
public class ThreatMetrixReviewStatusNode implements Node {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/ThreatMetrixReviewStatusNode";

    /**
     * Configuration for the node.
     */
    public interface Config {

    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        JsonValue sessionQueryResponse = getSessionQueryResponse(context);
        String reviewStatus = sessionQueryResponse.get(REVIEW_STATUS).asString();
        if (StringUtils.isEmpty(reviewStatus)) {
            throw new NodeProcessException("Unable to find " + REVIEW_STATUS + " in " + SESSION_QUERY_RESPONSE +
                                                   ". To use the ThreatMetrix Review Status Node, the ThreatMetrix " +
                                                   "service type must be: 3DS, " +
                                                   "All, Page-Integrity, Session or Session-Policy");
        }
        if (StringUtils.equals(ThreatMetrixReviewStatusOutcome.PASS.toString(), reviewStatus)) {
            return Action.goTo(ThreatMetrixReviewStatusOutcome.PASS.name()).build();
        } else if (StringUtils.equals(ThreatMetrixReviewStatusOutcome.CHALLENGE.toString(), reviewStatus)) {
            return Action.goTo(ThreatMetrixReviewStatusOutcome.CHALLENGE.name()).build();
        } else if (StringUtils.equals(ThreatMetrixReviewStatusOutcome.REVIEW.toString(), reviewStatus)) {
            return Action.goTo(ThreatMetrixReviewStatusOutcome.REVIEW.name()).build();
        }
        return Action.goTo(ThreatMetrixReviewStatusOutcome.REJECT.name()).build();
    }

    /**
     * The possible outcomes for the ThreatMetrix Review Status Node.
     */
    private enum ThreatMetrixReviewStatusOutcome {

        PASS("pass"),
        CHALLENGE("challenge"),
        REVIEW("review"),
        REJECT("reject");

        private String stringName;

        ThreatMetrixReviewStatusOutcome(String stringName) {
            this.stringName = stringName;
        }

        @Override
        public String toString() {
            return stringName;
        }
    }


    /**
     * Defines the possible outcomes from this ThreatMetrix Review Status Node.
     */
    public static class ThreatMetrixReviewStatusOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE,
                                                                       ThreatMetrixReviewStatusNode.class
                                                                               .getClassLoader());
            return ImmutableList.of(
                    new Outcome(ThreatMetrixReviewStatusOutcome.PASS.name(), bundle.getString("passOutcome")),
                    new Outcome(ThreatMetrixReviewStatusOutcome.CHALLENGE.name(), bundle.getString("challengeOutcome")),
                    new Outcome(ThreatMetrixReviewStatusOutcome.REVIEW.name(), bundle.getString("reviewOutcome")),
                    new Outcome(ThreatMetrixReviewStatusOutcome.REJECT.name(), bundle.getString("rejectOutcome")));
        }
    }
}

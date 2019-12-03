package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.ORG_ID;
import static org.forgerock.openam.auth.nodes.ThreatMetrixHelper.SESSION_ID;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;

import java.util.Arrays;
import java.util.UUID;
import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

/**
 * A node that checks to see if zero-page login headers have specified username and whether that username is in a group
 * permitted to use zero-page login headers.
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
        configClass      = ThreatMetrixProfilerNode.Config.class)
public class ThreatMetrixProfilerNode extends SingleOutcomeNode {
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {

        /**
         * The TMX Org Id
         */
        @Attribute(order = 100)
        String orgId();


        /**
         * The TMX PageId
         */
        @Attribute(order = 200)
        String pageId();

        /**
         * Profiler URI
         */
        @Attribute(order = 300)
        default String uri() {
            return "https://h.online-metrix.net/fp/yshd";
        }

        /**
         * Should the server generate the session ID
         */
        @Attribute(order = 400)
        default boolean useClientGeneratedSessionId() {
            return false;
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     * @param config The service config.
     */
    @Inject
    public ThreatMetrixProfilerNode(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) {
        JsonValue sharedState = context.sharedState;
        String sessionId;
        if (context.getCallback(TextOutputCallback.class).isPresent() && context.getCallback(HiddenValueCallback.class)
                                                                                .isPresent()) {
            if (config.useClientGeneratedSessionId()) {
                sessionId = context.getCallback(HiddenValueCallback.class).get().getValue();
                sharedState.put(SESSION_ID, sessionId);
            }
            return goToNext().replaceSharedState(sharedState.put(ORG_ID, config.orgId())).build();
        }


        sessionId = UUID.randomUUID().toString();
        sharedState.put(SESSION_ID, sessionId);

        String scriptSrc = String.format("%1$s.js?org_id=%2$s&session_id=%3$s&pageid=%4$s", config.uri(), config.orgId(),
                                         sessionId, config.pageId());
        String script = "var script = document.createElement('script');\n" +
                "script.type = 'text/javascript';\n" +
                "script.src = '%1$s'\n" +
                "document.getElementsByTagName('head')[0].appendChild(script);\n" +
                "var tmx_iframe = document.createElement('iframe');\n" +
                "tmx_iframe.src = '%1$s'\n" +
                "tmx_iframe.style.width = '100px';\n" +
                "tmx_iframe.style.height = '100px';\n" +
                "tmx_iframe.style.border = '0px';\n" +
                "tmx_iframe.style.position = 'absolute';\n" +
                "tmx_iframe.style.top = '-5000px';\n" +
                "document.getElementsByTagName('body')[0].appendChild(tmx_iframe);\n";

        return send(Arrays.asList(new ScriptTextOutputCallback(String.format(script, scriptSrc)),
                                  new HiddenValueCallback("ThreatMetrix Session ID"))).replaceSharedState(sharedState).build();
    }
}



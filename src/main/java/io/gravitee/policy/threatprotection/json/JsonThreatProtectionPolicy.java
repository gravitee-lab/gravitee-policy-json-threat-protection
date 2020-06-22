/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.threatprotection.json;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import io.gravitee.common.http.HttpHeaders;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;

import java.io.IOException;
import java.util.Collections;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonThreatProtectionPolicy {

    private final static String BAD_REQUEST = "Bad Request";
    private static final String JSON_THREAT_DETECTED_KEY = "JSON_THREAT_DETECTED";
    private static final String JSON_THREAT_MAX_DEPTH_KEY = "JSON_THREAT_MAX_DEPTH";
    private static final String JSON_THREAT_MAX_ENTRIES_KEY = "JSON_THREAT_MAX_ENTRIES";
    private static final String JSON_THREAT_MAX_NAME_LENGTH_KEY = "JSON_THREAT_MAX_NAME_LENGTH";
    private static final String JSON_THREAT_MAX_VALUE_LENGTH_KEY = "JSON_THREAT_MAX_VALUE_LENGTH";
    private static final String JSON_MAX_ARRAY_SIZE_KEY = "JSON_MAX_ARRAY_SIZE";

    private static final JsonFactory jsonFactory = new JsonFactory();

    private JsonThreatProtectionPolicyConfiguration configuration;

    public JsonThreatProtectionPolicy(JsonThreatProtectionPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequestContent
    public ReadWriteStream<Buffer> onRequestContent(Request request, PolicyChain policyChain) {

        if (request.headers().getOrDefault(HttpHeaders.CONTENT_TYPE, Collections.emptyList()).contains(MediaType.APPLICATION_JSON)) {
            // The policy is only applicable to json content type.
            return TransformableRequestStreamBuilder
                    .on(request)
                    .chain(policyChain)
                    .transform(buffer -> {

                        try{
                            validateJson(buffer.toString());
                        }catch (JsonException e) {
                            policyChain.streamFailWith(PolicyResult.failure(e.getKey(), HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN));
                        }catch (Exception e) {
                            policyChain.streamFailWith(PolicyResult.failure(JSON_THREAT_DETECTED_KEY, HttpStatusCode.BAD_REQUEST_400, BAD_REQUEST, MediaType.TEXT_PLAIN));
                        }

                        return buffer;
                    }).build();
        }

        return null;
    }

    public void validateJson(String json) throws JsonException {

        try {
            JsonParser parser = jsonFactory.createParser(json);
            int depth = 0, fieldCount = 0;

            JsonToken token;
            while ((token = parser.nextToken()) != null) {
                switch (token) {
                    case START_OBJECT:
                        depth++;
                        validateDepth(depth);
                        break;
                    case END_OBJECT:
                        depth--;
                        break;
                    case START_ARRAY:
                        validateArray(parser);
                        break;
                    case FIELD_NAME:
                        validateFieldCount(++fieldCount);
                        validateName(parser.getCurrentName());
                        break;
                    case VALUE_STRING:
                        validateValue(parser.getText());
                        break;
                }
            }
        } catch (IOException e) {
            throw new JsonException(JSON_THREAT_DETECTED_KEY, "Invalid json data");
        }
    }

    public void validateDepth(int depth) throws JsonException {

        if (configuration.hasMaxDepth() && depth > configuration.getMaxDepth()) {
            throw new JsonException(JSON_THREAT_MAX_DEPTH_KEY, "Max depth exceeded for json (max: " + configuration.getMaxDepth() + ")");
        }
    }

    public void validateFieldCount(int currentCount) throws JsonException {

        if (configuration.hasMaxEntries() && currentCount > configuration.getMaxEntries()) {
            throw new JsonException(JSON_THREAT_MAX_ENTRIES_KEY, "Max number of entries exceeded for json (max: " + configuration.getMaxEntries() + ")");
        }
    }

    private void validateName(String name) throws JsonException {

        if (configuration.hasMaxNameLength()) {
            if (name.length() > configuration.getMaxNameLength()) {
                throw new JsonException(JSON_THREAT_MAX_NAME_LENGTH_KEY, "Max length exceeded for field name [" + name + "] (max: " + configuration.getMaxNameLength() + ")");
            }
        }
    }

    private void validateValue(String value) throws JsonException {

        if (configuration.hasMaxValueLength()) {
            if (value.length() > configuration.getMaxValueLength()) {
                throw new JsonException(JSON_THREAT_MAX_VALUE_LENGTH_KEY, "Max length exceeded for field value [" + value + "] (max: " + configuration.getMaxValueLength() + ")");
            }
        }
    }

    private void validateArray(JsonParser parser) throws JsonException {

        JsonToken token;
        try {
            int entryCount = 0;
            while ((token = parser.nextToken()) != JsonToken.END_ARRAY) {
                if (token == JsonToken.VALUE_STRING) {
                    validateValue(parser.getText());
                }
                entryCount += 1;
                if (configuration.hasMaxArraySize() && entryCount > configuration.getMaxArraySize()) {
                    throw new JsonException(JSON_MAX_ARRAY_SIZE_KEY, "Max entry count exceeded for array (max: " + configuration.getMaxArraySize());
                }
            }
        } catch (IOException e) {
            throw new JsonException(JSON_THREAT_DETECTED_KEY, "Invalid json array.", e);
        }
    }
}

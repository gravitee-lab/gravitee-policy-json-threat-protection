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

import io.gravitee.policy.api.PolicyConfiguration;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public class JsonThreatProtectionPolicyConfiguration implements PolicyConfiguration {

    /**
     * Maximum number of json entries allowed in an object. Null or negative value should be considered as infinite.
     */
    private Integer maxEntries;

    /**
     * Maximum number of elements allowed in an array. Null or negative value should be considered as infinite.
     */
    private Integer maxArraySize;

    /**
     * Maximum depth of json structure. Null or negative value should be considered as infinite.
     */
    private Integer maxDepth ;

    /**
     * Maximum json field name length. Null or negative value should be considered as infinite.
     */
    private Integer maxNameLength;

    /**
     * Maximum json value length. Null or negative value should be considered as infinite.
     */
    private Integer maxValueLength;

    public boolean hasMaxEntries() {
        return maxEntries != null && maxEntries >= 0;
    }

    public boolean hasMaxArraySize() {
        return maxArraySize != null && maxArraySize >= 0;
    }

    public boolean hasMaxDepth() {
        return maxDepth != null && maxDepth >= 0;
    }

    public boolean hasMaxNameLength() {
        return maxNameLength != null && maxNameLength >= 0;
    }

    public boolean hasMaxValueLength() {
        return maxValueLength != null && maxValueLength >= 0;
    }

    public Integer getMaxEntries() {
        return maxEntries;
    }

    public void setMaxEntries(Integer maxEntries) {
        this.maxEntries = maxEntries;
    }

    public Integer getMaxArraySize() {
        return maxArraySize;
    }

    public void setMaxArraySize(Integer maxArraySize) {
        this.maxArraySize = maxArraySize;
    }

    public Integer getMaxDepth() {
        return maxDepth;
    }

    public void setMaxDepth(Integer maxDepth) {
        this.maxDepth = maxDepth;
    }

    public Integer getMaxNameLength() {
        return maxNameLength;
    }

    public void setMaxNameLength(Integer maxNameLength) {
        this.maxNameLength = maxNameLength;
    }

    public Integer getMaxValueLength() {
        return maxValueLength;
    }

    public void setMaxValueLength(Integer maxValueLength) {
        this.maxValueLength = maxValueLength;
    }
}

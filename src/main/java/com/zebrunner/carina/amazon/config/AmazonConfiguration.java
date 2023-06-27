package com.zebrunner.carina.amazon.config;

import com.zebrunner.carina.utils.config.Configuration;
import com.zebrunner.carina.utils.config.IParameter;

import java.util.Optional;

public final class AmazonConfiguration extends Configuration {

    public enum Parameter implements IParameter {

        S3_BUCKET_NAME("s3_bucket_name"),

        S3_REGION("s3_region"),

        ACCESS_KEY_ID("access_key_id") {
            @Override
            public boolean hidden() {
                return true;
            }
        },

        SECRET_KEY("secret_key") {
            @Override
            public boolean hidden() {
                return true;
            }
        };

        private final String key;

        Parameter(String key) {
            this.key = key;
        }

        public String getKey() {
            return key;
        }
    }

    @Override
    public String toString() {
        Optional<String> asString = asString(Parameter.values());
        if (asString.isEmpty()) {
            return "";
        }
        return "\n============= Amazon configuration ============\n" +
                asString.get();
    }
}

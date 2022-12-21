package com.zebrunner.carina.amazon;

import com.zebrunner.carina.commons.artifact.ArtifactManagerFactory;
import com.zebrunner.carina.commons.artifact.IArtifactManager;
import com.zebrunner.carina.commons.artifact.IArtifactManagerFactory;

import java.util.regex.Pattern;

@ArtifactManagerFactory
public class AmazonProviderFactory implements IArtifactManagerFactory {
    private static final Pattern AMAZON_S3_ENDPOINT_PATTERN = Pattern.compile("s3:\\/\\/([a-zA-Z-0-9][^\\/]*)\\/(.*)");

    @Override
    public boolean isSuitable(String url) {
        return AMAZON_S3_ENDPOINT_PATTERN.matcher(url).find();
    }

    @Override
    public IArtifactManager getInstance() {
        return AmazonS3Manager.getInstance();
    }
}

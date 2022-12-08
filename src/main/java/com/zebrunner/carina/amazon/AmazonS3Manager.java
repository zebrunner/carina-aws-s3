/*******************************************************************************
 * Copyright 2020-2022 Zebrunner Inc (https://www.zebrunner.com).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.zebrunner.carina.amazon;

import com.amazonaws.AmazonClientException;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.HttpMethod;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.AmazonS3URI;
import com.amazonaws.services.s3.model.DeleteObjectRequest;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.transfer.Download;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;
import com.zebrunner.carina.utils.Configuration;
import com.zebrunner.carina.utils.cloud.CloudManager;
import com.zebrunner.carina.utils.common.CommonUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.lang.invoke.MethodHandles;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AmazonS3Manager implements CloudManager {
    private static final Logger LOGGER = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());
    private static final Pattern S3_BUCKET_PATTERN = Pattern.compile("s3:\\/\\/([a-zA-Z-0-9][^\\/]*)\\/(.*)");
    private static volatile AmazonS3Manager instance = null;
    private AmazonS3 s3client = null;

    private AmazonS3Manager() {
    }

    public static synchronized AmazonS3Manager getInstance() {
        if (instance == null) {
            AmazonS3Manager amazonS3Manager = new AmazonS3Manager();

            AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
            String s3region = Configuration.get(Configuration.Parameter.S3_REGION);
            if (!s3region.isEmpty()) {
                builder.withRegion(Regions.fromName(s3region));
            }

            String accessKey = Configuration.getDecrypted(Configuration.Parameter.ACCESS_KEY_ID);
            String secretKey = Configuration.getDecrypted(Configuration.Parameter.SECRET_KEY);
            if (!accessKey.isEmpty() && !secretKey.isEmpty()) {
                BasicAWSCredentials creds = new BasicAWSCredentials(accessKey, secretKey);
                builder.withCredentials(new AWSStaticCredentialsProvider(creds)).build();
            }

            amazonS3Manager.s3client = builder.build();
            instance = amazonS3Manager;
        }
        return instance;
    }

    public AmazonS3 getClient() {
        return s3client;
    }

    @Override
    public boolean put(Path from, String to) throws FileNotFoundException {
        if (!ObjectUtils.allNotNull(from, to) || to.isEmpty()) {
            throw new IllegalArgumentException("Arguments cannot be null or empty.");
        }
        if (!Files.exists(from)) {
            throw new FileNotFoundException(String.format("File '%s' does not exist!", from));
        }
        boolean isSuccessful = false;
        AmazonS3URI amazonS3URI = new AmazonS3URI(to);
        try {
            LOGGER.debug("Uploading a new object to S3 from a file: {}", from);
            PutObjectRequest object = new PutObjectRequest(amazonS3URI.getBucket(), amazonS3URI.getKey(), from.toFile());
            this.s3client.putObject(object);
            LOGGER.debug("Uploaded to S3: '{}' with key '{}'", from, amazonS3URI.getKey());
            isSuccessful = true;
        } catch (AmazonServiceException ase) {
            LOGGER.error("Caught an AmazonServiceException, which "
                    + "means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.\n"
                    + "Error Message:    " + ase.getMessage() + "\n"
                    + "HTTP Status Code: " + ase.getStatusCode() + "\n"
                    + "AWS Error Code:   " + ase.getErrorCode() + "\n"
                    + "Error Type:       " + ase.getErrorType() + "\n"
                    + "Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            LOGGER.error("Caught an AmazonClientException, which "
                    + "means the client encountered "
                    + "an internal error while trying to "
                    + "communicate with S3, "
                    + "such as not being able to access the network.\n"
                    + "Error Message: " + ace.getMessage());
        } catch (Exception e) {
            LOGGER.error("Something went wrong when try to put artifact to the Amazon S3.", e);
        }
        return isSuccessful;
    }

    @Override
    public boolean download(String from, Path to) {
        if (!ObjectUtils.allNotNull(from, to) || from.isEmpty()) {
            throw new IllegalArgumentException("Arguments cannot be null or empty.");
        }
        boolean isSuccessful = false;
        AmazonS3URI amazonS3URI = new AmazonS3URI(from);
        LOGGER.info("App will be downloaded from s3.");
        LOGGER.info("[Bucket name: {}] [Key: {}] [File: {}].", amazonS3URI.getBucket(), amazonS3URI.getKey(), to.toAbsolutePath());

        Download appDownload = TransferManagerBuilder.standard()
                .withS3Client(this.s3client)
                .build()
                .download(amazonS3URI.getBucket(), amazonS3URI.getKey(), to.toFile());
        try {
            LOGGER.info("Transfer: {}", appDownload.getDescription());
            LOGGER.info("\t State: {}", appDownload.getState());
            LOGGER.info("\t Progress: ");
            // You can poll your transfer's status to check its progress
            while (!appDownload.isDone()) {
                LOGGER.info("\t\t transferred: {}%", (int) (appDownload.getProgress().getPercentTransferred() + 0.5));
                // fixme remove interval or add interval to method parameters
                CommonUtils.pause(1);
            }
            LOGGER.info("\t State: {}", appDownload.getState());
            isSuccessful = true;
        } catch (AmazonClientException e) {
            LOGGER.error("File wasn't downloaded from s3.", e);
        } catch (Exception e) {
            LOGGER.error("Something went wrong when try to download artifact from Amazon S3.", e);
        }
        return isSuccessful;
    }

    @Override
    public boolean delete(String url) {
        if (Objects.isNull(url) || url.isEmpty()) {
            throw new IllegalArgumentException("Argument cannot be null or empty");
        }
        boolean isSuccessful = false;
        AmazonS3URI amazonS3URI = new AmazonS3URI(url);
        try {
            this.s3client.deleteObject(new DeleteObjectRequest(amazonS3URI.getBucket(), amazonS3URI.getKey()));
            isSuccessful = true;
        } catch (AmazonServiceException ase) {
            LOGGER.error("Caught an AmazonServiceException, which "
                    + "means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.\n"
                    + "Error Message:    " + ase.getMessage() + "\n"
                    + "HTTP Status Code: " + ase.getStatusCode() + "\n"
                    + "AWS Error Code:   " + ase.getErrorCode() + "\n"
                    + "Error Type:       " + ase.getErrorType() + "\n"
                    + "Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            LOGGER.error("Caught an AmazonClientException.\nError Message: {}", ace.getMessage());
        } catch (Exception e) {
            LOGGER.error("Something went wrong when try to delete artifact from Amazon S3", e);
        }
        return isSuccessful;
    }

    @Override
    public String updateAppPath(String url) {
        if (Objects.isNull(url) || url.isEmpty()) {
            throw new IllegalArgumentException("Argument cannot be null or empty");
        }
        // get app path to be sure that we need(do not need) to download app
        // from s3 bucket
        Matcher matcher = S3_BUCKET_PATTERN.matcher(url);
        if (matcher.find()) {
            String bucketName = matcher.group(1);
            String key = matcher.group(2);
            Pattern pattern = Pattern.compile(key);

            // analyze if we have any pattern inside mobile_app to make extra
            // search in AWS
            int position = key.indexOf(".*");
            if (position > 0) {
                // /android/develop/dfgdfg.*/Mapmyrun.apk
                int slashPosition = key.substring(0, position).lastIndexOf("/");
                if (slashPosition > 0) {
                    key = key.substring(0, slashPosition);
                    S3ObjectSummary lastBuild = getLatestBuildArtifact(bucketName, key,
                            pattern);
                    key = lastBuild.getKey();
                }

            } else {
                key = get(bucketName, key).getKey();
            }
            LOGGER.info("next s3 app key will be used: {}", key);

            // generate presign url explicitly to register link as run artifact
            long hours = 72L * 1000 * 60 * 60; // generate presigned url for nearest 3 days
            return AmazonS3Manager.getInstance().generatePreSignUrl(bucketName, key, hours).toString();
        } else {
            throw new RuntimeException(String.format("Unable to parse '%s' path using S3 pattern", url));
        }
    }

    /**
     * Put any file to Amazon S3 storage.
     *
     * @param bucket S3 bucket name
     * @param key S3 storage path. Example: {@code DEMO/TestSuiteName/TestMethodName/file.txt}
     * @param filePath local storage path. Example: {@code C:/Temp/file.txt}
     *
     */
    public void put(String bucket, String key, String filePath) {
        put(bucket, key, filePath, null);
    }

    /**
     * Put any file to Amazon S3 storage.
     *
     * @param bucket S3 bucket name
     * @param key S3 storage path. Example: {@code DEMO/TestSuiteName/TestMethodName/file.txt}
     * @param filePath local storage path. Example: {@code C:/Temp/file.txt}
     * @param metadata custom tags metadata like name etc, see {@link ObjectMetadata}
     *
     */
    public void put(String bucket, String key, String filePath, ObjectMetadata metadata) {

        /*
         * if (mode != S3Mode.WRITE) {
         * if (mode == S3Mode.READ) {
         * LOGGER.warn("Unable to put data in READ mode!");
         * }
         * return;
         * }
         */

        if (key == null) {
            throw new RuntimeException("Key is null!");
        }
        if (key.isEmpty()) {
            throw new RuntimeException("Key is empty!");
        }

        if (filePath == null) {
            throw new RuntimeException("FilePath is null!");
        }
        if (filePath.isEmpty()) {
            throw new RuntimeException("FilePath is empty!");
        }

        File file = new File(filePath);
        if (!file.exists()) {
            throw new RuntimeException("File does not exist! " + filePath);
        }

        try {
            LOGGER.debug("Uploading a new object to S3 from a file: "
                    + filePath);

            PutObjectRequest object = new PutObjectRequest(bucket, key, file);
            if (metadata != null) {
                object.setMetadata(metadata);
            }

            s3client.putObject(object);
            LOGGER.debug("Uploaded to S3: '" + filePath + "' with key '" + key
                    + "'");

        } catch (AmazonServiceException ase) {
            LOGGER.error("Caught an AmazonServiceException, which "
                    + "means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.\n"
                    + "Error Message:    " + ase.getMessage() + "\n"
                    + "HTTP Status Code: " + ase.getStatusCode() + "\n"
                    + "AWS Error Code:   " + ase.getErrorCode() + "\n"
                    + "Error Type:       " + ase.getErrorType() + "\n"
                    + "Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            LOGGER.error("Caught an AmazonClientException, which "
                    + "means the client encountered "
                    + "an internal error while trying to "
                    + "communicate with S3, "
                    + "such as not being able to access the network.\n"
                    + "Error Message: " + ace.getMessage());
        }
    }

    /**
     * Get any file from Amazon S3 storage as S3Object.
     *
     * @param bucket S3 Bucket name.
     * @param key S3 storage path. Example: {@code DEMO/TestSuiteName/TestMethodName/file.txt}
     * @return see {@link S3Object}
     */
    public S3Object get(String bucket, String key) {
        // S3Object s3object = null;

        /*
         * if (mode != S3Mode.WRITE && mode != S3Mode.READ) {
         * throw new RuntimeException("Unable to get S3 object in OFF mode!");
         * }
         */

        if (bucket == null) {
            throw new RuntimeException("Bucket is null!");
        }
        if (bucket.isEmpty()) {
            throw new RuntimeException("Bucket is empty!");
        }

        if (key == null) {
            throw new RuntimeException("Key is null!");
        }
        if (key.isEmpty()) {
            throw new RuntimeException("Key is empty!");
        }

        try {
            LOGGER.info("Finding an s3object...");
            // TODO investigate possibility to add percentage of completed
            // downloading
            S3Object s3object = s3client.getObject(new GetObjectRequest(bucket,
                    key));
            LOGGER.info("Content-Type: "
                    + s3object.getObjectMetadata().getContentType());
            return s3object;
            /*
             * GetObjectRequest rangeObjectRequest = new GetObjectRequest(
             * bucketName, key); rangeObjectRequest.setRange(0, 10); S3Object
             * objectPortion = s3client.getObject(rangeObjectRequest);
             */
        } catch (AmazonServiceException ase) {
            LOGGER.error("Caught an AmazonServiceException, which "
                    + "means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.\n"
                    + "Error Message:    " + ase.getMessage() + "\n"
                    + "HTTP Status Code: " + ase.getStatusCode() + "\n"
                    + "AWS Error Code:   " + ase.getErrorCode() + "\n"
                    + "Error Type:       " + ase.getErrorType() + "\n"
                    + "Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            LOGGER.error("Caught an AmazonClientException, which "
                    + "means the client encountered "
                    + "an internal error while trying to "
                    + "communicate with S3, "
                    + "such as not being able to access the network.\n"
                    + "Error Message: " + ace.getMessage());
        }
        // TODO investigate pros and cons returning null
        throw new RuntimeException("Unable to download '" + key
                + "' from Amazon S3 bucket '" + bucket + "'");
    }

    /**
     * Delete file from Amazon S3 storage.
     *
     * @param bucket S3 Bucket name.
     * @param key S3 storage path. Example: {@code DEMO/TestSuiteName/TestMethodName/file.txt}
     */
    public void delete(String bucket, String key) {
        if (key == null) {
            throw new RuntimeException("Key is null!");
        }
        if (key.isEmpty()) {
            throw new RuntimeException("Key is empty!");
        }

        try {
            s3client.deleteObject(new DeleteObjectRequest(bucket, key));
        } catch (AmazonServiceException ase) {
            LOGGER.error("Caught an AmazonServiceException, which "
                    + "means your request made it "
                    + "to Amazon S3, but was rejected with an error response for some reason.\n"
                    + "Error Message:    " + ase.getMessage() + "\n"
                    + "HTTP Status Code: " + ase.getStatusCode() + "\n"
                    + "AWS Error Code:   " + ase.getErrorCode() + "\n"
                    + "Error Type:       " + ase.getErrorType() + "\n"
                    + "Request ID:       " + ase.getRequestId());
        } catch (AmazonClientException ace) {
            LOGGER.error("Caught an AmazonClientException.\n"
                    + "Error Message: " + ace.getMessage());
        }
    }

    /**
     * Get latest build artifact from Amazon S3 storage as S3Object.
     *
     * @param bucket S3 Bucket name.
     * @param key S3 storage path to your project. Example: {@code android/MyProject}
     * @param pattern pattern to find single build artifact Example: {@code .*prod-google-release.*}
     * @return see {@link S3ObjectSummary}
     */
    public S3ObjectSummary getLatestBuildArtifact(String bucket, String key, Pattern pattern) {
        if (pattern == null) {
            throw new RuntimeException("pattern is null!");
        }

        S3ObjectSummary latestBuild = null;

        ObjectListing objBuilds = s3client.listObjects(bucket, key);

        int i = 0;
        int limit = 100;
        boolean isTruncated = false;
        // by default S3 return only 1000 objects summary so need while cycle here
        do {
            LOGGER.info("looking for s3 artifact using iteration #" + i);

            for (S3ObjectSummary obj : objBuilds.getObjectSummaries()) {
                LOGGER.debug("Existing S3 artifact: " + obj.getKey());
                Matcher matcher = pattern.matcher(obj.getKey());
                if (matcher.find()) {
                    if (latestBuild == null) {
                        latestBuild = obj;
                    }

                    if (obj.getLastModified().after(latestBuild.getLastModified())) {
                        latestBuild = obj;
                    }
                }
            }
            isTruncated = objBuilds.isTruncated();
            objBuilds = s3client.listNextBatchOfObjects(objBuilds);
        } while (isTruncated && ++i < limit);

        if (latestBuild == null) {
            LOGGER.error("Unable to find S3 build artifact by pattern: " + pattern);
        } else {
            LOGGER.info("latest artifact: " + latestBuild.getKey());
        }
        return latestBuild;
    }

    /**
     * Method to download file from s3 to local file system
     *
     * @param bucketName AWS S3 bucket name
     * @param key (example: android/apkFolder/ApkName.apk)
     * @param file (local file name)
     */
    public void download(final String bucketName, final String key, final File file) {
        download(bucketName, key, file, 10);
    }

    /**
     * Method to download file from s3 to local file system
     *
     * @param bucketName AWS S3 bucket name
     * @param key (example: android/apkFolder/ApkName.apk)
     * @param file (local file name)
     * @param pollingInterval (polling interval in sec for S3 download status determination)
     */
    public void download(final String bucketName, final String key, final File file, long pollingInterval) {
        LOGGER.info("App will be downloaded from s3.");
        LOGGER.info("[Bucket name: {}] [Key: {}] [File: {}]", bucketName, key, file.getAbsolutePath());

        Download appDownload = TransferManagerBuilder.standard()
                .withS3Client(s3client)
                .build()
                .download(bucketName, key, file);
        try {
            LOGGER.info("Transfer: {}", appDownload.getDescription());
            LOGGER.info("\t State: {}", appDownload.getState());
            LOGGER.info("\t Progress: ");
            // You can poll your transfer's status to check its progress
            while (!appDownload.isDone()) {
                LOGGER.info("\t\t transferred: {}%", (int) (appDownload.getProgress().getPercentTransferred() + 0.5));
                CommonUtils.pause(pollingInterval);
            }
            LOGGER.info("\t State: {}", appDownload.getState());
        } catch (AmazonClientException e) {
            throw new RuntimeException("File wasn't downloaded from s3. See log: ".concat(e.getMessage()));
        }
    }

    /**
     * Method to generate pre-signed object URL to s3 object
     *
     * @param bucketName AWS S3 bucket name
     * @param key (example: {@code android/apkFolder/ApkName.apk})
     * @param ms espiration time in ms, i.e. 1 hour is 1000*60*60
     * @return url String pre-signed URL
     */
    public URL generatePreSignUrl(final String bucketName, final String key, long ms) {

        java.util.Date expiration = new java.util.Date();
        long msec = expiration.getTime();
        msec += ms;
        expiration.setTime(msec);

        GeneratePresignedUrlRequest generatePresignedUrlRequest = new GeneratePresignedUrlRequest(bucketName, key);
        generatePresignedUrlRequest.setMethod(HttpMethod.GET);
        generatePresignedUrlRequest.setExpiration(expiration);

        URL url = s3client.generatePresignedUrl(generatePresignedUrlRequest);
        return url;
    }

    /*
     * public void read(S3Object s3object) {
     * displayTextInputStream(s3object.getObjectContent()); }
     *
     * private void displayTextInputStream(InputStream input) { // Read one text
     * line at a time and display. LOGGER.info("File content is: ");
     * BufferedReader reader = new BufferedReader(new InputStreamReader(input));
     * while (true) { String line = null; try { line = reader.readLine(); }
     * catch (IOException e) { LOGGER.error("Failed to read file", e); } if
     * (line == null) break;
     *
     * System.out.println("    " + line); } }
     */
}

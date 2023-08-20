#!/usr/bin/bash

# Set the target directory
target_dir="$1"

# Informative message - Creating directory
echo -e "\e[96mCreating directory: $target_dir\e[0m"

# Create the target directory
mkdir "$target_dir"
cd "$target_dir"

# Informative message - Gathering URLs using waybackurls
echo -e "\e[96mGathering URLs using waybackurls...\e[0m"
waybackurls "$target_dir" >> urls.txt

# Informative message - Gathering URLs using katana
echo -e "\e[96mGathering URLs using katana...\e[0m"
katana -u "http://$target_dir/" 2> /dev/null >> urls.txt

# Informative message - Gathering URLs using gau
echo -e "\e[96mGathering URLs using gau...\e[0m"
gau "$target_dir" >> urls.txt

# Sort and remove duplicate URLs
echo -e "\e[96mSorting and removing duplicate URLs...\e[0m"
cat urls.txt | sort -u | tee final.txt > /dev/null

# Run uro on final.txt to extract Uniq URLs
echo -e "\e[96mExtracting uniq URLs...\e[0m"
cat final.txt | uro | tee uniq.txt > /dev/null

# Filter URLs for JavaScript files
echo -e "\e[96mFiltering URLs for JavaScript files...\e[0m"
cat uniq.txt | grep -E "\\.js" | tee result.txt > /dev/null

# Set the list of keywords
keywords=("password" "passwd" "pass" "pwd" "secret" "auth" "token" "authToken" "access_token" "refresh_token" "session_token" "api_key" "apiKey" "authKey" "apiSecret" "api_secret" "clientSecret" "client_secret" "serviceKey" "service_key" "dbUser" "dbUsername" "dbPassword" "dbHost" "dbPort" "dbConnectionString" "encrypt" "decrypt" "encryptionKey" "encryption_key" "socialSecurityNumber" "ssn" "creditCardNumber" "ccNumber" "personalIdentificationNumber" "pin" "private_key" "privatekey" "passphrase" "console.log" "alert" "debugger" "filePath" "directoryPath" "url" "endpoint" "api/v1" "api/v2" "api/v3" "api/v4" "api/v5" "api/v6" "api/v7" "api/v8" "api/v9" "api/v10" "api/secure" "api/auth" "api/admin" "api/private" "api/public" "api/internal" "api/external" "api/protected" "api/secret" "api/confidential" "api" "apiEndpoint" "apiGateway" "apiServer" "apiService" "apiClient" "apiRequest" "apiResponse" "apiCall" "apiToken" "aws" "aws_access_key" "aws_secret_key" "aws_region" "aws_account_id" "aws_s3" "aws_ec2" "aws_lambda" "aws_iam" "aws_rds" "aws_cognito" "aws_cloudfront" "aws_dynamodb" "aws_sns" "aws_sqs" "aws_ssm" "aws_secret_manager" "dashboard" "admin_dashboard" "user_dashboard" "control_panel" "management_panel" "dashboard_url" "dashboard_login" "dashboard_password" "oauth" "oauth_token" "oauth2" "oauth_client" "oauth_server" "oauth_provider" "oauth_authorize" "oauth_access" "oauth_token_url" "auth" "authenticate" "authentication" "authorization" "authorize" "user_auth" "user_authorization" "role_authorization" "permission_authorization" "access_control" "admin" "administrator" "admin_panel" "admin_page" "admin_console" "admin_interface" "admin_portal" "admin_center" "admin_area" "admin_access" "admin_login" "admin_logout" "admin_auth" "admin_security" "admin_role" "admin_user" "admin_group" "admin_privileges" "admin_settings" "admin_configuration" "admin_management" "admin_controls" "admin_tools" "admin_audit" "admin_reports" "admin_tasks" "admin_operations" "admin_monitoring" "admin_notifications" "admin_alerts" "admin_logs" "admin_history" "admin_backdoor" "admin_permissions" "admin_authorization" "admin_superuser" "admin_staff" "admin_power" "admin_rights" "passwd" "passcode" "pass_key" "passphrase" "pass_phrase" "pass_word" "password_hash" "pwd_hash" "pwd_salt" "pwd_hash_salt" "pwd_md5" "pwd_sha1" "pwd_sha256" "pwd_sha512" "pwd_bcrypt" "passwordEncoder" "access_token" "refresh_token" "session_token" "auth_token" "oauth_token" "id_token" "jwt_token" "bearer_token" "token_key" "authenticate" "authentication" "auth_check" "auth_verify" "auth_process" "auth_validate" "auth_login" "auth_logout" "auth_user" "user" "username" "user_id" "user_email" "user_password" "user_credentials" "verification_code" "one_time_password" "otp_code" "recovery_code" "reset_code" "activation_code" "mfa_code" "mfa_token" "mfa_key" "remember_me" "remember_token" "crypto_key" "decryption_key" "cipher_key" "key_pair" "forgot_password" "reset_password" "recover_password" "password_reset_token" "reset_password_link" "secure_cookie" "session_id" "session_key" "admin_password" "root_password" "superuser_password" "fingerprint" "facial_recognition" "biometric_data" "social_login" "api_key" "api_secret" "twofactor_code" "twofactor_token" "twofactor_key" "database" "db" "dbConnection" "db_connection" "dbConfig" "db_config" "dbUser" "dbUsername" "dbPassword" "dbHost" "dbPort" "dbConnectionString" "db_url" "personal_information" "pii" "name" "address" "phone_number" "social_security_number" "date_of_birth" "national_id" "passport_number" "driver_license" "tax_id" "credit_card" "cc_number" "credit_card_number" "cc_expiry" "credit_card_expiry" "cc_cvv" "credit_card_cvv" "cc_holder" "credit_card_holder" "email" "email_address" "email_sender" "email_receiver" "email_subject" "email_body" "http://" "https://" "protocol" "url" "website" "web_url" ":80" ":443" ":8080" ":8000" ":3000" ":8081" ":3306" ":5432" ":27017" ":1521" ":1" ":7" ":9" ":13" ":21" ":22" ":23" ":25" ":26" ":37" ":53" ":79" ":81" ":88" ":106" ":110" ":111" ":113" ":119" ":135" ":139" ":143" ":144" ":179" ":199" ":389" ":427" ":444" ":445" ":465" ":514" ":515" ":543" ":544" ":548" ":554" ":587" ":631" ":646" ":873" ":990" ":993" ":995" ":1025" ":1026" ":1027" ":1028" ":1029" ":1110" ":1433" ":1434" ":1521" ":1720" ":1723" ":1755" ":1900" ":2000" ":2049" ":2121" ":2181" ":2375" ":2376" ":3306" ":3389" ":3689" ":3690" ":4321" ":4369" ":4444" ":4500" ":5000" ":5009" ":5432" ":5672" ":5900" ":5984" ":6379" ":6443" ":6514" ":6666" ":7001" ":7002" ":8000" ":8001" ":8009" ":8081" ":8090" ":8091" ":8181" ":8443" ":8888" ":9000" ":9042" ":920" "users")

# Iterate over each URL in the result.txt file
while IFS= read -r url; do
    echo -e "\e[96mVisiting URL: $url\e[0m"

    # Fetch the content of the URL
    content=$(curl -s "$url")

    # Check if the content contains any of the keywords
    for keyword in "${keywords[@]}"; do
        if echo "$content" | grep -qi "$keyword"; then
            echo -e "\e[93mKeyword found: $keyword\e[0m"
        fi
    done

    echo
done < "result.txt"

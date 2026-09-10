#!/usr/bin/env bash
set -euo pipefail

for command_name in aws base64 jq kubectl mktemp openssl sha256sum; do
  command -v "$command_name" >/dev/null || {
    printf 'Missing required command: %s\n' "$command_name" >&2
    exit 1
  }
done

: "${EXPECTED_KUBE_CONTEXT:?Set EXPECTED_KUBE_CONTEXT to the customer/demo cluster context}"
: "${AWS_REGION:?Set AWS_REGION to the AWS Secrets Manager region}"
: "${DEMO_IAM_PRINCIPAL_ARN:?Set DEMO_IAM_PRINCIPAL_ARN to an IAM user or role ARN}"

current_context="$(kubectl config current-context)"
if [[ "$current_context" != "$EXPECTED_KUBE_CONTEXT" ]]; then
  printf 'Wrong Kubernetes context. Expected %s, current %s.\n' \
    "$EXPECTED_KUBE_CONTEXT" "$current_context" >&2
  exit 1
fi

if [[ ! "$DEMO_IAM_PRINCIPAL_ARN" =~ ^arn:[^:]+:iam::[0-9]{12}:(user|role)/.+$ ]]; then
  printf '%s\n' 'DEMO_IAM_PRINCIPAL_ARN must be an IAM user or IAM role ARN, not an STS session ARN.' >&2
  exit 1
fi

namespace="${NAMESPACE:-mongodb-dam}"
release="${RELEASE:-mongodb-dam}"
secret_name="${SECRET_NAME:-mongodb-dam-secrets}"
mapping_secret="${DIRECT_USER_MAPPING_SECRET:-mongodb-dam-demo-direct-user}"
mapping_key="${DIRECT_USER_MAPPING_KEY:-identity-mapping.json}"
aws_secret_id="${DEMO_AWS_SECRET_ID:-mongodb-dam/demo/direct-user}"
database="${DEMO_DATABASE:-dam_demo}"
if [[ ! "$mapping_key" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf '%s\n' 'DIRECT_USER_MAPPING_KEY must be a single Kubernetes Secret data key.' >&2
  exit 1
fi

admin_account="$(aws --region "$AWS_REGION" sts get-caller-identity --query Account --output text)"
principal_account="$(cut -d: -f5 <<<"$DEMO_IAM_PRINCIPAL_ARN")"
if [[ "$admin_account" != "$principal_account" ]]; then
  printf 'This MVP provisioner supports a same-account IAM principal. Admin account=%s, principal account=%s.\n' \
    "$admin_account" "$principal_account" >&2
  printf '%s\n' 'Cross-account Secrets Manager access also needs a customer-managed KMS key and is intentionally not automated.' >&2
  exit 1
fi

mongodb_pod="$(kubectl -n "$namespace" get pods \
  -l "app.kubernetes.io/instance=$release,app.kubernetes.io/component=mongodb" \
  -o jsonpath='{.items[0].metadata.name}')"
if [[ -z "$mongodb_pod" ]]; then
  printf '%s\n' 'MongoDB pod was not found. Deploy the demo first.' >&2
  exit 1
fi
mapping_path="/var/run/mongodb-dam/identity/$mapping_key"
if ! kubectl -n "$namespace" get "deployment/${release}-outpost" -o json \
  | jq -e --arg secret "$mapping_secret" --arg key "$mapping_key" \
      --arg path "$mapping_path" '
        ([.spec.template.spec.containers[]
          | select(.name == "outpost")
          | .env[]?
          | select(.name == "OUTPOST_IDENTITY_MAPPING_FILE" and .value == $path)]
          | length) == 1
        and
        ([.spec.template.spec.volumes[]?
          | select(
              .name == "identity-mapping"
              and .secret.secretName == $secret
              and any(.secret.items[]?; .key == $key and .path == $key)
            )]
          | length) == 1
      ' >/dev/null; then
  printf 'Outpost is not configured for mapping Secret %s key %s. Deploy in demo mode with matching DIRECT_USER_MAPPING_* values.\n' \
    "$mapping_secret" "$mapping_key" >&2
  exit 1
fi

principal_salt="$(kubectl -n "$namespace" get secret "$secret_name" \
  -o jsonpath='{.data.principal-hash-salt}' | base64 --decode)"
if [[ -z "$principal_salt" ]]; then
  printf '%s\n' 'The principal hash salt is empty.' >&2
  exit 1
fi

iam_digest="$(printf '%s' "$DEMO_IAM_PRINCIPAL_ARN" | sha256sum)"
iam_digest="${iam_digest%% *}"
mongo_username="iam-${iam_digest:0:16}"
mongo_password="$(openssl rand -base64 36 | tr -d '\n')"
principal_digest="$(
  {
    printf '%s' "$principal_salt"
    printf '\0'
    printf '%s' "$mongo_username"
  } | sha256sum
)"
principal_digest="${principal_digest%% *}"
principal_hash="sha256:$principal_digest"

kubectl -n "$namespace" exec "$mongodb_pod" -- \
  env DAM_DEMO_USERNAME="$mongo_username" DAM_DEMO_PASSWORD="$mongo_password" \
  DAM_DEMO_DATABASE="$database" \
  sh -ceu '
    mongosh --quiet --host 127.0.0.1 --port 27017 \
      --username "$MONGO_INITDB_ROOT_USERNAME" \
      --password "$MONGO_INITDB_ROOT_PASSWORD" \
      --authenticationDatabase admin \
      --eval '\''
        const username = process.env.DAM_DEMO_USERNAME;
        const password = process.env.DAM_DEMO_PASSWORD;
        const admin = db.getSiblingDB("admin");
        const roles = [{role: "readWrite", db: process.env.DAM_DEMO_DATABASE}];
        if (admin.getUser(username)) {
          admin.updateUser(username, {pwd: password, roles});
        } else {
          admin.createUser({user: username, pwd: password, roles});
        }
        print(JSON.stringify({status: "ready", username, roles}));
      '\''
  '

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT
chmod 700 "$tmp_dir"

credential_file="$tmp_dir/credential.json"
jq -n \
  --arg iam_principal_arn "$DEMO_IAM_PRINCIPAL_ARN" \
  --arg mongo_username "$mongo_username" \
  --arg mongo_password "$mongo_password" \
  --arg auth_database admin \
  --arg database "$database" \
  '{
    version: 1,
    status: "active",
    iam_principal_arn: $iam_principal_arn,
    mongo_username: $mongo_username,
    mongo_password: $mongo_password,
    auth_database: $auth_database,
    database: $database
  }' >"$credential_file"
chmod 600 "$credential_file"

if aws --region "$AWS_REGION" secretsmanager describe-secret \
  --secret-id "$aws_secret_id" >/dev/null 2>&1; then
  aws --region "$AWS_REGION" secretsmanager put-secret-value \
    --secret-id "$aws_secret_id" \
    --secret-string "file://$credential_file" >/dev/null
else
  aws --region "$AWS_REGION" secretsmanager create-secret \
    --name "$aws_secret_id" \
    --description 'MongoDB DAM MVP: IAM-gated direct MongoDB demo credential' \
    --secret-string "file://$credential_file" >/dev/null
fi

policy_file="$tmp_dir/resource-policy.json"
jq -n --arg principal "$DEMO_IAM_PRINCIPAL_ARN" '{
  Version: "2012-10-17",
  Statement: [{
    Sid: "AllowMappedIamPrincipalRead",
    Effect: "Allow",
    Principal: {AWS: $principal},
    Action: "secretsmanager:GetSecretValue",
    Resource: "*"
  }]
}' >"$policy_file"
aws --region "$AWS_REGION" secretsmanager put-resource-policy \
  --secret-id "$aws_secret_id" \
  --resource-policy "file://$policy_file" \
  --block-public-policy >/dev/null

mapping_manifest="$tmp_dir/mapping-secret.yaml"
identity_mapping_file="$tmp_dir/identity-mapping.json"
secret_arn="$(aws --region "$AWS_REGION" secretsmanager describe-secret \
  --secret-id "$aws_secret_id" --query ARN --output text)"
if [[ "$DEMO_IAM_PRINCIPAL_ARN" == *":user/"* ]]; then
  principal_type=iam_user
else
  principal_type=iam_role
fi
jq -n \
  --arg mongodb_principal_hash "$principal_hash" \
  --arg principal_type "$principal_type" \
  --arg principal_arn "$DEMO_IAM_PRINCIPAL_ARN" \
  --arg account_id "$principal_account" \
  --arg credential_resource "$secret_arn" \
  '{
    schema_version: 1,
    mappings: [{
      mongodb_principal_hash: $mongodb_principal_hash,
      provider: "aws",
      principal_type: $principal_type,
      principal_arn: $principal_arn,
      account_id: $account_id,
      credential_source: "aws_secrets_manager",
      credential_resource: $credential_resource
    }]
  }' >"$identity_mapping_file"
chmod 600 "$identity_mapping_file"

kubectl -n "$namespace" create secret generic "$mapping_secret" \
  --from-literal="iam-principal-arn=$DEMO_IAM_PRINCIPAL_ARN" \
  --from-literal="mongo-username=$mongo_username" \
  --from-literal="principal-hash=$principal_hash" \
  --from-literal="aws-secret-id=$aws_secret_id" \
  --from-literal="aws-secret-arn=$secret_arn" \
  --from-literal="aws-account-id=$principal_account" \
  --from-literal="principal-type=$principal_type" \
  --from-literal="database=$database" \
  --from-literal='status=active' \
  --from-file="$mapping_key=$identity_mapping_file" \
  --dry-run=client -o yaml >"$mapping_manifest"
kubectl apply -f "$mapping_manifest" >/dev/null

kubectl -n "$namespace" rollout restart "deployment/${release}-outpost" >/dev/null
kubectl -n "$namespace" rollout status "deployment/${release}-outpost" \
  --timeout="${DEPLOY_TIMEOUT:-3m}" >/dev/null

printf '\nDirect-user mapping provisioned.\n'
printf 'IAM principal:       %s\n' "$DEMO_IAM_PRINCIPAL_ARN"
printf 'MongoDB user:        %s (SCRAM, readWrite on %s)\n' "$mongo_username" "$database"
printf 'DAM principal hash:  %s\n' "$principal_hash"
printf 'AWS secret ARN:      %s\n' "$secret_arn"
printf '%s\n' 'The password was written only to AWS Secrets Manager and was not printed.'

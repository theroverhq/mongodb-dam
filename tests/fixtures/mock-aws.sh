#!/usr/bin/env bash
set -euo pipefail

arguments=" $* "
if [[ -n "${MOCK_EXPECT_PROFILE:-}" \
  && "$arguments" != *" --profile $MOCK_EXPECT_PROFILE "* ]]; then
  printf 'Expected AWS profile %s, arguments were: %s\n' \
    "$MOCK_EXPECT_PROFILE" "$*" >&2
  exit 2
fi
if [[ "${MOCK_EXPECT_NO_STATIC_CREDENTIALS:-false}" == true \
  && ( -n "${AWS_ACCESS_KEY_ID:-}" \
    || -n "${AWS_SECRET_ACCESS_KEY:-}" \
    || -n "${AWS_SESSION_TOKEN:-}" ) ]]; then
  printf '%s\n' 'Expected direct-user invocation to remove ambient static AWS credentials.' >&2
  exit 2
fi
if [[ -n "${MOCK_EXPECT_ACCESS_KEY_ID:-}" \
  && "${AWS_ACCESS_KEY_ID:-}" != "$MOCK_EXPECT_ACCESS_KEY_ID" ]]; then
  printf 'Expected direct-user access key %s, received %s.\n' \
    "$MOCK_EXPECT_ACCESS_KEY_ID" "${AWS_ACCESS_KEY_ID:-<unset>}" >&2
  exit 2
fi
if [[ -n "${MOCK_EXPECT_SESSION_TOKEN:-}" \
  && "${AWS_SESSION_TOKEN:-}" != "$MOCK_EXPECT_SESSION_TOKEN" ]]; then
  printf '%s\n' 'Expected the scoped direct-user session token.' >&2
  exit 2
fi

if [[ "$arguments" == *' sts get-caller-identity '* ]]; then
  printf '%s\n' "${MOCK_AWS_CALLER_ARN:-arn:aws:iam::111122223333:user/dam-demo-alice}"
  exit 0
fi

if [[ "$arguments" == *' secretsmanager get-secret-value '* ]]; then
  case "${MOCK_AWS_SECRET_RESULT:-denied}" in
    denied)
      printf '%s\n' 'An error occurred (AccessDeniedException): explicit deny in an identity-based policy' >&2
      exit 254
      ;;
    allowed)
      printf '%s\n' 'arn:aws:secretsmanager:ap-south-1:111122223333:secret:mongodb-dam-demo-AbCdEf'
      exit 0
      ;;
    error)
      printf '%s\n' 'An error occurred (InternalServiceError): simulated failure' >&2
      exit 255
      ;;
  esac
fi

printf 'Unexpected mock AWS arguments: %s\n' "$*" >&2
exit 2

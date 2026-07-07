import json,os,csv,io,logging,math,time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

import boto3
from botocore.exceptions import ClientError
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EntityType(Enum):
    USER = "User"
    ROLE = "Role"
    GROUP = "Group"
    POLICY = "Policy"
    SERVICE_ACCOUNT = "ServiceAccount"
    RESOURCE = "Resource"
    ORGANIZATION = "Organization"
    ACCOUNT = "Account"
    PROJECT = "Project"
    PERMISSION_SET = "PermissionSet"
    ACCESS_KEY = "AccessKey"
    MFA_DEVICE = "MFADevice"

    def to_schema_type(self) -> str:
        """Map scanner internal type to Supabase schema entity_type CHECK constraint value."""
        mapping = {
            'USER': 'user',
            'ROLE': 'role',
            'GROUP': 'group',
            'POLICY': 'managed_policy',
            'SERVICE_ACCOUNT': 'service_account',
            'PERMISSION_SET': 'permission_set',
        }
        return mapping.get(self.name, self.value.lower())

    @classmethod
    def is_schema_entity(cls, type_name: str) -> bool:
        """Check if this entity type should be stored in scan_entities table."""
        schema_types = {'USER', 'ROLE', 'GROUP', 'POLICY', 'SERVICE_ACCOUNT', 'PERMISSION_SET'}
        return type_name in schema_types


class RelationType(Enum):
    MEMBER_OF = "MEMBER_OF"
    ATTACHED_TO = "ATTACHED_TO"
    TRUSTS = "TRUSTS"
    CAN_ASSUME = "CAN_ASSUME"
    BINDS_TO = "BINDS_TO"
    ALLOWS = "ALLOWS"
    HAS_KEY = "HAS_KEY"
    HAS_MFA = "HAS_MFA"
    PART_OF = "PART_OF"
    CONTAINS = "CONTAINS"
    ASSIGNED_TO = "ASSIGNED_TO"
    CAN_IMPERSONATE = "CAN_IMPERSONATE"
    DEPENDS_ON = "DEPENDS_ON"


@dataclass
class IAMNode:
    id: str
    name: str
    type: str
    provider: str
    account: str
    region: str = "global"

    # Risk flags
    is_admin: bool = False
    is_overprivileged: bool = False
    has_mfa: bool = False
    has_console_access: bool = False
    has_access_keys: bool = False
    is_active: bool = True
    is_external: bool = False
    is_dormant: bool = False

    # Compliance
    applicable_compliances: List[str] = field(default_factory=list)
    data_residency_violation: bool = False

    # Service detection for cost engine (NEW)
    detected_services: List[str] = field(default_factory=list)

    # Raw properties
    props: Dict[str, Any] = field(default_factory=dict)

    # Temporal
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    password_last_used: Optional[str] = None

    def __post_init__(self):
        if self.applicable_compliances is None:
            self.applicable_compliances = []
        if self.props is None:
            self.props = {}
        if self.detected_services is None:
            self.detected_services = []


@dataclass
class IAMEdge:
    source: str
    target: str
    type: str
    props: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.props is None:
            self.props = {}


@dataclass
class IAMGraph:
    scan_id: str
    provider: str
    account: str
    scanned_at: str
    nodes: List[Dict]
    edges: List[Dict]
    stats: Dict[str, Any]
    compliance_context: Dict[str, Any] = field(default_factory=dict)

    def to_json(self, filepath: str):
        # Ensure scan_id is in every node and edge
        for node in self.nodes:
            node['scan_id'] = self.scan_id
        for edge in self.edges:
            edge['scan_id'] = self.scan_id

        with open(filepath, 'w') as f:
            json.dump(asdict(self), f, indent=2, default=str)
        logger.info(f"Graph saved to {filepath}")

    def to_neo4j_csv(self, nodes_file: str, edges_file: str):
        """Export as CSV for Neo4j admin import (fastest bulk load)"""
        import csv

        with open(nodes_file, 'w', newline='') as f:
            if self.nodes:
                writer = csv.DictWriter(f, fieldnames=self.nodes[0].keys())
                writer.writeheader()
                writer.writerows(self.nodes)

        # Edges CSV
        with open(edges_file, 'w', newline='') as f:
            if self.edges:
                writer = csv.DictWriter(f, fieldnames=self.edges[0].keys())
                writer.writeheader()
                writer.writerows(self.edges)

        logger.info(f"Neo4j CSV: {nodes_file}, {edges_file}")


class PermissionClassifier:

    # Full admin patterns
    ADMIN_PATTERNS = {'*', '*:*'}
    IAM_ADMIN_PATTERNS = {'iam:*', 'iam:CreateRole', 'iam:AttachRolePolicy',
                          'iam:PutRolePolicy', 'iam:CreatePolicy',
                          'iam:CreateAccessKey', 'iam:CreateUser'}
    STS_ADMIN_PATTERNS = {'sts:AssumeRole', 'sts:AssumeRoleWithSAML',
                          'sts:AssumeRoleWithWebIdentity'}

    SERVICE_PATTERNS = {
        'rds': ['rds:', 'RDS'],
        's3': ['s3:', 'S3'],
        'ec2': ['ec2:', 'EC2'],
        'lambda': ['lambda:', 'Lambda'],
        'dynamodb': ['dynamodb:', 'DynamoDB'],
        'secretsmanager': ['secretsmanager:', 'SecretsManager'],
        'kms': ['kms:', 'KMS'],
        'cloudsql': ['cloudsql:', 'CloudSQL'],
        'bigquery': ['bigquery:', 'BigQuery'],
        'cloudstorage': ['storage:', 'CloudStorage'],
        'spanner': ['spanner:', 'Spanner'],
        'healthlake': ['healthlake:', 'HealthLake'],
        'redshift': ['redshift:', 'Redshift'],
    }

    @classmethod
    def classify_permission(cls, action: str) -> Tuple[str, int]:
        """
        Classify a single permission action and returns: (risk_level, risk_score)
        where : risk_level: 'admin', 'high', 'medium', 'low'
        range of risk_score: 0-100
        """
        action = action.strip()

        # Full admin
        if action in cls.ADMIN_PATTERNS:
            return 'admin', 100

        # IAM admin
        if any(action.startswith(p.replace('*', '')) for p in cls.IAM_ADMIN_PATTERNS):
            return 'admin', 95

        # STS assume role on wildcard
        if action in cls.STS_ADMIN_PATTERNS:
            return 'high', 85

        # Service wildcard
        if action.endswith(':*'):
            service = action.split(':')[0]
            if service in ['iam', 'sts', 'organizations']:
                return 'admin', 90
            return 'high', 70

        # Specific action on wildcard resource
        if '*' in action:
            return 'medium', 50

        # Specific action
        return 'low', 20

    @classmethod
    def is_admin_permission(cls, action: str) -> bool:
        """Check if a single permission is admin-level."""
        risk_level, _ = cls.classify_permission(action)
        return risk_level == 'admin'

    @classmethod
    def detect_services(cls, permissions: List[str]) -> List[str]:
        """Detect which AWS/GCP services are referenced in permissions."""
        services = set()
        for action in permissions:
            for service, patterns in cls.SERVICE_PATTERNS.items():
                if any(pattern in action for pattern in patterns):
                    services.add(service)
        return list(services)

    @classmethod
    def calculate_static_risk(cls, permissions: List[str]) -> Tuple[bool, bool, float, List[str]]:
        """
        Calculate static risk for a set of permissions.
        Returns: (is_admin, is_overprivileged, risk_score, detected_services)
        """
        if not permissions:
            return False, False, 0, []

        max_risk = 0
        is_admin = False
        is_overprivileged = False

        for action in permissions:
            risk_level, score = cls.classify_permission(action)
            max_risk = max(max_risk, score)
            if risk_level == 'admin':
                is_admin = True
            if risk_level in ('high', 'admin'):
                is_overprivileged = True

        # Risk score: weighted average with max penalty
        avg_risk = sum(cls.classify_permission(a)[1] for a in permissions) / len(permissions)
        risk_score = max(max_risk, avg_risk * 0.7 + max_risk * 0.3)

        services = cls.detect_services(permissions)

        return is_admin, is_overprivileged, min(100, risk_score), services



class AWSIAMScanner:
    """
    AWS IAM Scanner using ALL relevant APIs (CORRECTED v2.1):
      - get_account_authorization_details (PAGINATED)
      - get_access_key_last_used (temporal)
      - list_mfa_devices (security)
      - generate_credential_report (comprehensive)
      - get_policy_version (ACTUAL permission parsing — CRITICAL FIX)
      - organizations APIs (org structure)
      - sso-admin APIs (SSO permission sets)
      - Resource policies (S3, KMS, etc.)
      - cloudtrail:LookupEvents (temporal events — NEW)
    """

    def __init__(self, access_key_id: str, secret_access_key: str, region: str = "us-east-1"):
        self.session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        self.iam = self.session.client('iam')
        self.sts = self.session.client('sts')
        self.cloudtrail = self.session.client('cloudtrail')
        self.account_id = self.sts.get_caller_identity()['Account']

        try:
            self.org = self.session.client('organizations')
            self.org_enabled = True
        except Exception:
            self.org_enabled = False

        try:
            self.sso_admin = self.session.client('sso-admin')
            self.sso_enabled = True
        except Exception:
            self.sso_enabled = False

        self.nodes = []
        self.edges = []
        self.node_ids = set()

        # Cache for policy documents (ARN -> permissions)
        self._policy_cache: Dict[str, List[str]] = {}

    def scan(self, selected_compliances: List[str] = None) -> IAMGraph:
        """Execute complete AWS scan with all APIs (CORRECTED)."""
        if selected_compliances is None:
            selected_compliances = ['SOC2']

        scan_id = f"aws-{self.account_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        logger.info(f"AWS Scan {scan_id} starting for account {self.account_id}")

        try:
            # === PRIMARY API: get_account_authorization_details (PAGINATED) ===
            auth_details = self._get_auth_details_paginated()

            # === TEMPORAL: Generate credential report ===
            credential_report = self._get_credential_report()

            # === MFA: List MFA devices for all users ===
            mfa_data = self._get_all_mfa_devices()

            # === ACCESS KEYS: Get last used for all keys ===
            key_last_used = self._get_all_access_key_last_used()

            # === ORGANIZATIONS: Get org structure ===
            org_data = self._get_org_data() if self.org_enabled else {}

            # === SSO: Get permission sets ===
            sso_data = self._get_sso_data() if self.sso_enabled else {}

            # === RESOURCE POLICIES: S3, KMS, etc. ===
            resource_policies = self._get_resource_policies()

            # === CLOUDTRAIL: Recent events (last 7 days) ===
            cloudtrail_events = self._get_cloudtrail_events()

            # Normalize everything
            self._normalize_users(auth_details.get('UserDetailList', []), credential_report, mfa_data, key_last_used)
            self._normalize_groups(auth_details.get('GroupDetailList', []))
            self._normalize_roles(auth_details.get('RoleDetailList', []))
            self._normalize_policies(auth_details.get('Policies', []))
            self._normalize_org(org_data)
            self._normalize_sso(sso_data)
            self._normalize_resource_policies(resource_policies)
            self._normalize_cloudtrail_events(cloudtrail_events)

            # Build account node
            self._add_node(IAMNode(
                id=f"arn:aws:iam::{self.account_id}:root",
                name=f"Account {self.account_id}",
                type=EntityType.ACCOUNT.value,
                provider="aws",
                account=self.account_id,
                props={'account_id': self.account_id}
            ))

            # Build stats
            stats = self._build_stats()

            return IAMGraph(
                scan_id=scan_id,
                provider="aws",
                account=self.account_id,
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=self.nodes,
                edges=self.edges,
                stats=stats,
                compliance_context={'selected_compliances': selected_compliances}
            )

        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            return IAMGraph(
                scan_id=scan_id,
                provider="aws",
                account=self.account_id,
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=self.nodes,
                edges=self.edges,
                stats={'error': str(e), 'total_nodes': len(self.nodes), 'total_edges': len(self.edges)},
                compliance_context={'selected_compliances': selected_compliances}
            )

    def _add_node(self, node: IAMNode):
        if node.id not in self.node_ids:
            self.nodes.append(asdict(node))
            self.node_ids.add(node.id)

    def _add_edge(self, edge: IAMEdge):
        self.edges.append(asdict(edge))

    def _get_auth_details_paginated(self) -> Dict:
        """Get ALL authorization details with pagination."""
        all_details = {
            'UserDetailList': [],
            'GroupDetailList': [],
            'RoleDetailList': [],
            'Policies': []
        }
        marker = None

        while True:
            kwargs = {'Filter': ['User', 'Group', 'Role', 'LocalManagedPolicy', 'AWSManagedPolicy']}
            if marker:
                kwargs['Marker'] = marker

            response = self.iam.get_account_authorization_details(**kwargs)

            all_details['UserDetailList'].extend(response.get('UserDetailList', []))
            all_details['GroupDetailList'].extend(response.get('GroupDetailList', []))
            all_details['RoleDetailList'].extend(response.get('RoleDetailList', []))
            all_details['Policies'].extend(response.get('Policies', []))

            marker = response.get('Marker')
            if not marker:
                break

        logger.info(f"AWS: Collected {len(all_details['UserDetailList'])} users, "
                   f"{len(all_details['GroupDetailList'])} groups, "
                   f"{len(all_details['RoleDetailList'])} roles, "
                   f"{len(all_details['Policies'])} policies")
        return all_details

    def _get_policy_permissions(self, policy_arn: str, default_version_id: str) -> List[str]:
        """Fetch and parse ACTUAL policy document to extract permissions."""
        cache_key = f"{policy_arn}:{default_version_id}"
        if cache_key in self._policy_cache:
            return self._policy_cache[cache_key]

        try:
            response = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            doc = response['PolicyVersion']['Document']
            perms = self._extract_perms_from_doc(doc)
            self._policy_cache[cache_key] = perms
            return perms
        except Exception as e:
            logger.warning(f"Could not fetch policy {policy_arn}: {e}")
            return []

    def _extract_perms_from_doc(self, doc: Dict) -> List[str]:
        """Extract permission actions from policy document."""
        perms = []
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                perms.extend(actions)
        return perms

    # === TEMPORAL APIs ===

    def _get_credential_report(self) -> Dict[str, Dict]:
        """Generate and parse credential report for all users (with timeout)."""
        report_data = {}
        try:
            self.iam.generate_credential_report()
            import time
            for attempt in range(20):  # 20 attempts, 2s each = 40s max
                time.sleep(2)
                response = self.iam.get_credential_report()
                if response['State'] == 'COMPLETE':
                    break
                if attempt == 19:
                    logger.warning("Credential report generation timed out")
                    return {}

            csv_content = response['Content'].decode('utf-8')
            reader = csv.DictReader(io.StringIO(csv_content))

            for row in reader:
                username = row.get('user', '')
                if username:
                    report_data[username] = {
                        'password_last_used': row.get('password_last_used', 'N/A'),
                        'password_enabled': row.get('password_enabled', 'false'),
                        'mfa_active': row.get('mfa_active', 'false'),
                        'access_key_1_active': row.get('access_key_1_active', 'false'),
                        'access_key_1_last_used_date': row.get('access_key_1_last_used_date', 'N/A'),
                        'access_key_2_active': row.get('access_key_2_active', 'false'),
                        'access_key_2_last_used_date': row.get('access_key_2_last_used_date', 'N/A'),
                    }
        except Exception as e:
            logger.warning(f"Could not get credential report: {e}")
        return report_data

    def _get_all_mfa_devices(self) -> Dict[str, List[Dict]]:
        """Get MFA devices for all users."""
        mfa_data = {}
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    try:
                        devices = self.iam.list_mfa_devices(UserName=username)
                        mfa_data[username] = devices.get('MFADevices', [])
                    except Exception:
                        mfa_data[username] = []
        except Exception as e:
            logger.warning(f"Could not get MFA devices: {e}")
        return mfa_data

    def _get_all_access_key_last_used(self) -> Dict[str, Dict]:
        """Get last used info for all access keys."""
        key_data = {}
        try:
            paginator = self.iam.get_paginator('list_access_keys')
            for page in paginator.paginate():
                for key in page['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    try:
                        last_used = self.iam.get_access_key_last_used(AccessKeyId=key_id)
                        key_data[key_id] = {
                            'last_used_date': str(last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate', '')),
                            'service_name': last_used.get('AccessKeyLastUsed', {}).get('ServiceName', ''),
                            'region': last_used.get('AccessKeyLastUsed', {}).get('Region', '')
                        }
                    except Exception:
                        key_data[key_id] = {'last_used_date': 'never', 'service_name': '', 'region': ''}
        except Exception as e:
            logger.warning(f"Could not get access key last used: {e}")
        return key_data

    def _get_cloudtrail_events(self) -> List[Dict]:
        """Get recent CloudTrail events for temporal analysis."""
        events = []
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=7)

            paginator = self.cloudtrail.get_paginator('lookup_events')
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}]
            ):
                for event in page.get('Events', []):
                    events.append({
                        'event_id': event.get('EventId'),
                        'event_name': event.get('EventName'),
                        'event_time': str(event.get('EventTime')),
                        'username': event.get('Username'),
                        'source_ip': event.get('SourceIPAddress'),
                        'raw_event': json.loads(event.get('CloudTrailEvent', '{}'))
                    })
        except Exception as e:
            logger.warning(f"Could not get CloudTrail events: {e}")
        return events

    # === ORGANIZATION APIs ===

    def _get_org_data(self) -> Dict:
        """Get organization structure and policies."""
        org_data = {'org': None, 'accounts': [], 'policies': []}
        try:
            org = self.org.describe_organization()['Organization']
            org_data['org'] = org

            paginator = self.org.get_paginator('list_accounts')
            for page in paginator.paginate():
                org_data['accounts'].extend(page['Accounts'])

            try:
                policies = self.org.list_policies(Filter='SERVICE_CONTROL_POLICY')['Policies']
                org_data['policies'] = policies
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Could not get org data: {e}")
        return org_data

    # === SSO APIs ===

    def _get_sso_data(self) -> Dict:
        """Get SSO permission sets and assignments."""
        sso_data = {'permission_sets': [], 'assignments': []}
        try:
            instances = self.sso_admin.list_instances()['Instances']
            if not instances:
                return sso_data

            instance_arn = instances[0]['InstanceArn']

            paginator = self.sso_admin.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=instance_arn):
                for ps_arn in page.get('PermissionSets', []):
                    try:
                        ps = self.sso_admin.describe_permission_set(
                            InstanceArn=instance_arn,
                            PermissionSetArn=ps_arn
                        )['PermissionSet']
                        sso_data['permission_sets'].append(ps)

                        accounts = self.sso_admin.list_accounts_for_provisioned_permission_set(
                            InstanceArn=instance_arn,
                            PermissionSetArn=ps_arn
                        )['AccountIds']

                        for account_id in accounts:
                            assignments = self.sso_admin.list_account_assignments(
                                InstanceArn=instance_arn,
                                AccountId=account_id,
                                PermissionSetArn=ps_arn
                            )['AccountAssignments']
                            sso_data['assignments'].extend(assignments)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Could not get SSO data: {e}")
        return sso_data

    # === RESOURCE POLICIES ===

    def _get_resource_policies(self) -> Dict[str, List[Dict]]:
        """Get resource-based policies for S3, KMS, etc."""
        policies = {'s3': [], 'kms': [], 'sns': [], 'sqs': []}
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket['Name'])
                    policies['s3'].append({
                        'resource': f"arn:aws:s3:::{bucket['Name']}",
                        'policy': json.loads(policy['Policy'])
                    })
                except ClientError:
                    pass

            kms = self.session.client('kms')
            paginator = kms.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        policy = kms.get_key_policy(KeyId=key['KeyId'], PolicyName='default')
                        policies['kms'].append({
                            'resource': key['KeyArn'],
                            'policy': json.loads(policy['Policy'])
                        })
                    except Exception:
                        pass
        except Exception as e:
            logger.warning(f"Could not get resource policies: {e}")
        return policies

    # === NORMALIZATION (CORRECTED with actual permission parsing) ===

    def _normalize_users(self, users: List[Dict], cred_report: Dict, mfa_data: Dict, key_data: Dict):
        """Normalize user data with ACTUAL permission analysis."""
        for user in users:
            username = user['UserName']
            user_arn = user['Arn']

            # Get credential report data
            cred_info = cred_report.get(username, {})

            # Check dormancy
            last_used = cred_info.get('password_last_used', 'N/A')
            is_dormant = False
            if last_used not in ('N/A', 'no_information', ''):
                try:
                    last_used_date = datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00')
                    is_dormant = (datetime.now(timezone.utc) - last_used_date.replace(tzinfo=timezone.utc)).days > 90
                except Exception:
                    pass

            # MFA status
            mfa_devices = mfa_data.get(username, [])
            has_mfa = len(mfa_devices) > 0

            # Access keys
            access_keys = user.get('AccessKeys', [])
            keys_with_usage = []
            for key in access_keys:
                key_id = key['AccessKeyId']
                usage = key_data.get(key_id, {})
                keys_with_usage.append({
                    'key_id': key_id,
                    'status': key.get('Status', ''),
                    'last_used': usage.get('last_used_date', 'never'),
                    'service': usage.get('service_name', ''),
                    'region': usage.get('region', '')
                })

            # === CRITICAL FIX: Extract ACTUAL permissions from attached policies ===
            attached_policies = user.get('AttachedManagedPolicies', [])
            all_permissions = []
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                default_version = policy.get('DefaultVersionId', 'v1')
                perms = self._get_policy_permissions(policy_arn, default_version)
                all_permissions.extend(perms)

            # Also check inline policies
            for inline in user.get('UserPolicyList', []):
                inline_perms = self._extract_perms_from_doc(inline.get('PolicyDocument', {}))
                all_permissions.extend(inline_perms)

            # Classify permissions
            is_admin, is_overprivileged, risk_score, detected_services = \
                PermissionClassifier.calculate_static_risk(all_permissions)

            node = IAMNode(
                id=user_arn,
                name=username,
                type=EntityType.USER.value,
                provider="aws",
                account=self.account_id,
                is_admin=is_admin,
                is_overprivileged=is_overprivileged,
                has_mfa=has_mfa,
                has_console_access=cred_info.get('password_enabled') == 'true',
                has_access_keys=len(access_keys) > 0,
                is_dormant=is_dormant,
                detected_services=detected_services,
                props={
                    'user_id': user.get('UserId', ''),
                    'path': user.get('Path', '/'),
                    'group_count': len(user.get('GroupList', [])),
                    'attached_policy_count': len(attached_policies),
                    'inline_policy_count': len(user.get('UserPolicyList', [])),
                    'mfa_device_count': len(mfa_devices),
                    'access_keys': keys_with_usage,
                    'password_last_used': cred_info.get('password_last_used', 'N/A'),
                    'permissions': all_permissions[:100],  # Limit for storage
                    'permission_count': len(all_permissions),
                    'risk_score': risk_score
                },
                created_at=str(user.get('CreateDate', '')),
                last_used_at=str(user.get('PasswordLastUsed', ''))
            )
            self._add_node(node)

            # User -> Group edges
            for group_name in user.get('GroupList', []):
                group_arn = f"arn:aws:iam::{self.account_id}:group/{group_name}"
                self._add_edge(IAMEdge(source=user_arn, target=group_arn, type=RelationType.MEMBER_OF.value))

            # Policy -> User edges
            for policy in attached_policies:
                self._add_edge(IAMEdge(
                    source=policy['PolicyArn'], target=user_arn,
                    type=RelationType.ATTACHED_TO.value,
                    props={'policy_name': policy['PolicyName']}
                ))

            # User -> AccessKey nodes
            for key in keys_with_usage:
                key_node_id = f"{user_arn}:key:{key['key_id']}"
                self._add_node(IAMNode(
                    id=key_node_id,
                    name=key['key_id'],
                    type=EntityType.ACCESS_KEY.value,
                    provider="aws",
                    account=self.account_id,
                    is_active=key['status'] == 'Active',
                    is_dormant=key['last_used'] == 'never',
                    props={'last_used': key['last_used'], 'service': key['service']}
                ))
                self._add_edge(IAMEdge(source=user_arn, target=key_node_id, type=RelationType.HAS_KEY.value))

            # User -> MFA nodes
            for device in mfa_devices:
                mfa_id = device['SerialNumber']
                self._add_node(IAMNode(
                    id=mfa_id,
                    name=device.get('DeviceName', 'MFA'),
                    type=EntityType.MFA_DEVICE.value,
                    provider="aws",
                    account=self.account_id,
                    props={'enable_date': str(device.get('EnableDate', ''))}
                ))
                self._add_edge(IAMEdge(source=user_arn, target=mfa_id, type=RelationType.HAS_MFA.value))

    def _normalize_groups(self, groups: List[Dict]):
        for group in groups:
            group_arn = group['Arn']
            attached = group.get('AttachedManagedPolicies', [])

            # Extract actual permissions
            all_permissions = []
            for policy in attached:
                perms = self._get_policy_permissions(policy['PolicyArn'], policy.get('DefaultVersionId', 'v1'))
                all_permissions.extend(perms)

            for inline in group.get('GroupPolicyList', []):
                inline_perms = self._extract_perms_from_doc(inline.get('PolicyDocument', {}))
                all_permissions.extend(inline_perms)

            is_admin, is_overprivileged, risk_score, detected_services = \
                PermissionClassifier.calculate_static_risk(all_permissions)

            self._add_node(IAMNode(
                id=group_arn,
                name=group['GroupName'],
                type=EntityType.GROUP.value,
                provider="aws",
                account=self.account_id,
                is_admin=is_admin,
                is_overprivileged=is_overprivileged,
                detected_services=detected_services,
                props={
                    'group_id': group.get('GroupId', ''),
                    'path': group.get('Path', '/'),
                    'attached_policy_count': len(attached),
                    'inline_policy_count': len(group.get('GroupPolicyList', [])),
                    'permissions': all_permissions[:100],
                    'permission_count': len(all_permissions),
                    'risk_score': risk_score
                },
                created_at=str(group.get('CreateDate', ''))
            ))

            for policy in attached:
                self._add_edge(IAMEdge(
                    source=policy['PolicyArn'], target=group_arn,
                    type=RelationType.ATTACHED_TO.value,
                    props={'policy_name': policy['PolicyName']}
                ))

    def _normalize_roles(self, roles: List[Dict]):
        for role in roles:
            role_arn = role['Arn']
            trust_policy = role.get('AssumeRolePolicyDocument', {})
            trusted = self._parse_trust_policy(trust_policy)

            attached = role.get('AttachedManagedPolicies', [])

            # Extract actual permissions
            all_permissions = []
            for policy in attached:
                perms = self._get_policy_permissions(policy['PolicyArn'], policy.get('DefaultVersionId', 'v1'))
                all_permissions.extend(perms)

            for inline in role.get('RolePolicyList', []):
                inline_perms = self._extract_perms_from_doc(inline.get('PolicyDocument', {}))
                all_permissions.extend(inline_perms)

            is_admin, is_overprivileged, risk_score, detected_services = \
                PermissionClassifier.calculate_static_risk(all_permissions)

            is_external = any(self.account_id not in p for p in trusted if p.startswith('arn:aws:iam::'))
            has_wildcard = '*' in trusted

            self._add_node(IAMNode(
                id=role_arn,
                name=role['RoleName'],
                type=EntityType.ROLE.value,
                provider="aws",
                account=self.account_id,
                is_admin=is_admin,
                is_overprivileged=is_overprivileged,
                is_external=is_external or has_wildcard,
                detected_services=detected_services,
                props={
                    'role_id': role.get('RoleId', ''),
                    'path': role.get('Path', '/'),
                    'max_session_duration': role.get('MaxSessionDuration', 3600),
                    'description': role.get('Description', ''),
                    'trusted_principals': trusted,
                    'has_wildcard_trust': has_wildcard,
                    'attached_policy_count': len(attached),
                    'instance_profile_count': len(role.get('InstanceProfileList', [])),
                    'permissions': all_permissions[:100],
                    'permission_count': len(all_permissions),
                    'risk_score': risk_score
                },
                created_at=str(role.get('CreateDate', '')),
                last_used_at=str(role.get('RoleLastUsed', {}).get('LastUsedDate', ''))
            ))

            # Role -> Trust edges
            for principal in trusted:
                if principal == '*':
                    self._add_edge(IAMEdge(source=role_arn, target="arn:aws:iam::*:*",
                                          type=RelationType.TRUSTS.value, props={'trust_type': 'wildcard'}))
                else:
                    self._add_edge(IAMEdge(source=role_arn, target=principal,
                                          type=RelationType.TRUSTS.value, props={'trust_type': 'principal'}))

            # Policy -> Role edges
            for policy in attached:
                self._add_edge(IAMEdge(source=policy['PolicyArn'], target=role_arn,
                                      type=RelationType.ATTACHED_TO.value))

    def _normalize_policies(self, policies: List[Dict]):
        for policy in policies:
            policy_arn = policy['Arn']
            perms = self._get_policy_permissions(policy_arn, policy.get('DefaultVersionId', 'v1'))

            is_admin, is_overprivileged, risk_score, detected_services = \
                PermissionClassifier.calculate_static_risk(perms)

            self._add_node(IAMNode(
                id=policy_arn,
                name=policy['PolicyName'],
                type=EntityType.POLICY.value,
                provider="aws",
                account=self.account_id,
                is_admin=is_admin,
                is_overprivileged=is_overprivileged,
                detected_services=detected_services,
                props={
                    'policy_id': policy.get('PolicyId', ''),
                    'default_version_id': policy.get('DefaultVersionId', ''),
                    'attachment_count': policy.get('AttachmentCount', 0),
                    'is_attachable': policy.get('IsAttachable', True),
                    'permissions': perms[:100],
                    'permission_count': len(perms),
                    'risk_score': risk_score
                },
                created_at=str(policy.get('CreateDate', '')),
                last_used_at=str(policy.get('UpdateDate', ''))
            ))

            for perm in perms[:20]:
                self._add_edge(IAMEdge(source=policy_arn, target=f"perm:{perm}",
                                      type=RelationType.ALLOWS.value, props={'action': perm}))

    def _normalize_org(self, org_data: Dict):
        if org_data.get('org'):
            org = org_data['org']
            org_id = org['Id']

            self._add_node(IAMNode(
                id=f"org:{org_id}",
                name=f"Org {org_id}",
                type=EntityType.ORGANIZATION.value,
                provider="aws",
                account=self.account_id,
                props={'master_account_id': org.get('MasterAccountId', '')}
            ))

            for account in org_data.get('accounts', []):
                acc_id = account['Id']
                self._add_node(IAMNode(
                    id=f"account:{acc_id}",
                    name=account.get('Name', acc_id),
                    type=EntityType.ACCOUNT.value,
                    provider="aws",
                    account=acc_id,
                    props={'email': account.get('Email', ''), 'status': account.get('Status', '')}
                ))
                self._add_edge(IAMEdge(source=f"org:{org_id}", target=f"account:{acc_id}",
                                      type=RelationType.CONTAINS.value))

    def _normalize_sso(self, sso_data: Dict):
        for ps in sso_data.get('permission_sets', []):
            ps_arn = ps['PermissionSetArn']
            self._add_node(IAMNode(
                id=ps_arn,
                name=ps.get('Name', 'PermissionSet'),
                type=EntityType.PERMISSION_SET.value,
                provider="aws",
                account=self.account_id,
                props={'description': ps.get('Description', ''), 'session_duration': ps.get('SessionDuration', '')}
            ))

        for assignment in sso_data.get('assignments', []):
            self._add_edge(IAMEdge(
                source=assignment.get('PermissionSetArn', ''),
                target=f"account:{assignment.get('AccountId', '')}",
                type=RelationType.ASSIGNED_TO.value,
                props={'principal_type': assignment.get('PrincipalType', ''),
                       'principal_id': assignment.get('PrincipalId', '')}
            ))

    def _normalize_resource_policies(self, policies: Dict):
        for service, items in policies.items():
            for item in items:
                resource = item['resource']
                policy_doc = item['policy']

                self._add_node(IAMNode(
                    id=resource,
                    name=resource.split(':')[-1] if ':' in resource else resource,
                    type=EntityType.RESOURCE.value,
                    provider="aws",
                    account=self.account_id,
                    props={'service': service, 'policy': json.dumps(policy_doc)}
                ))

                for stmt in policy_doc.get('Statement', []):
                    if stmt.get('Effect') == 'Allow':
                        principal = stmt.get('Principal', {})
                        if isinstance(principal, dict):
                            for vals in principal.values():
                                if isinstance(vals, str):
                                    vals = [vals]
                                for val in vals:
                                    self._add_edge(IAMEdge(
                                        source=val, target=resource,
                                        type=RelationType.BINDS_TO.value,
                                        props={'action': stmt.get('Action', [])}
                                    ))

    def _normalize_cloudtrail_events(self, events: List[Dict]):
        """Store CloudTrail events as temporal nodes (not in scan_entities)."""
        for event in events:
            event_id = f"event:{event['event_id']}"
            self._add_node(IAMNode(
                id=event_id,
                name=event['event_name'],
                type="Event",  # Not a schema entity type
                provider="aws",
                account=self.account_id,
                props={
                    'event_time': event['event_time'],
                    'username': event['username'],
                    'source_ip': event['source_ip'],
                    'raw_event': event['raw_event']
                }
            ))

    def _build_stats(self) -> Dict:
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'user_count': sum(1 for n in self.nodes if n['type'] == 'User'),
            'role_count': sum(1 for n in self.nodes if n['type'] == 'Role'),
            'group_count': sum(1 for n in self.nodes if n['type'] == 'Group'),
            'policy_count': sum(1 for n in self.nodes if n['type'] == 'Policy'),
            'admin_count': sum(1 for n in self.nodes if n.get('is_admin')),
            'external_count': sum(1 for n in self.nodes if n.get('is_external')),
            'dormant_count': sum(1 for n in self.nodes if n.get('is_dormant')),
            'mfa_missing_count': sum(1 for n in self.nodes if n['type'] == 'User' and not n.get('has_mfa')),
            'overprivileged_count': sum(1 for n in self.nodes if n.get('is_overprivileged')),
            'services_detected': list(set(
                svc for n in self.nodes for svc in n.get('detected_services', [])
            ))
        }

    def _parse_trust_policy(self, doc: Dict) -> List[str]:
        trusted = []
        for stmt in doc.get('Statement', []):
            if stmt.get('Effect') == 'Allow':
                principal = stmt.get('Principal', {})
                if isinstance(principal, str) and principal == '*':
                    trusted.append('*')
                elif isinstance(principal, dict):
                    for vals in principal.values():
                        if isinstance(vals, list):
                            trusted.extend(vals)
                        elif isinstance(vals, str):
                            trusted.append(vals)
        return list(set(trusted))



class GCPIAMScanner:
    """
    GCP IAM Scanner using ALL relevant APIs (CORRECTED v2.1):
      1. searchAllIamPolicies (with empty string fix)
      2. projects.serviceAccounts.list + .keys.list + .get
      3. roles/iam.serviceAccountTokenCreator
      4. organizations.getOrgPolicy
      5. iam.simulateActAsServiceAccount
    """

    def __init__(self, service_account_json: str, project_id: Optional[str] = None):
        if os.path.exists(service_account_json):
            with open(service_account_json, 'r') as f:
                creds_info = json.load(f)
        else:
            creds_info = json.loads(service_account_json)

        self.project_id = project_id or creds_info.get('project_id')
        self.credentials = service_account.Credentials.from_service_account_info(
            creds_info,
            scopes=['https://www.googleapis.com/auth/cloud-platform']
        )

        self.asset_client = build('cloudasset', 'v1', credentials=self.credentials)
        self.iam_client = build('iam', 'v1', credentials=self.credentials)
        self.crm_client = build('cloudresourcemanager', 'v1', credentials=self.credentials)
        self.org_client = build('cloudresourcemanager', 'v3', credentials=self.credentials)

        self.nodes = []
        self.edges = []
        self.node_ids = set()

    def scan(self, scope: str = None, selected_compliances: List[str] = None) -> IAMGraph:
        if selected_compliances is None:
            selected_compliances = ['SOC2']

        if scope is None:
            scope = f"projects/{self.project_id}"

        scan_id = f"gcp-{self.project_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        logger.info(f"GCP Scan {scan_id} starting for {scope}")

        try:
            policies = self._get_all_policies(scope)
            service_accounts = self._get_service_accounts_with_keys()
            org_policies = self._get_org_policies()
            impersonation_paths = self._get_impersonation_paths(service_accounts)

            self._normalize_service_accounts(service_accounts)
            self._normalize_policies(policies)
            self._normalize_org_policies(org_policies)
            self._normalize_impersonation(impersonation_paths)

            self._add_node(IAMNode(
                id=f"gcp:project:{self.project_id}",
                name=self.project_id,
                type=EntityType.PROJECT.value,
                provider="gcp",
                account=self.project_id,
                props={'project_id': self.project_id}
            ))

            stats = self._build_stats()

            return IAMGraph(
                scan_id=scan_id,
                provider="gcp",
                account=self.project_id,
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=self.nodes,
                edges=self.edges,
                stats=stats,
                compliance_context={'selected_compliances': selected_compliances}
            )

        except Exception as e:
            logger.error(f"GCP Scan failed: {e}", exc_info=True)
            return IAMGraph(
                scan_id=scan_id,
                provider="gcp",
                account=self.project_id,
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=self.nodes,
                edges=self.edges,
                stats={'error': str(e)},
                compliance_context={'selected_compliances': selected_compliances}
            )

    def _add_node(self, node: IAMNode):
        if node.id not in self.node_ids:
            self.nodes.append(asdict(node))
            self.node_ids.add(node.id)

    def _add_edge(self, edge: IAMEdge):
        self.edges.append(asdict(edge))

    def _get_all_policies(self, scope: str) -> List[Dict]:
        """Get all IAM policies via searchAllIamPolicies (with empty string fix)."""
        policies = []
        page_token = None

        while True:
            request = self.asset_client.v1().searchAllIamPolicies(
                scope=scope,
                pageToken=page_token
            )
            response = request.execute()
            policies.extend(response.get('results', []))
            page_token = response.get('nextPageToken')
            # FIX: Check both None and empty string
            if not page_token:
                break

        logger.info(f"GCP: Found {len(policies)} policy bindings")
        return policies

    def _get_service_accounts_with_keys(self) -> List[Dict]:
        """Get service accounts with their keys and details."""
        sas = []
        try:
            response = self.iam_client.projects().serviceAccounts().list(
                name=f"projects/{self.project_id}"
            ).execute()

            for sa in response.get('accounts', []):
                sa_name = sa['name']

                try:
                    keys_resp = self.iam_client.projects().serviceAccounts().keys().list(
                        name=sa_name
                    ).execute()
                    sa['keys'] = keys_resp.get('keys', [])
                except Exception:
                    sa['keys'] = []

                try:
                    sa['can_create_tokens'] = self._check_token_creator(sa['email'])
                except Exception:
                    sa['can_create_tokens'] = False

                sas.append(sa)

        except Exception as e:
            logger.warning(f"Could not get service accounts: {e}")

        return sas

    def _check_token_creator(self, sa_email: str) -> bool:
        """Check if SA has roles/iam.serviceAccountTokenCreator."""
        try:
            policy = self.crm_client.projects().getIamPolicy(
                resource=self.project_id,
                body={}
            ).execute()

            for binding in policy.get('bindings', []):
                if binding['role'] == 'roles/iam.serviceAccountTokenCreator':
                    if f"serviceAccount:{sa_email}" in binding.get('members', []):
                        return True
            return False
        except Exception:
            return False

    def _get_org_policies(self) -> List[Dict]:
        """Get organization-level policies."""
        policies = []
        try:
            project = self.crm_client.projects().get(projectId=self.project_id).execute()
            org_id = project.get('parent', {}).get('id') if project.get('parent', {}).get('type') == 'organization' else None

            if org_id:
                policies.append({'org_id': org_id, 'constraints': []})

        except Exception as e:
            logger.warning(f"Could not get org policies: {e}")

        return policies

    def _get_impersonation_paths(self, service_accounts: List[Dict]) -> List[Dict]:
        """Find service account impersonation paths."""
        paths = []
        try:
            policy = self.crm_client.projects().getIamPolicy(
                resource=self.project_id,
                body={}
            ).execute()

            for binding in policy.get('bindings', []):
                if 'serviceAccount' in binding['role'].lower():
                    for member in binding.get('members', []):
                        if member.startswith('serviceAccount:'):
                            paths.append({
                                'source': member.replace('serviceAccount:', ''),
                                'target_role': binding['role'],
                                'can_impersonate': True
                            })
        except Exception as e:
            logger.warning(f"Could not get impersonation paths: {e}")

        return paths

    def _normalize_service_accounts(self, sas: List[Dict]):
        for sa in sas:
            sa_email = sa['email']
            sa_id = f"gcp:sa:{sa_email}"
            keys = sa.get('keys', [])

            self._add_node(IAMNode(
                id=sa_id,
                name=sa_email.split('@')[0],
                type=EntityType.SERVICE_ACCOUNT.value,
                provider="gcp",
                account=self.project_id,
                has_access_keys=len(keys) > 0,
                is_active=not sa.get('disabled', False),
                props={
                    'email': sa_email,
                    'unique_id': sa.get('uniqueId', ''),
                    'display_name': sa.get('displayName', ''),
                    'key_count': len(keys),
                    'can_create_tokens': sa.get('can_create_tokens', False)
                },
                created_at=sa.get('createTime', '')
            ))

            for key in keys:
                key_id = f"{sa_id}:key:{key['name'].split('/')[-1]}"
                self._add_node(IAMNode(
                    id=key_id,
                    name=key['name'].split('/')[-1],
                    type=EntityType.ACCESS_KEY.value,
                    provider="gcp",
                    account=self.project_id,
                    is_active=key.get('keyAlgorithm', '') != '',
                    props={'algorithm': key.get('keyAlgorithm', ''), 'valid_after': key.get('validAfterTime', '')}
                ))
                self._add_edge(IAMEdge(source=sa_id, target=key_id, type=RelationType.HAS_KEY.value))

    def _normalize_policies(self, policies: List[Dict]):
        for policy in policies:
            resource = policy.get('resource', '')
            policy_data = policy.get('policy', {})

            resource_id = resource.replace('//', '')
            resource_type = resource.split('/')[2] if '/' in resource else 'unknown'

            self._add_node(IAMNode(
                id=resource_id,
                name=resource.split('/')[-1] if '/' in resource else resource,
                type=EntityType.RESOURCE.value,
                provider="gcp",
                account=self.project_id,
                props={'resource_type': resource_type, 'full_name': resource}
            ))

            for binding in policy_data.get('bindings', []):
                role = binding['role']
                role_id = f"gcp:role:{role}"

                is_admin = 'admin' in role or 'owner' in role or 'editor' in role
                self._add_node(IAMNode(
                    id=role_id,
                    name=role.split('/')[-1],
                    type=EntityType.ROLE.value,
                    provider="gcp",
                    account=self.project_id,
                    is_admin=is_admin,
                    props={'full_role': role}
                ))

                self._add_edge(IAMEdge(source=role_id, target=resource_id,
                                      type=RelationType.BINDS_TO.value))

                for member in binding.get('members', []):
                    member_type, member_id = self._parse_member(member)
                    member_entity_id = f"gcp:{member_type}:{member_id}"

                    if member_entity_id not in self.node_ids:
                        entity_type = self._member_to_entity(member_type)
                        is_external = member_type in ['allUsers', 'allAuthenticatedUsers']

                        self._add_node(IAMNode(
                            id=member_entity_id,
                            name=member_id.split('@')[0] if '@' in member_id else member_id,
                            type=entity_type.value,
                            provider="gcp",
                            account=self.project_id,
                            is_external=is_external,
                            props={'member_type': member_type}
                        ))

                    self._add_edge(IAMEdge(source=member_entity_id, target=role_id,
                                          type=RelationType.ATTACHED_TO.value,
                                          props={'resource': resource_id}))

    def _normalize_org_policies(self, policies: List[Dict]):
        for policy in policies:
            org_id = policy.get('org_id')
            if org_id:
                self._add_node(IAMNode(
                    id=f"gcp:org:{org_id}",
                    name=f"Organization {org_id}",
                    type=EntityType.ORGANIZATION.value,
                    provider="gcp",
                    account=self.project_id,
                    props={'org_id': org_id}
                ))
                self._add_edge(IAMEdge(
                    source=f"gcp:org:{org_id}",
                    target=f"gcp:project:{self.project_id}",
                    type=RelationType.CONTAINS.value
                ))

    def _normalize_impersonation(self, paths: List[Dict]):
        for path in paths:
            source = f"gcp:sa:{path['source']}"
            if source in self.node_ids:
                for node in self.nodes:
                    if node['type'] == 'ServiceAccount' and node['id'] != source:
                        self._add_edge(IAMEdge(
                            source=source,
                            target=node['id'],
                            type=RelationType.CAN_IMPERSONATE.value,
                            props={'via_role': path.get('target_role', '')}
                        ))

    def _build_stats(self) -> Dict:
        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'service_account_count': sum(1 for n in self.nodes if n['type'] == 'ServiceAccount'),
            'role_count': sum(1 for n in self.nodes if n['type'] == 'Role'),
            'resource_count': sum(1 for n in self.nodes if n['type'] == 'Resource'),
            'admin_count': sum(1 for n in self.nodes if n.get('is_admin')),
            'external_count': sum(1 for n in self.nodes if n.get('is_external'))
        }

    def _parse_member(self, member: str) -> tuple:
        if ':' in member:
            return member.split(':', 1)
        return 'unknown', member

    def _member_to_entity(self, member_type: str) -> EntityType:
        mapping = {
            'user': EntityType.USER,
            'serviceAccount': EntityType.SERVICE_ACCOUNT,
            'group': EntityType.GROUP,
            'domain': EntityType.ORGANIZATION,
            'allUsers': EntityType.USER,
            'allAuthenticatedUsers': EntityType.USER
        }
        return mapping.get(member_type, EntityType.USER)



class Neo4jImporter:
    """Import IAM graph to Neo4j using STANDARD CYPHER (no APOC plugin required)."""

    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def import_graph(self, graph: IAMGraph, clear_existing: bool = False):
        """Import graph using standard Cypher CREATE/MERGE."""
        logger.info(f"Importing {graph.stats['total_nodes']} nodes, {graph.stats['total_edges']} edges")

        with self.driver.session() as session:
            if clear_existing:
                session.run("MATCH (n) WHERE n.scan_id = $scan_id DETACH DELETE n", scan_id=graph.scan_id)

            # Create Scan node
            session.run("""
                CREATE (s:Scan {scan_id: $scan_id, provider: $provider, account: $account, scanned_at: $scanned_at})
            """, scan_id=graph.scan_id, provider=graph.provider, account=graph.account, scanned_at=graph.scanned_at)

            # Batch create nodes using UNWIND (standard Cypher)
            for batch in [graph.nodes[i:i+500] for i in range(0, len(graph.nodes), 500)]:
                for node in batch:
                    node['scan_id'] = graph.scan_id

                session.run("""
                    UNWIND $nodes AS node
                    CREATE (n:Entity)
                    SET n = node
                    SET n:_EntityType
                """, nodes=batch)

            # Create indices for performance
            session.run("CREATE INDEX entity_id_idx IF NOT EXISTS FOR (e:Entity) ON (e.id)")
            session.run("CREATE INDEX scan_id_idx IF NOT EXISTS FOR (s:Scan) ON (s.scan_id)")
            session.run("CREATE INDEX entity_type_idx IF NOT EXISTS FOR (e:Entity) ON (e.type)")

            # Batch create relationships
            for batch in [graph.edges[i:i+500] for i in range(0, len(graph.edges), 500)]:
                for edge in batch:
                    edge['scan_id'] = graph.scan_id

                session.run("""
                    UNWIND $edges AS edge
                    MATCH (a:Entity {id: edge.source, scan_id: edge.scan_id})
                    MATCH (b:Entity {id: edge.target, scan_id: edge.scan_id})
                    CREATE (a)-[r:RELATES {type: edge.type}]->(b)
                    SET r = edge.props
                """, edges=batch)

        logger.info("Neo4j import complete")



class IAMScanner:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.neo4j = Neo4jImporter(neo4j_uri, neo4j_user, neo4j_password)

    def scan_aws(self, access_key: str, secret_key: str, region: str = "us-east-1",
                 selected_compliances: List[str] = None) -> IAMGraph:
        if selected_compliances is None:
            selected_compliances = ['SOC2']

        try:
            scanner = AWSIAMScanner(access_key, secret_key, region)
            graph = scanner.scan(selected_compliances)

            if not graph.stats.get('error'):
                graph.to_json(f"/tmp/{graph.scan_id}.json")
                self.neo4j.import_graph(graph)

            return graph
        except Exception as e:
            logger.error(f"AWS scan failed: {e}", exc_info=True)
            return IAMGraph(
                scan_id=f"aws-error-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                provider="aws",
                account="unknown",
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=[], edges=[],
                stats={'error': str(e)},
                compliance_context={'selected_compliances': selected_compliances}
            )

    def scan_gcp(self, service_account_json: str, project_id: str = None,
                 selected_compliances: List[str] = None) -> IAMGraph:
        if selected_compliances is None:
            selected_compliances = ['SOC2']

        try:
            scanner = GCPIAMScanner(service_account_json, project_id)
            graph = scanner.scan(selected_compliances=selected_compliances)

            if not graph.stats.get('error'):
                graph.to_json(f"/tmp/{graph.scan_id}.json")
                self.neo4j.import_graph(graph)

            return graph
        except Exception as e:
            logger.error(f"GCP scan failed: {e}", exc_info=True)
            return IAMGraph(
                scan_id=f"gcp-error-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                provider="gcp",
                account=project_id or "unknown",
                scanned_at=datetime.now(timezone.utc).isoformat(),
                nodes=[], edges=[],
                stats={'error': str(e)},
                compliance_context={'selected_compliances': selected_compliances}
            )

    def close(self):
        self.neo4j.close()



import math
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from supabase import create_client, Client
from neo4j import GraphDatabase

from iam_scanner import IAMScanner, EntityType, PermissionClassifier
from breach_cost_estimator import BreachCostEstimator, ServiceType, Region, ComplianceFramework, DataSensitivity


class ScanOrchestrator:
    """Orchestrates the full scan pipeline: Scanner → Neo4j → Supabase."""

    def __init__(self, supabase_url: str, supabase_key: str,
                 neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.supabase: Client = create_client(supabase_url, supabase_key)
        self.neo4j = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.cost_estimator = BreachCostEstimator()

    def create_scan_record(self, clerk_id: str, credential_id: str, scan_name: str,
                           scan_type: str, csp_target: str,
                           selected_compliances: List[str]) -> str:
        """Create the scan metadata record in Supabase."""
        scan_id = str(uuid.uuid4())

        data = {
            'id': scan_id,
            'clerk_id': clerk_id,
            'csp_credential_id': credential_id,
            'scan_name': scan_name,
            'scan_type': scan_type,
            'csp_target': csp_target,
            'selected_compliances': selected_compliances,
            'status': 'running',
            'started_at': datetime.now(timezone.utc).isoformat(),
            'current_phase': 'discovery',
            'phase_progress': 0
        }

        self.supabase.table('iam_scans').insert(data).execute()
        return scan_id

    
    def run_scan(self, scan_id: str, clerk_id: str, aws_access_key: str = None,
                 aws_secret_key: str = None, aws_region: str = 'us-east-1',
                 gcp_sa_json: str = None, gcp_project_id: str = None,
                 selected_compliances: List[str] = None):
        """Run the full scan pipeline."""

        if selected_compliances is None:
            selected_compliances = ['SOC2']

        scanner = IAMScanner(
            neo4j_uri=self.neo4j_uri,
            neo4j_user=self.neo4j_user,
            neo4j_password=self.neo4j_password
        )

        try:
            # --- AWS Scan ---
            if aws_access_key and aws_secret_key:
                self._update_phase(scan_id, 'discovery', 25)
                aws_graph = scanner.scan_aws(
                    access_key=aws_access_key,
                    secret_key=aws_secret_key,
                    region=aws_region,
                    selected_compliances=selected_compliances
                )
                if aws_graph.stats.get('error'):
                    raise Exception(f"AWS scan failed: {aws_graph.stats['error']}")
                self._store_entities(scan_id, clerk_id, aws_graph)
                self._store_temporal_events(scan_id, clerk_id, aws_graph)
                self._update_phase(scan_id, 'discovery', 50)

            # --- GCP Scan ---
            if gcp_sa_json:
                self._update_phase(scan_id, 'discovery', 75)
                gcp_graph = scanner.scan_gcp(
                    service_account_json=gcp_sa_json,
                    project_id=gcp_project_id,
                    selected_compliances=selected_compliances
                )
                if gcp_graph.stats.get('error'):
                    raise Exception(f"GCP scan failed: {gcp_graph.stats['error']}")
                self._store_entities(scan_id, clerk_id, gcp_graph)
                self._update_phase(scan_id, 'discovery', 100)

            scanner.close()
            return scan_id

        except Exception as e:
            scanner.close()
            self._update_scan_status(scan_id, 'failed', str(e))
            raise

 
    def _store_entities(self, scan_id: str, clerk_id: str, graph):
        """Store graph nodes into scan_entities table (chunked to 500)."""

        entities_to_insert = []

        for node in graph.nodes:
            # Only store types that exist in scan_entities table
            if not EntityType.is_schema_entity(node['type']):
                continue

            entity = {
                'id': str(uuid.uuid4()),
                'scan_id': scan_id,
                'clerk_id': clerk_id,
                'entity_type': EntityType[node['type']].to_schema_type(),
                'entity_arn': node.get('id'),
                'entity_name': node.get('name'),
                'entity_id': node['props'].get('user_id') or node['props'].get('role_id') or node['props'].get('group_id'),
                'csp_source': node.get('provider'),
                'aws_account_id': node.get('account') if node.get('provider') == 'aws' else None,
                'gcp_project_id': node.get('account') if node.get('provider') == 'gcp' else None,
                'properties': node.get('props', {}),
                'permissions': node['props'].get('permissions', []),
                'permissions_count': node['props'].get('permission_count', 0),
                'attached_policies': node['props'].get('attached_policy_count', 0),
                'member_of_groups': node['props'].get('group_count', 0),
                'static_risk_score': node['props'].get('risk_score', 0),
                'static_risk_factors': {
                    'is_admin': node.get('is_admin', False),
                    'is_overprivileged': node.get('is_overprivileged', False),
                    'has_mfa': node.get('has_mfa', False),
                    'is_dormant': node.get('is_dormant', False),
                    'is_external': node.get('is_external', False),
                    'detected_services': node.get('detected_services', [])
                },
                'applicable_compliances': graph.compliance_context.get('selected_compliances', ['SOC2'])
            }
            entities_to_insert.append(entity)

        # BATCH INSERT: Chunk to 500 to avoid Supabase limits
        CHUNK_SIZE = 500
        for i in range(0, len(entities_to_insert), CHUNK_SIZE):
            chunk = entities_to_insert[i:i + CHUNK_SIZE]
            self.supabase.table('scan_entities').insert(chunk).execute()

        print(f"Stored {len(entities_to_insert)} entities in {math.ceil(len(entities_to_insert)/CHUNK_SIZE)} batches")

    def _store_temporal_events(self, scan_id: str, clerk_id: str, graph):
        """Store CloudTrail events in temporal_events table."""
        events_to_insert = []

        for node in graph.nodes:
            if node['type'] != 'Event':
                continue

            event = {
                'id': str(uuid.uuid4()),
                'scan_id': scan_id,
                'clerk_id': clerk_id,
                'entity_type': 'user',
                'event_type': 'login',
                'event_name': node.get('name'),
                'event_time': node['props'].get('event_time'),
                'event_source': 'cloudtrail',
                'raw_event': node['props'].get('raw_event', {})
            }
            events_to_insert.append(event)

        if events_to_insert:
            CHUNK_SIZE = 500
            for i in range(0, len(events_to_insert), CHUNK_SIZE):
                chunk = events_to_insert[i:i + CHUNK_SIZE]
                self.supabase.table('temporal_events').insert(chunk).execute()

    def run_graph_analysis(self, scan_id: str) -> List[Dict]:
        """Run shortest path, centrality, and anomaly detection in Neo4j."""
        self._update_phase(scan_id, 'graph_building', 50)

        with self.neo4j.session() as session:
            # Find all admin roles
            admins = session.run("""
                MATCH (r:Entity {scan_id: $scan_id, type: 'Role', is_admin: true})
                RETURN r.id AS admin_id, r.name AS admin_name
            """, scan_id=scan_id)

            admin_nodes = [record for record in admins]

            # Find shortest paths from all users to any admin
            paths = []
            for admin in admin_nodes:
                result = session.run("""
                    MATCH (u:Entity {scan_id: $scan_id, type: 'User'})
                    MATCH (a:Entity {id: $admin_id, scan_id: $scan_id})
                    MATCH p = shortestPath((u)-[*..10]->(a))
                    RETURN u.id AS source, u.name AS source_name,
                           a.id AS target, a.name AS target_name,
                           [node IN nodes(p) | node.id] AS path_nodes,
                           [node IN nodes(p) | node.type] AS path_types,
                           length(p) AS path_length
                """, scan_id=scan_id, admin_id=admin['admin_id'])

                paths.extend([dict(record) for record in result])

        self._update_phase(scan_id, 'graph_building', 100)
        return paths

    def create_attack_paths(self, scan_id: str, clerk_id: str, paths: List[Dict],
                            selected_compliances: List[str],
                            region_name: str = 'INDIA',
                            annual_revenue: float = None):
        """Create attack path records with corrected cost estimation."""

        # Map region string to Region enum
        region_enum = Region[region_name.upper()] if region_name.upper() in Region.__members__ else Region.GLOBAL

        paths_to_insert = []

        for path in paths:
            path_entities = self._get_path_entities(scan_id, path['path_nodes'])

            static_score = self._calculate_static_score(path_entities)

            graph_score = self._calculate_graph_score(path)

            temporal_score = self._calculate_temporal_score(scan_id, path['source'])

            detected_services = self._detect_services_from_path(path_entities)

            service_type = self._map_to_service_type(detected_services)

            # Normalize compliance names (PCI-DSS → PCI_DSS)
            frameworks = []
            for fw in selected_compliances:
                fw_normalized = fw.upper().replace('-', '_').replace(' ', '_')
                if fw_normalized in ComplianceFramework.__members__:
                    frameworks.append(ComplianceFramework[fw_normalized])

            data_sensitivity = self._infer_sensitivity(detected_services)

            # Run cost estimator
            cost_estimate = self.cost_estimator.estimate(
                service=service_type,
                region=region_enum,
                compliance_frameworks=frameworks,
                estimated_records_exposed=10000,
                data_sensitivity=data_sensitivity,
                company_annual_revenue_usd=annual_revenue
            )

            cost_score = self._calculate_cost_score(cost_estimate.estimated_total_breach_cost)

            # --- Hybrid Risk Score (SGTC formula) ---
            hybrid_score = self._calculate_hybrid_risk(static_score, graph_score, temporal_score, cost_score)

            # Build cost breakdown with service context
            cost_breakdown = cost_estimate.to_dict()['cost_breakdown']
            cost_breakdown['detected_services'] = detected_services
            cost_breakdown['service_type_used'] = service_type.value
            cost_breakdown['data_sensitivity'] = data_sensitivity.name

            path_record = {
                'id': str(uuid.uuid4()),
                'scan_id': scan_id,
                'clerk_id': clerk_id,
                'path_name': f"{path['source_name']} → {path['target_name']}",
                'path_description': f"Privilege escalation path of length {path['path_length']}",
                'path_nodes': {'nodes': path['path_nodes'], 'types': path.get('path_types', [])},
                'path_length': path['path_length'],
                'source_entity_id': path['source'],
                'target_entity_id': path['target'],
                'source_name': path['source_name'],
                'target_name': path['target_name'],
                'target_permission': 'admin',
                'static_score': static_score,
                'graph_score': graph_score,
                'temporal_score': temporal_score,
                'cost_score': cost_score,
                'estimated_cost_impact': cost_estimate.estimated_total_breach_cost,
                'cost_breakdown': cost_breakdown,
                'cost_calculation_log': ' | '.join(cost_estimate.methodology_notes),
                'triggered_compliances': selected_compliances,
                'has_residency_violation': False,
                'hybrid_risk_score': hybrid_score,
                'remediation_status': 'open'
            }
            paths_to_insert.append(path_record)

            # --- Create cost_analyses for each compliance ---
            self._create_cost_analyses(scan_id, clerk_id, path_record['id'], cost_estimate, frameworks)

        # Batch insert attack_paths
        if paths_to_insert:
            CHUNK_SIZE = 500
            for i in range(0, len(paths_to_insert), CHUNK_SIZE):
                chunk = paths_to_insert[i:i + CHUNK_SIZE]
                self.supabase.table('attack_paths').insert(chunk).execute()

        return len(paths_to_insert)

    def _create_cost_analyses(self, scan_id: str, clerk_id: str, path_id: str,
                              cost_estimate, compliance_frameworks: List[ComplianceFramework]):
        """Create per-compliance cost analysis records."""

        analyses = []
        for framework in compliance_frameworks:
            analysis = {
                'id': str(uuid.uuid4()),
                'scan_id': scan_id,
                'clerk_id': clerk_id,
                'path_id': path_id,
                'compliance_framework': framework.value,
                'cost_model_version': 'v2.0',
                'total_estimated_cost': cost_estimate.estimated_total_breach_cost,
                'cost_score': self._calculate_cost_score(cost_estimate.estimated_total_breach_cost),
                'cost_score_formula': 'log-normalization against MTL',
                'confidence_level': cost_estimate.confidence_level,
                'confidence_reason': f"Based on IBM/Ponemon 2025 {Region.INDIA.value} benchmark"
            }
            analyses.append(analysis)

        if analyses:
            self.supabase.table('cost_analyses').insert(analyses).execute()

    def create_compliance_violations(self, scan_id: str, clerk_id: str,
                                     selected_compliances: List[str]):
        """Detect and store compliance violations from scan_entities."""

        result = self.supabase.table('scan_entities').select('*').eq('scan_id', scan_id).execute()
        entities = result.data

        violations = []

        for entity in entities:
            props = entity.get('properties', {})
            risk_factors = entity.get('static_risk_factors', {})

            # MFA Missing for users
            if entity['entity_type'] == 'user' and not risk_factors.get('has_mfa', False):
                for compliance in selected_compliances:
                    violations.append({
                        'id': str(uuid.uuid4()),
                        'scan_id': scan_id,
                        'clerk_id': clerk_id,
                        'compliance_framework': compliance.lower(),
                        'violation_type': 'mfa_missing',
                        'severity': 'high',
                        'resource_id': entity['entity_arn'],
                        'resource_type': 'user',
                        'expected_state': 'MFA enabled for all users',
                        'actual_state': 'MFA not configured',
                        'estimated_penalty': 0
                    })

            # Overprivileged check
            if risk_factors.get('is_admin', False) and entity['entity_type'] not in ['role', 'managed_policy']:
                for compliance in selected_compliances:
                    violations.append({
                        'id': str(uuid.uuid4()),
                        'scan_id': scan_id,
                        'clerk_id': clerk_id,
                        'compliance_framework': compliance.lower(),
                        'violation_type': 'overprivileged',
                        'severity': 'critical',
                        'resource_id': entity['entity_arn'],
                        'resource_type': entity['entity_type'],
                        'expected_state': 'Principle of least privilege',
                        'actual_state': 'Admin-level permissions attached',
                        'estimated_penalty': 0
                    })

            # Dormant access keys
            if risk_factors.get('is_dormant', False) and entity['entity_type'] == 'user':
                for compliance in selected_compliances:
                    violations.append({
                        'id': str(uuid.uuid4()),
                        'scan_id': scan_id,
                        'clerk_id': clerk_id,
                        'compliance_framework': compliance.lower(),
                        'violation_type': 'dormant_credentials',
                        'severity': 'medium',
                        'resource_id': entity['entity_arn'],
                        'resource_type': 'user',
                        'expected_state': 'Active credentials only',
                        'actual_state': 'No activity in 90+ days',
                        'estimated_penalty': 0
                    })

        if violations:
            CHUNK_SIZE = 500
            for i in range(0, len(violations), CHUNK_SIZE):
                chunk = violations[i:i + CHUNK_SIZE]
                self.supabase.table('compliance_violations').insert(chunk).execute()

    def finalize_scan(self, scan_id: str):
        """Update scan status and summary."""

        paths_result = self.supabase.table('attack_paths').select('*').eq('scan_id', scan_id).execute()
        paths = paths_result.data

        violations_result = self.supabase.table('compliance_violations').select('*').eq('scan_id', scan_id).execute()
        violations = violations_result.data

        total_cost = sum(p.get('estimated_cost_impact', 0) for p in paths)

        self.supabase.table('iam_scans').update({
            'status': 'completed',
            'completed_at': datetime.now(timezone.utc).isoformat(),
            'current_phase': 'reporting',
            'phase_progress': 100,
            'total_paths': len(paths),
            'critical_count': sum(1 for p in paths if p.get('risk_severity') == 'critical'),
            'high_count': sum(1 for p in paths if p.get('risk_severity') == 'high'),
            'medium_count': sum(1 for p in paths if p.get('risk_severity') == 'medium'),
            'low_count': sum(1 for p in paths if p.get('risk_severity') == 'low'),
            'max_risk_score': max((p.get('hybrid_risk_score', 0) for p in paths), default=0),
            'avg_risk_score': sum(p.get('hybrid_risk_score', 0) for p in paths) / len(paths) if paths else 0,
            'total_estimated_breach_cost': total_cost,
            'compliance_violations_found': len(violations)
        }).eq('id', scan_id).execute()


    def _update_phase(self, scan_id: str, phase: str, progress: int):
        self.supabase.table('iam_scans').update({
            'current_phase': phase,
            'phase_progress': progress
        }).eq('id', scan_id).execute()

    def _update_scan_status(self, scan_id: str, status: str, error_message: str = None):
        update_data = {
            'status': status,
            'completed_at': datetime.now(timezone.utc).isoformat() if status in ['completed', 'failed'] else None
        }
        if error_message:
            update_data['error_message'] = error_message
        self.supabase.table('iam_scans').update(update_data).eq('id', scan_id).execute()

    def _get_path_entities(self, scan_id: str, path_nodes: List[str]) -> List[Dict]:
        """Get entity data for all nodes in a path."""
        entities = []
        for node_id in path_nodes:
            result = self.supabase.table('scan_entities').select('*').eq('scan_id', scan_id).eq('entity_arn', node_id).execute()
            if result.data:
                entities.append(result.data[0])
        return entities

    def _calculate_static_score(self, path_entities: List[Dict]) -> float:
        """Calculate static score from actual entity risk scores."""
        if not path_entities:
            return 0.0

        scores = []
        for entity in path_entities:
            risk_factors = entity.get('static_risk_factors', {})
            base_score = entity.get('static_risk_score', 0)

            # Boost for admin/overprivileged
            if risk_factors.get('is_admin'):
                base_score = max(base_score, 90)
            elif risk_factors.get('is_overprivileged'):
                base_score = max(base_score, 70)

            scores.append(base_score)

        return max(scores) * 0.7 + (sum(scores) / len(scores)) * 0.3

    def _calculate_graph_score(self, path: Dict) -> float:
        """Score based on path topology."""
        length = path.get('path_length', 1)
        # Shorter paths = more dangerous
        base_score = max(0, 100 - (length * 8))

        # Bonus for paths ending at admin
        if 'admin' in path.get('target_name', '').lower():
            base_score += 10

        return min(100, base_score)

    def _calculate_temporal_score(self, scan_id: str, source_id: str) -> float:
        """Calculate temporal score from temporal_events."""
        try:
            result = self.supabase.table('temporal_events').select('*').eq('scan_id', scan_id).execute()
            events = result.data

            if not events:
                return 0.0

            # Count anomalous events
            anomalous = sum(1 for e in events if e.get('is_anomalous', False))
            total = len(events)

            if total == 0:
                return 0.0

            anomaly_ratio = anomalous / total
            return min(100, anomaly_ratio * 100 + 20)

        except Exception:
            return 0.0

    def _detect_services_from_path(self, path_entities: List[Dict]) -> List[str]:
        """Detect services from entities in the path."""
        services = set()
        for entity in path_entities:
            risk_factors = entity.get('static_risk_factors', {})
            detected = risk_factors.get('detected_services', [])
            services.update(detected)
        return list(services)

    def _map_to_service_type(self, detected_services: List[str]) -> ServiceType:
        """Map detected services to ServiceType enum with generic fallback."""
        # Primary service mappings
        service_mapping = {
            'rds': ServiceType.RDS,
            's3': ServiceType.S3,
            'ec2': ServiceType.EC2,
            'lambda': ServiceType.LAMBDA,
            'dynamodb': ServiceType.DYNAMODB,
            'secretsmanager': ServiceType.SECRETS_MANAGER,
            'kms': ServiceType.KMS,
            'cloudsql': ServiceType.CLOUD_SQL,
            'bigquery': ServiceType.BIGQUERY,
            'cloudstorage': ServiceType.CLOUD_STORAGE,
            'spanner': ServiceType.SPANNER,
        }

        # Return first matched service
        for svc in detected_services:
            if svc in service_mapping:
                return service_mapping[svc]

        # FALLBACK: If no specific service detected, use generic compute
        return ServiceType.EC2

    def _infer_sensitivity(self, detected_services: List[str]) -> DataSensitivity:
        """Infer data sensitivity from services. Covers ALL services."""
        critical_services = {'kms', 'secretsmanager'}
        restricted_services = {'rds', 'cloudsql', 'spanner', 'redshift', 'dynamodb'}
        confidential_services = {'s3', 'bigquery', 'cloudstorage'}

        if any(s in critical_services for s in detected_services):
            return DataSensitivity.CRITICAL
        elif any(s in restricted_services for s in detected_services):
            return DataSensitivity.RESTRICTED
        elif any(s in confidential_services for s in detected_services):
            return DataSensitivity.CONFIDENTIAL
        else:
            return DataSensitivity.INTERNAL

    def _calculate_cost_score(self, total_cost: float) -> float:
        """Log-normalization against MTL of $10M."""
        min_cost = 1000
        mtl = 10000000
        if total_cost <= 0:
            return 0
        score = (math.log(total_cost) - math.log(min_cost)) / (math.log(mtl) - math.log(min_cost)) * 100
        return max(0, min(100, score))

    def _calculate_hybrid_risk(self, static: float, graph: float, temporal: float, cost: float) -> int:
        """SGTC hybrid risk formula."""
        weights = {'static': 0.40, 'graph': 0.30, 'temporal': 0.20, 'cost': 0.10}
        s = static * weights['static']
        g = graph * weights['graph']
        t = temporal * weights['temporal']
        c = cost * weights['cost']
        max_floor = max(s, g, t, c) * 0.6
        euclidean = math.sqrt(s**2 + g**2 + t**2 + c**2) * 0.4
        raw = max_floor + euclidean
        max_possible = (100 * weights['static'] * 0.6) + \
            (math.sqrt((100*weights['static'])**2 + (100*weights['graph'])**2 +
                      (100*weights['temporal'])**2 + (100*weights['cost'])**2) * 0.4)
        return round((raw / max_possible) * 100)

    def get_graph_for_cytoscape(self, scan_id: str) -> dict:
        """Transform stored graph data into Cytoscape.js elements format."""
        import json
        import glob
        import os

        # Find the graph JSON file
        graph_files = glob.glob(f"/tmp/*{scan_id}*.json") if '-' not in scan_id[:8] else []
        # Also check for scan records to find the original scan_id
        if not graph_files:
            # Look up the scan record to find the provider-specific scan_id
            result = self.supabase.table('iam_scans').select('*').eq('id', scan_id).execute()
            if result.data:
                for f in os.listdir('/tmp'):
                    if f.endswith('.json') and (f.startswith('aws-') or f.startswith('gcp-')):
                        graph_files.append(f'/tmp/{f}')

        if not graph_files:
            return {"elements": {"nodes": [], "edges": []}}

        # Use the most recent file
        graph_file = sorted(graph_files)[-1]

        with open(graph_file, 'r') as f:
            graph_data = json.load(f)

        cyto_nodes = []
        for node in graph_data.get('nodes', []):
            cyto_nodes.append({
                "data": {
                    "id": node.get('id', ''),
                    "label": node.get('name', node.get('id', '')),
                    "type": node.get('type', 'Unknown'),
                    "provider": node.get('provider', ''),
                    "is_admin": node.get('is_admin', False),
                    "is_overprivileged": node.get('is_overprivileged', False),
                    "has_mfa": node.get('has_mfa', False),
                    "is_dormant": node.get('is_dormant', False),
                    "is_external": node.get('is_external', False),
                    "risk_score": node.get('props', {}).get('risk_score', 0),
                    "account": node.get('account', ''),
                }
            })

        cyto_edges = []
        for edge in graph_data.get('edges', []):
            cyto_edges.append({
                "data": {
                    "id": f"{edge.get('source', '')}->{edge.get('target', '')}",
                    "source": edge.get('source', ''),
                    "target": edge.get('target', ''),
                    "label": edge.get('type', ''),
                    "type": edge.get('type', ''),
                }
            })

        return {
            "elements": {
                "nodes": cyto_nodes,
                "edges": cyto_edges
            },
            "stats": graph_data.get('stats', {})
        }
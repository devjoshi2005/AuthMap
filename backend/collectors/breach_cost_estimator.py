from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum
import json


class Region(Enum):
    INDIA = "india"
    US = "us"
    EU = "eu"
    UK = "uk"
    MIDDLE_EAST = "middle_east"
    CANADA = "canada"
    BRAZIL = "brazil"
    GLOBAL = "global"

class ComplianceFramework(Enum):
    DPDP = "dpdp"
    RBI = "rbi"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    IRDAI = "irdai"
    SEBI = "sebi"
    IT_ACT = "it_act"

class DataSensitivity(Enum):
    PUBLIC = 1.0
    INTERNAL = 1.5
    CONFIDENTIAL = 2.5
    RESTRICTED = 4.0
    CRITICAL = 6.0

class ServiceType(Enum):
    RDS = "aws_rds"
    DYNAMODB = "aws_dynamodb"
    S3 = "aws_s3"
    LAMBDA = "aws_lambda"
    EC2 = "aws_ec2"
    EKS = "aws_eks"
    SECRETS_MANAGER = "aws_secrets_manager"
    KMS = "aws_kms"
    CLOUD_SQL = "gcp_cloud_sql"
    SPANNER = "gcp_spanner"
    BIGQUERY = "gcp_bigquery"
    CLOUD_STORAGE = "gcp_cloud_storage"
    CLOUD_FUNCTIONS = "gcp_cloud_functions"
    GKE = "gcp_gke"
    SECRET_MANAGER = "gcp_secret_manager"
    CLOUD_KMS = "gcp_cloud_kms"


REGION_BASE_COSTS = {
    Region.US: 10_220_000,
    Region.MIDDLE_EAST: 7_290_000,
    Region.EU: 6_240_000,
    Region.CANADA: 4_840_000,
    Region.UK: 4_140_000,
    Region.INDIA: 2_510_000,
    Region.BRAZIL: 1_220_000,
    Region.GLOBAL: 4_440_000,
}

PER_RECORD_BASE = {
    Region.US: 165,
    Region.EU: 101,
    Region.INDIA: 61,
    Region.GLOBAL: 108,
}

REGULATORY_MAXIMUMS = {
    ComplianceFramework.DPDP: {
        "security_failure": 250_000_000,
        "breach_notification_failure": 200_000_000,
        "children_data_violation": 200_000_000,
        "sdf_violation": 150_000_000,
        "general_violation": 50_000_000,
        "currency": "INR",
        "usd_conversion": 0.012,
    },
    ComplianceFramework.RBI: {
        "procedural": 10_000_000,
        "significant_control": 100_000_000,
        "major_incident": 100_000_000,
        "currency": "INR",
        "usd_conversion": 0.012,
    },
    ComplianceFramework.PCI_DSS: {
        "per_record_low": 50,
        "per_record_high": 90,
        "monthly_noncompliance_low": 5_000,
        "monthly_noncompliance_high": 100_000,
        "currency": "USD",
        "usd_conversion": 1.0,
    },
    ComplianceFramework.GDPR: {
        "tier1_max": 10_000_000,
        "tier2_max": 20_000_000,
        "currency": "EUR",
        "usd_conversion": 1.08,
    },
    ComplianceFramework.SOC2: {
        "estimated_revenue_impact_pct": 0.15,
        "currency": "USD",
        "usd_conversion": 1.0,
    },
    ComplianceFramework.HIPAA: {
        "tier1_per_violation": 137,
        "tier4_per_violation": 2_067_813,
        "currency": "USD",
        "usd_conversion": 1.0,
    },
}

SERVICE_DATA_PROFILES = {
    ServiceType.RDS: {
        "typical_data_types": ["transaction_logs", "customer_pii", "financial_records", "health_records"],
        "default_sensitivity": DataSensitivity.RESTRICTED,
        "compliance_relevance": [ComplianceFramework.RBI, ComplianceFramework.PCI_DSS, ComplianceFramework.DPDP, ComplianceFramework.HIPAA],
        "unit_of_measure": "rows",
    },
    ServiceType.DYNAMODB: {
        "typical_data_types": ["user_profiles", "session_data", "transaction_metadata"],
        "default_sensitivity": DataSensitivity.CONFIDENTIAL,
        "compliance_relevance": [ComplianceFramework.DPDP, ComplianceFramework.RBI],
        "unit_of_measure": "items",
    },
    ServiceType.S3: {
        "typical_data_types": ["documents", "backups", "logs", "media"],
        "default_sensitivity": DataSensitivity.INTERNAL,
        "compliance_relevance": [ComplianceFramework.DPDP, ComplianceFramework.SOC2],
        "unit_of_measure": "objects",
    },
    ServiceType.SECRETS_MANAGER: {
        "typical_data_types": ["api_keys", "passwords", "certificates"],
        "default_sensitivity": DataSensitivity.CRITICAL,
        "compliance_relevance": [ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS],
        "unit_of_measure": "secrets",
    },
    ServiceType.CLOUD_SQL: {
        "typical_data_types": ["transaction_logs", "card_tokens", "account_balances", "customer_pii"],
        "default_sensitivity": DataSensitivity.RESTRICTED,
        "compliance_relevance": [ComplianceFramework.RBI, ComplianceFramework.PCI_DSS, ComplianceFramework.DPDP],
        "unit_of_measure": "rows",
    },
    ServiceType.SPANNER: {
        "typical_data_types": ["global_ledgers", "transactional_data", "financial_records"],
        "default_sensitivity": DataSensitivity.CRITICAL,
        "compliance_relevance": [ComplianceFramework.RBI, ComplianceFramework.PCI_DSS, ComplianceFramework.DPDP],
        "unit_of_measure": "rows",
    },
    ServiceType.BIGQUERY: {
        "typical_data_types": ["analytics_data", "aggregated_metrics", "ml_training_data"],
        "default_sensitivity": DataSensitivity.CONFIDENTIAL,
        "compliance_relevance": [ComplianceFramework.DPDP, ComplianceFramework.SOC2],
        "unit_of_measure": "rows",
    },
    ServiceType.CLOUD_STORAGE: {
        "typical_data_types": ["documents", "backups", "archives"],
        "default_sensitivity": DataSensitivity.INTERNAL,
        "compliance_relevance": [ComplianceFramework.DPDP, ComplianceFramework.SOC2],
        "unit_of_measure": "objects",
    },
    ServiceType.SECRET_MANAGER: {
        "typical_data_types": ["api_keys", "credentials", "certificates"],
        "default_sensitivity": DataSensitivity.CRITICAL,
        "compliance_relevance": [ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS],
        "unit_of_measure": "secrets",
    },
}


@dataclass
class BreachCostEstimate:
    service: str
    region: str
    compliance_frameworks: List[str]
    estimated_records_exposed: int
    base_cost_per_record: float
    sensitivity_multiplier: float
    compliance_multiplier: float
    region_multiplier: float
    estimated_per_record_cost: float
    estimated_total_breach_cost: float
    regulatory_max_penalty: float
    estimated_penalty_range: Tuple[float, float]
    methodology_notes: List[str]
    data_sources: List[str]
    confidence_level: str

    def to_dict(self) -> Dict:
        return {
            "service": self.service,
            "region": self.region,
            "compliance_frameworks": self.compliance_frameworks,
            "estimated_records_exposed": self.estimated_records_exposed,
            "cost_breakdown": {
                "base_cost_per_record_usd": round(self.base_cost_per_record, 2),
                "sensitivity_multiplier": self.sensitivity_multiplier,
                "compliance_multiplier": self.compliance_multiplier,
                "region_multiplier": self.region_multiplier,
                "final_per_record_cost_usd": round(self.estimated_per_record_cost, 2),
                "total_records_cost_usd": round(self.estimated_per_record_cost * self.estimated_records_exposed, 2),
                "total_estimated_breach_cost_usd": round(self.estimated_total_breach_cost, 2),
                "regulatory_max_penalty_usd": round(self.regulatory_max_penalty, 2),
                "estimated_penalty_range_usd": [
                    round(self.estimated_penalty_range[0], 2),
                    round(self.estimated_penalty_range[1], 2)
                ],
            },
            "transparency": {
                "methodology_notes": self.methodology_notes,
                "data_sources": self.data_sources,
                "confidence_level": self.confidence_level,
                "disclaimer": "This is an ESTIMATE based on industry benchmarks and regulatory frameworks. Actual penalties are discretionary and determined by regulatory authorities based on case-specific factors."
            }
        }


class BreachCostEstimator:
    def __init__(self):
        self.sources = [
            "IBM Security & Ponemon Institute: Cost of a Data Breach Report 2025",
            "Digital Personal Data Protection Act, 2023 (India)",
            "Reserve Bank of India: Master Directions on Cyber Security",
            "PCI Security Standards Council: PCI-DSS v4.0",
            "GDPR Article 83: Administrative Fines",
        ]

    def estimate(self, service, region, compliance_frameworks, estimated_records_exposed,
                 data_sensitivity=None, company_annual_revenue_usd=None):
        profile = SERVICE_DATA_PROFILES.get(service, {
            "default_sensitivity": DataSensitivity.INTERNAL,
            "compliance_relevance": [ComplianceFramework.SOC2],
            "unit_of_measure": "records",
        })
        sensitivity = data_sensitivity or profile["default_sensitivity"]
        base_per_record = PER_RECORD_BASE.get(region, PER_RECORD_BASE[Region.GLOBAL])
        sensitivity_mult = sensitivity.value
        compliance_mult = self._calculate_compliance_multiplier(compliance_frameworks)
        region_mult = self._calculate_region_multiplier(region, compliance_frameworks)
        adjusted_per_record = base_per_record * sensitivity_mult * compliance_mult * region_mult
        adjusted_per_record = min(adjusted_per_record, 500.0)
        total_from_records = adjusted_per_record * estimated_records_exposed
        region_total_max = REGION_BASE_COSTS.get(region, REGION_BASE_COSTS[Region.GLOBAL]) * 2
        total_breach_cost = min(total_from_records, region_total_max)
        max_penalty, penalty_range = self._estimate_regulatory_penalty(
            compliance_frameworks, sensitivity, estimated_records_exposed, company_annual_revenue_usd
        )
        notes = [
            f"Base per-record cost: ${base_per_record} (derived from IBM/Ponemon 2025 regional averages)",
            f"Data sensitivity: {sensitivity.name} (multiplier: {sensitivity_mult}x)",
            f"Compliance frameworks: {[c.value for c in compliance_frameworks]} (multiplier: {compliance_mult}x)",
            f"Region: {region.value} (multiplier: {region_mult}x)",
            f"Per-record cost capped at $500 to prevent unrealistic projections",
            f"Total cost capped at {region_total_max/1_000_000:.1f}M USD (2x regional IBM average)",
            "Regulatory penalties are MAXIMUM estimates; actual penalties are discretionary",
        ]
        if len(compliance_frameworks) <= 2 and estimated_records_exposed < 100_000:
            confidence = "high"
        elif len(compliance_frameworks) <= 4 and estimated_records_exposed < 1_000_000:
            confidence = "medium"
        else:
            confidence = "low"
        return BreachCostEstimate(
            service=service.value, region=region.value,
            compliance_frameworks=[c.value for c in compliance_frameworks],
            estimated_records_exposed=estimated_records_exposed,
            base_cost_per_record=base_per_record, sensitivity_multiplier=sensitivity_mult,
            compliance_multiplier=compliance_mult, region_multiplier=region_mult,
            estimated_per_record_cost=adjusted_per_record,
            estimated_total_breach_cost=total_breach_cost,
            regulatory_max_penalty=max_penalty, estimated_penalty_range=penalty_range,
            methodology_notes=notes, data_sources=self.sources, confidence_level=confidence,
        )

    def _calculate_compliance_multiplier(self, frameworks):
        multipliers = {
            ComplianceFramework.SOC2: 1.0, ComplianceFramework.DPDP: 1.3,
            ComplianceFramework.RBI: 1.4, ComplianceFramework.PCI_DSS: 1.5,
            ComplianceFramework.IRDAI: 1.2, ComplianceFramework.SEBI: 1.3,
            ComplianceFramework.GDPR: 1.6, ComplianceFramework.HIPAA: 1.5,
        }
        total = 1.0
        for fw in frameworks:
            total += (multipliers.get(fw, 1.0) - 1.0)
        return round(total, 2)

    def _calculate_region_multiplier(self, region, frameworks):
        base = {Region.US: 2.3, Region.EU: 1.4, Region.INDIA: 0.6,
                Region.BRAZIL: 0.3, Region.GLOBAL: 1.0}
        mult = base.get(region, 1.0)
        if region == Region.INDIA:
            if ComplianceFramework.DPDP in frameworks: mult += 0.4
            if ComplianceFramework.RBI in frameworks: mult += 0.3
        return round(mult, 2)

    def _estimate_regulatory_penalty(self, frameworks, sensitivity, records_exposed, company_revenue):
        max_penalty = 0
        low_estimate = 0
        high_estimate = 0
        for fw in frameworks:
            low = 0
            high = 0
            regs = REGULATORY_MAXIMUMS.get(fw, {})
            match fw:
                case ComplianceFramework.DPDP:
                    max_inr = regs.get("security_failure", 250_000_000)
                    max_usd = max_inr * regs.get("usd_conversion", 0.012)
                    max_penalty = max(max_penalty, max_usd)
                    severity_factor = sensitivity.value / 6.0
                    scale_factor = min(records_exposed / 1_000_000, 1.0)
                    low = max_usd * 0.05 * severity_factor
                    high = max_usd * 0.35 * max(severity_factor, scale_factor)
                case ComplianceFramework.RBI:
                    max_inr = regs.get("major_incident", 100_000_000)
                    max_usd = max_inr * regs.get("usd_conversion", 0.012)
                    max_penalty = max(max_penalty, max_usd)
                    low = max_usd * 0.1; high = max_usd * 0.6
                case ComplianceFramework.PCI_DSS:
                    per_record = regs.get("per_record_high", 90)
                    max_usd = per_record * records_exposed
                    max_penalty = max(max_penalty, max_usd)
                    low = per_record * 0.5 * records_exposed
                    high = per_record * records_exposed
                case ComplianceFramework.GDPR:
                    max_eur = company_revenue * 0.04 if company_revenue else regs.get("tier2_max", 20_000_000)
                    max_usd = max_eur * regs.get("usd_conversion", 1.08)
                    max_penalty = max(max_penalty, max_usd)
                    low = max_usd * 0.02; high = max_usd * 0.15
                case ComplianceFramework.SOC2:
                    if company_revenue:
                        impact_pct = regs.get("estimated_revenue_impact_pct", 0.15)
                        max_usd = company_revenue * impact_pct
                        max_penalty = max(max_penalty, max_usd)
                        low = max_usd * 0.05; high = max_usd * 0.3
                case _:
                    continue
            low_estimate += low; high_estimate += high
        cap = 500_000_000
        return (min(max_penalty, cap), (min(low_estimate, cap), min(high_estimate, cap)))



if __name__ == "__main__":
    estimator = BreachCostEstimator()
    result = estimator.estimate(
        service=ServiceType.CLOUD_SQL,
        region=Region.INDIA,
        compliance_frameworks=[ComplianceFramework.RBI, ComplianceFramework.DPDP, ComplianceFramework.PCI_DSS],
        estimated_records_exposed=500_000,
        data_sensitivity=DataSensitivity.CRITICAL,
    )
    print(json.dumps(result.to_dict(), indent=2))
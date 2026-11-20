from typing import List, Dict, Any
from app.core.config import COLOR_RED, COLOR_ORANGE, COLOR_GREEN, COLOR_BLUE

class RiskCalculator:
    """Computes SOC composite threat posture and operational risk metrics."""

    def calculate_overall_risk(self, alerts: List[Dict[str, Any]], logs_count: int) -> Dict[str, Any]:
        """
        Calculates organizational risk level based on detected threat severities,
        hostile IP concentration, and volume ratios.
        """
        if not alerts:
            return {
                "level": "LOW RISK",
                "percentage": 10,
                "color": COLOR_GREEN,
                "description": "Clean operational profile. No active intrusion indicators detected.",
                "contributing_factors": [
                    "Zero heuristic rule violations triggered",
                    "No anomalous behavioral outliers identified"
                ]
            }

        crit_count = sum(1 for a in alerts if a.get("severity") == "Critical")
        high_count = sum(1 for a in alerts if a.get("severity") == "High")
        med_count = sum(1 for a in alerts if a.get("severity") == "Medium")
        low_count = sum(1 for a in alerts if a.get("severity") == "Low")

        distinct_ips = len(set(a.get("source_ip") for a in alerts if a.get("source_ip")))

        # Weighted calculation
        raw_score = (crit_count * 35) + (high_count * 20) + (med_count * 8) + (low_count * 2) + (distinct_ips * 5)
        score = min(98, max(15, raw_score))

        factors = []
        if crit_count > 0:
            factors.append(f"{crit_count} Critical severity threat(s) flagged")
        if high_count > 0:
            factors.append(f"{high_count} High severity incident(s) requiring attention")
        if distinct_ips > 1:
            factors.append(f"{distinct_ips} distinct attacking IP host(s) observed")
        if logs_count > 0:
            threat_ratio = (len(alerts) / logs_count) * 100
            if threat_ratio > 20:
                factors.append(f"Elevated incident concentration ({threat_ratio:.1f}% of total traffic)")

        if score >= 75 or crit_count >= 2:
            level = "CRITICAL RISK"
            color = COLOR_RED
            desc = "Imminent compromise indicators detected. Immediate incident response required!"
        elif score >= 50 or crit_count >= 1 or high_count >= 2:
            level = "HIGH RISK"
            color = COLOR_RED
            desc = "Immediate attention required!"
        elif score >= 25:
            level = "MEDIUM RISK"
            color = COLOR_ORANGE
            desc = "Elevated suspicious activity observed. Review alerted vectors."
        else:
            level = "LOW RISK"
            color = COLOR_GREEN
            desc = "Minor anomalous queries observed. Operating within tolerable threshold."

        return {
            "level": level,
            "percentage": score,
            "color": color,
            "description": desc,
            "contributing_factors": factors if factors else ["Baseline traffic inspection"]
        }

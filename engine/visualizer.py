

import json
import logging
import os
import warnings
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

warnings.filterwarnings('ignore')
from fixedLDS import ConfigManager, NumpyTypeHandler, StatisticsCalculator, apply_all_fixes

# Optional LLM integration
try:
    from ollama import Client
    ollama_client = Client()
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    ollama_client = None

logger = logging.getLogger("linux_anomaly_detection")

class LinuxAnomalyVisualizer:
    """
    Comprehensive visualization and reporting for Linux anomaly detection.
    Supports all 14 Linux detection jobs across 5 data groups.
    """

    def __init__(self, config):
        self.config = config
        self.viz_dir = os.path.join(config["output"]["results_dir"], "visualizations")
        self.report_dir = os.path.join(config["output"]["results_dir"], "reports")
        os.makedirs(self.viz_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

        self.logger = logging.getLogger("linux_anomaly_detection")
        # Set visualization style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (14, 8)
        plt.rcParams['font.size'] = 10
        self.config = ConfigManager.fix_config(config)

        #ADD HELPER OBJECTS:
        self.type_handler = NumpyTypeHandler()
        self.stats_calculator = StatisticsCalculator()
        # small helper to avoid calling round() on numpy.bool_ or other non-numeric types
    def _safe_round(self, value, ndigits=3):
        try:
            return round(float(value), ndigits)
        except Exception:
            try:
                # Fallback: attempt to coerce to float without rounding
                return float(value)
            except Exception:
                # Last resort: return original value unchanged
                return value
    def _create_ml_only_markdown_report(self, summary: dict, ml_insights: dict, viz_paths: list[str], data_type: str, llm_analysis: dict | None=None) -> str:
        """Create a report where ML anomalies are the only true anomalies."""

        report_lines = [
            f"# {data_type.title()} Anomaly Detection Report",
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "**Classification Method**: ML Anomalies Only",
            "",
            "## Summary",
            ""
        ]

        # Add summary with corrected terminology
        if 'total_anomalies' in summary:
            report_lines.extend([
                f"- **Total anomalies detected**: {summary['total_anomalies']}",
                f"- **Total normal events**: {summary['total_normal']}",
                f"- **Total records analyzed**: {summary['total_records']}",
                f"- **Anomaly percentage**: {summary['anomaly_percentage']}%",
                f"- **Normal percentage**: {summary['normal_percentage']}%",
                "",
                "**Note**: Only machine learning detections are classified as anomalies. ",
                "Statistical detections and rule-based findings are treated as normal behavior.",
                ""
            ])

            if 'analysis_time_span_hours' in summary:
                report_lines.extend([
                    f"- **Analysis period**: {summary.get('analysis_start', 'N/A')} to {summary.get('analysis_end', 'N/A')}",
                    f"- **Time span**: {summary['analysis_time_span_hours']} hours",
                    ""
                ])

        # Add ML score statistics
        if 'ml_score_stats' in summary:
            ml_stats = summary['ml_score_stats']
            report_lines.extend([
                "### Anomaly Score Statistics",
                "",
                f"- **Average Score**: {ml_stats['mean']}",
                f"- **Highest Score**: {ml_stats['max']}",
                f"- **Lowest Score**: {ml_stats['min']}",
                ""
            ])

        # Add confidence statistics
        if 'confidence_stats' in summary:
            conf_stats = summary['confidence_stats']
            report_lines.extend([
                "### Detection Confidence Statistics",
                "",
                f"- **Average Confidence**: {conf_stats['mean']}%",
                f"- **Highest Confidence**: {conf_stats['max']}%",
                f"- **Lowest Confidence**: {conf_stats['min']}%",
                ""
            ])

        # Add top entities
        entity_keys = [k for k in summary.keys() if k.startswith('top_')]
        if entity_keys:
            report_lines.extend(["### Top Anomalous Entities", ""])
            for key in entity_keys:
                entity_type = key.replace('top_', '').replace('_', ' ').title()
                entities = summary[key]
                report_lines.append(f"**{entity_type}:**")
                for entity, count in list(entities.items())[:5]:
                    report_lines.append(f"- {entity}: {count} anomalies")
                report_lines.append("")

        # Add insights
        if 'ml_patterns' in ml_insights:
            report_lines.extend([
                "### Detection Insights",
                ""
            ])
            for pattern in ml_insights['ml_patterns']:
                report_lines.append(f"- {pattern}")
            report_lines.append("")

        # Add LLM analysis (if available) or a deterministic fallback
        report_lines.append("### LLM Analysis")
        report_lines.append("")
        if llm_analysis and isinstance(llm_analysis, dict) and llm_analysis:
            # Prefer structured fields if returned
            if 'summary' in llm_analysis:
                report_lines.append("**LLM Summary:**")
                report_lines.append("")
                report_lines.append(str(llm_analysis.get('summary')))
                report_lines.append("")

            if 'patterns' in llm_analysis:
                report_lines.append("**Key Patterns Identified by LLM:**")
                report_lines.append("")
                report_lines.append(str(llm_analysis.get('patterns')))
                report_lines.append("")

            if 'implications' in llm_analysis:
                report_lines.append("**Security Implications (LLM):**")
                report_lines.append("")
                report_lines.append(str(llm_analysis.get('implications')))
                report_lines.append("")

            if 'recommendations' in llm_analysis:
                report_lines.append("**Recommendations (LLM):**")
                report_lines.append("")
                report_lines.append(str(llm_analysis.get('recommendations')))
                report_lines.append("")
        else:
            # Deterministic fallback: summarize top ml_insights into a short paragraph
            fallback_lines = []
            if isinstance(ml_insights, dict):
                det_summary = ml_insights.get('detection_summary') or ''
                if det_summary:
                    fallback_lines.append(det_summary)

                patterns = ml_insights.get('ml_patterns') if isinstance(ml_insights.get('ml_patterns', None), list) else None
                if patterns:
                    fallback_lines.append('Key patterns: ' + '; '.join([str(p) for p in patterns[:3]]))

            if fallback_lines:
                report_lines.extend(fallback_lines)
            else:
                report_lines.append('LLM analysis unavailable; enable Ollama LLM in config or check Ollama connectivity to include automated reasoning here.')
            report_lines.append("")

        # Add visualizations
        if viz_paths:
            report_lines.extend([
                "## Visualizations",
                ""
            ])
            for i, viz_path in enumerate(viz_paths, 1):
                viz_name = os.path.basename(viz_path)
                report_lines.extend([
                    f"### Visualization {i}: {viz_name}",
                    "",
                    f"![{viz_name}](../{viz_name})",
                    ""
                ])

        # Add conclusion
        report_lines.extend([
            "## Next Steps",
            "",
            "1. Investigate the anomalies identified in this report",
            "2. Review potential false positives and tune detection thresholds if needed",
            "3. Implement recommended security controls",
            "4. Schedule a follow-up analysis to verify improvements",
            "",
            "---",
            "",
            "*Report generated by Linux Anomaly Detection System*"
        ])

        return "\n".join(report_lines)


    def _generate_no_ml_anomalies_report(self, data_type: str, total_records: int) -> tuple[str, str]:
        """Generate report when no ML anomalies are found."""

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = self.config.get("output", {}).get("results_dir", "results/reports")
        os.makedirs(output_dir, exist_ok=True)

        report_file = os.path.join(output_dir, f"{data_type}_anomaly_report_{timestamp_str}.md")
        csv_file = os.path.join(output_dir, f"{data_type}_anomaly_data_{timestamp_str}.csv")

        # Create empty CSV
        empty_df = pd.DataFrame()
        empty_df.to_csv(csv_file, index=False)

        # Create report
        report_content = f"""# {data_type.title()} Anomaly Detection Report

    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    **Classification Method**: ML Anomalies Only

    ## Summary

    - **Total anomalies detected**: 0
    - **Total normal events**: {total_records}
    - **Anomaly percentage**: 0.0%

    **Note**: Only machine learning detections are classified as anomalies.

    ## Key Findings

    No true anomalies were detected in the {data_type} data.

    ### Possible Reasons:
    1. ML detection thresholds may be too high
    2. Current data patterns are within normal ML baselines
    3. ML models may need retraining with recent data

    ### Recommended Actions:
    1. Review ML detection thresholds
    2. Check if ML models are properly loaded
    3. Consider expanding the analysis time window
    4. Validate ML model performance

    ---

    *Report generated by Linux Anomaly Detection System*
    """

        with open(report_file, "w", encoding='utf-8') as f:
            f.write(report_content)

        logger.info(f"Generated no-anomalies report: {report_file}")
        return report_file, csv_file
    def create_ml_only_visualizations(self, ml_anomalies: pd.DataFrame, data_type: str) -> list[str]:
        """Create visualizations showing only ML-detected anomalies (true anomalies)."""

        viz_paths = []

        if ml_anomalies.empty:
            logger.warning(f"No true anomalies to visualize for {data_type} (only ML detections count as anomalies)")
            return viz_paths

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        try:
            # Visualization 1: ML Scores Distribution
            if 'ml_anomaly_score' in ml_anomalies.columns:
                plt.figure(figsize=(10, 6))
                ml_scores = ml_anomalies['ml_anomaly_score'].dropna()

                if len(ml_scores) > 0:
                    plt.hist(ml_scores, bins=20, alpha=0.7, color='red', edgecolor='black')
                    plt.title(f'True Anomaly Score Distribution - {data_type.title()} (ML Only)')
                    plt.xlabel('Anomaly Score (ML)')
                    plt.ylabel('Count')
                    plt.grid(True, alpha=0.3)

                    viz_file = f"anomaly_scores_{data_type}_{timestamp}.png"
                    viz_path = os.path.join(self.viz_dir, viz_file)
                    plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(viz_path)

            # Visualization 2: ML Confidence Levels
            if 'confidence' in ml_anomalies.columns:
                plt.figure(figsize=(10, 6))
                confidence_scores = ml_anomalies['confidence'].dropna() * 100  # Convert to percentage

                if len(confidence_scores) > 0:
                    plt.hist(confidence_scores, bins=20, alpha=0.7, color='blue', edgecolor='black')
                    plt.title(f'Anomaly Confidence Distribution - {data_type.title()} (ML Only)')
                    plt.xlabel('Confidence (%)')
                    plt.ylabel('Count')
                    plt.grid(True, alpha=0.3)

                    viz_file = f"anomaly_confidence_{data_type}_{timestamp}.png"
                    viz_path = os.path.join(self.viz_dir, viz_file)
                    plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(viz_path)

            # Visualization 3: Top ML Anomalous Entities
            entity_cols = ['user.name', 'process.name', 'host.hostname', 'destination.ip']
            for col in entity_cols:
                if col in ml_anomalies.columns:
                    entity_counts = ml_anomalies[col].dropna().astype(str).fillna('unknown').value_counts().head(10)

                    if len(entity_counts) > 0:
                        plt.figure(figsize=(12, 8))
                        entity_counts.plot(kind='barh', color='orange', alpha=0.7)
                        plt.title(f'Top 10 Anomalous {col.replace(".", " ").title()} - {data_type.title()}')
                        plt.xlabel('Anomaly Count')
                        plt.ylabel(col.replace(".", " ").title())
                        plt.tight_layout()

                        viz_file = f"top_anomalous_{col.replace('.', '_')}_{data_type}_{timestamp}.png"
                        viz_path = os.path.join(self.viz_dir, viz_file)
                        plt.savefig(viz_path, dpi=300, bbox_inches='tight')
                        plt.close()
                        viz_paths.append(viz_path)
                        break  # Only create one entity visualization

            logger.info(f"Created {len(viz_paths)} anomaly visualizations for {data_type} (ML detections only)")

        except Exception as e:
            logger.error(f"Error creating anomaly visualizations: {e}")
            plt.close('all')

        return viz_paths
    def _generate_ml_specific_insights(self, ml_anomalies: pd.DataFrame, data_type: str) -> dict:
        """Generate insights where only ML detections are considered anomalies."""

        insights = {
            'detection_summary': f'Only ML-detected anomalies are classified as true anomalies. Found {len(ml_anomalies)} anomalies in {data_type} data.',
            'classification_note': 'Statistical detections, rule-based detections, and other methods are classified as normal behavior.',
            'ml_patterns': []
        }

        if ml_anomalies.empty:
            insights['detection_summary'] = f'No true anomalies detected in {data_type} data (only ML detections count as anomalies)'
            return insights

        # ML Score distribution analysis
        if 'ml_anomaly_score' in ml_anomalies.columns:
            ml_scores = ml_anomalies['ml_anomaly_score'].dropna()
            if len(ml_scores) > 0:
                high_score_count = len(ml_scores[ml_scores >= 0.8])
                medium_score_count = len(ml_scores[(ml_scores >= 0.5) & (ml_scores < 0.8)])
                low_score_count = len(ml_scores[ml_scores < 0.5])

                insights['ml_patterns'].append(
                    f"ML Score Distribution: {high_score_count} high-confidence (≥0.8), "
                    f"{medium_score_count} medium-confidence (0.5-0.8), "
                    f"{low_score_count} low-confidence (<0.5)"
                )

        # Confidence analysis
        if 'confidence' in ml_anomalies.columns:
            confidence_scores = ml_anomalies['confidence'].dropna()
            if len(confidence_scores) > 0:
                avg_confidence = confidence_scores.mean() * 100
                insights['ml_patterns'].append(
                    f"Average ML confidence: {self._safe_round(avg_confidence, 1)}%"
                )

        # Detection threshold analysis
        if 'detection_threshold' in ml_anomalies.columns:
            thresholds = ml_anomalies['detection_threshold'].dropna().unique()
            if len(thresholds) > 0:
                insights['ml_patterns'].append(
                    f"ML thresholds used: {', '.join([str(self._safe_round(t,3)) for t in sorted(thresholds)])}"
                )

        # Job source analysis
        # if 'job_source' in ml_anomalies.columns:
        #     job_counts = ml_anomalies['job_source'].astype(str).fillna('unknown').value_counts()
        #     top_jobs = job_counts.head(3)
        #     insights['ml_specific_patterns'].append(
        #         f"Top ML detection jobs: {', '.join([f'{job}({count})' for job, count in top_jobs.items()])}"
        #     )

        return insights
    def _generate_ml_only_summary_stats(self, ml_anomalies: pd.DataFrame, total_records: int, data_type: str) -> dict:
        """Generate summary statistics where ML anomalies = anomalies, everything else = normal."""

        ml_count = len(ml_anomalies)
        normal_count = total_records - ml_count
        ml_percentage = (ml_count / total_records * 100) if total_records > 0 else 0

        summary = {
            'total_anomalies': ml_count,  # Only ML anomalies count as anomalies
            'total_normal': normal_count,  # Everything else (including statistical) is normal
            'total_records': total_records,
            'anomaly_percentage': round(ml_percentage, 2),
            'normal_percentage': round(100 - ml_percentage, 2),
            'classification_method': 'ML_anomalies_only',
            'note': 'Only machine learning detections are classified as anomalies'
        }

        # Add temporal analysis for ML anomalies
        if not ml_anomalies.empty and '@timestamp' in ml_anomalies.columns:
            try:
                ml_with_time = self._ensure_datetime_format(ml_anomalies.copy())
                if not ml_with_time.empty:
                    time_range = ml_with_time['@timestamp'].max() - ml_with_time['@timestamp'].min()
                    summary['analysis_time_span_hours'] = round(time_range.total_seconds() / 3600, 1)
                    summary['analysis_start'] = str(ml_with_time['@timestamp'].min())
                    summary['analysis_end'] = str(ml_with_time['@timestamp'].max())
            except Exception as e:
                logger.warning(f"Error in ML temporal analysis: {e}")

        # Add ML-specific metrics
        if not ml_anomalies.empty:
            if 'ml_anomaly_score' in ml_anomalies.columns:
                ml_scores = ml_anomalies['ml_anomaly_score'].dropna()
                if len(ml_scores) > 0:
                    summary['ml_score_stats'] = {
                        'mean': self._safe_round(ml_scores.mean(), 3),
                        'max': self._safe_round(ml_scores.max(), 3),
                        'min': self._safe_round(ml_scores.min(), 3)
                    }

            if 'confidence' in ml_anomalies.columns:
                confidence_scores = ml_anomalies['confidence'].dropna()
                if len(confidence_scores) > 0:
                    summary['confidence_stats'] = {
                        'mean': self._safe_round(confidence_scores.mean() * 100, 1),
                        'max': self._safe_round(confidence_scores.max() * 100, 1),
                        'min': self._safe_round(confidence_scores.min() * 100, 1)
                    }

            # Top entities with ML anomalies
            entity_cols = ['user.name', 'process.name', 'host.hostname', 'destination.ip']
            for col in entity_cols:
                if col in ml_anomalies.columns:
                    entity_counts = ml_anomalies[col].dropna().astype(str).fillna('unknown').value_counts()
                    if len(entity_counts) > 0:
                        summary[f'top_{col.replace(".", "_")}'] = entity_counts.head(5).to_dict()
                        summary[f'unique_{col.replace(".", "_")}_count'] = len(entity_counts)
                        break

        # Avoid passing raw pandas/numpy types into the statistics calculator
        # which may attempt to round numpy.bool_ objects. Return the safe
        # pre-computed summary dictionary instead.
        return summary

    def generate_comprehensive_report(self, results_dict: dict[str, pd.DataFrame], data_type: str) -> tuple[str, str]:
        """
        FIXED: Generate reports using ONLY ML-detected anomalies.
        Statistical anomalies are completely filtered out.
        """
        try:
            logger.info(f"Generating ML-only comprehensive report for {data_type} anomalies")
            # Defensive normalization: ensure results_dict is a mapping of job_name -> pd.DataFrame
            normalized_results = {}
            if not isinstance(results_dict, dict):
                try:
                    # Try to coerce to dict if possible
                    results_dict = dict(results_dict)
                except Exception:
                    logger.warning("generate_comprehensive_report: results_dict is not a dict-like object; treating as empty")
                    results_dict = {}

            for job_name, job_results in results_dict.items():
                # If it's already a DataFrame, keep it
                if isinstance(job_results, pd.DataFrame):
                    normalized_results[job_name] = job_results
                    continue

                # Tuple like (df, saveable)
                if isinstance(job_results, tuple) and len(job_results) > 0 and isinstance(job_results[0], pd.DataFrame):
                    normalized_results[job_name] = job_results[0]
                    logger.debug(f"Normalized tuple result for job {job_name} to DataFrame")
                    continue

                # Dict -> try to convert to DataFrame
                if isinstance(job_results, dict):
                    try:
                        normalized_results[job_name] = pd.DataFrame.from_dict(job_results)
                        logger.debug(f"Converted dict result for job {job_name} to DataFrame")
                        continue
                    except Exception:
                        normalized_results[job_name] = pd.DataFrame([job_results])
                        logger.debug(f"Wrapped dict result for job {job_name} into single-row DataFrame")
                        continue

                # List -> try DataFrame
                if isinstance(job_results, list):
                    try:
                        normalized_results[job_name] = pd.DataFrame(job_results)
                        logger.debug(f"Converted list result for job {job_name} to DataFrame")
                        continue
                    except Exception:
                        normalized_results[job_name] = pd.DataFrame([{'value': job_results}])
                        continue

                # Unknown type: create empty DataFrame and log
                logger.warning(f"generate_comprehensive_report: job {job_name} returned unsupported type {type(job_results).__name__}; using empty DataFrame")
                normalized_results[job_name] = pd.DataFrame()

            # Replace results_dict with normalized mapping
            results_dict = normalized_results

            # STEP 1: Extract ONLY ML anomalies from all results
            ml_only_anomalies = []
            total_records_processed = 0

            for job_name, job_results in results_dict.items():
                if not isinstance(job_results, pd.DataFrame) or job_results.empty:
                    continue

                # Count all records processed (for accurate percentage)
                total_records_processed += len(job_results)

                # CRITICAL FILTER: Only ML-detected anomalies
                if 'detection_method' in job_results.columns and 'final_anomaly' in job_results.columns:
                    ml_mask = (
                        (job_results['detection_method'] == 'machine_learning') &
                        (job_results['final_anomaly'])
                    )
                    ml_anomalies = job_results[ml_mask].copy()

                    if not ml_anomalies.empty:
                        ml_anomalies['job_source'] = job_name  # Track source job
                        ml_only_anomalies.append(ml_anomalies)

            if not ml_only_anomalies:
                logger.warning(f"No ML anomalies found for {data_type} - generating empty report")
                return self._generate_no_ml_anomalies_report(data_type, total_records_processed)

            # Combine all ML anomalies
            combined_ml_anomalies = pd.concat(ml_only_anomalies, ignore_index=True)

            # STEP 2: Treat everything else as NORMAL (including statistical detections)
            ml_anomaly_count = len(combined_ml_anomalies)
            normal_count = total_records_processed - ml_anomaly_count

            # Extract all non-ML records as "normal" data
            all_normal_records = []
            for job_results in results_dict.values():
                if job_results.empty:
                    continue

                # Everything that's NOT an ML anomaly is considered normal
                if 'detection_method' in job_results.columns and 'final_anomaly' in job_results.columns:
                    normal_mask = ~(
                        (job_results['detection_method'] == 'machine_learning') &
                        (job_results['final_anomaly'])
                    )
                    normal_records = job_results[normal_mask].copy()

                    if not normal_records.empty:
                        # Mark these as normal regardless of their original final_anomaly status
                        normal_records['final_anomaly'] = False
                        normal_records['classification'] = 'normal'
                        all_normal_records.append(normal_records)
                else:
                    # If no detection method column, treat all as normal
                    normal_records = job_results.copy()
                    normal_records['final_anomaly'] = False
                    normal_records['classification'] = 'normal'
                    all_normal_records.append(normal_records)

            # Create normal data DataFrame
            pd.concat(all_normal_records, ignore_index=True) if all_normal_records else pd.DataFrame()

            logger.info(f"Classification: {ml_anomaly_count} ML anomalies, {normal_count} normal records (including statistical detections) from {total_records_processed} total")

            # STEP 3: Generate report components using only ML data
            try:
                summary = self._generate_ml_only_summary_stats(combined_ml_anomalies, total_records_processed, data_type)
            except Exception as e:
                logger.warning(f"Error generating ML summary stats: {e}")
                summary = {"error": "Could not generate ML summary statistics"}

            try:
                ml_insights = self._generate_ml_specific_insights(combined_ml_anomalies, data_type)
            except Exception as e:
                logger.warning(f"Error generating ML insights: {e}")
                ml_insights = {"error": "Could not generate ML insights"}

            try:
                visualizations = self.create_ml_only_visualizations(combined_ml_anomalies, data_type)
            except Exception as e:
                logger.warning(f"Error creating ML visualizations: {e}")
                visualizations = []

            # STEP 4: Create ML-focused report
            try:
                llm_analysis = self._generate_llm_analysis(summary, {}, ml_insights, {}, combined_ml_anomalies, data_type)
            except Exception as e:
                logger.warning(f"LLM analysis generation failed: {e}")
                llm_analysis = None

            report_content = self._create_ml_only_markdown_report(
                summary, ml_insights, visualizations, data_type, llm_analysis=llm_analysis
            )

            # STEP 5: Save report and data
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = self.config.get("output", {}).get("results_dir", "results/reports")
            os.makedirs(output_dir, exist_ok=True)

            report_file = os.path.join(output_dir, f"ml_only_{data_type}_report_{timestamp_str}.md")
            csv_file = os.path.join(output_dir, f"ml_only_{data_type}_data_{timestamp_str}.csv")

            # Save ML-only report
            with open(report_file, "w", encoding='utf-8') as f:
                f.write(report_content)

            # Save ML-only data
            combined_ml_anomalies.to_csv(csv_file, index=False)

            logger.info(f"Generated ML-only report: {report_file}")
            logger.info(f"Saved ML-only data: {csv_file}")

            return report_file, csv_file

        except Exception as e:
            logger.error(f"Error generating ML-only report for {data_type}: {e}")
            return self._generate_error_report(data_type, str(e))

    def _create_discovery_visualizations(self, results_dict):
        """Create discovery command visualizations."""
        viz_paths = []

        # Combine discovery results
        all_discovery_data = []
        for job_name, results in results_dict.items():
            if not results.empty and 'process.name' in results.columns:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_discovery_data.append(results_copy)

        if not all_discovery_data:
            return viz_paths

        combined_data = pd.concat(all_discovery_data, ignore_index=True)
        combined_data = self._ensure_datetime_format(combined_data)

        # Get anomalies if available
        has_anomalies = False
        if 'final_anomaly' in combined_data.columns:
            anomalies = combined_data[combined_data['final_anomaly']]
            has_anomalies = not anomalies.empty

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 1. Discovery commands by category
            if 'discovery_category' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                category_counts = combined_data['discovery_category'].astype(str).fillna('unknown').value_counts()

                category_counts.plot(kind='bar', alpha=0.7,
                                        color='blue' if not has_anomalies else 'orange')
                plt.title('Discovery Commands by Category', fontsize=14, fontweight='bold')
                plt.xlabel('Category')
                plt.ylabel('Number of Commands')
                plt.xticks(rotation=45)
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"discovery_categories_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 2. Top discovery commands
            if 'process.name' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                cmd_counts = combined_data['process.name'].astype(str).fillna('unknown').value_counts().head(15)

                cmd_counts.plot(kind='barh', alpha=0.7,
                                color='blue' if not has_anomalies else 'orange')
                plt.title('Top 15 Discovery Commands', fontsize=14, fontweight='bold')
                plt.xlabel('Number of Executions')
                plt.ylabel('Command')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"discovery_commands_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 3. Discovery commands by user
            if 'user.name' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                user_counts = combined_data['user.name'].astype(str).fillna('unknown').value_counts().head(10)

                user_counts.plot(kind='bar', alpha=0.7,
                                    color='blue' if not has_anomalies else 'orange')
                plt.title('Discovery Commands by User', fontsize=14, fontweight='bold')
                plt.xlabel('User')
                plt.ylabel('Number of Commands')
                plt.xticks(rotation=45)
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"discovery_users_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            return viz_paths

        except Exception as e:
            logger.error(f"Error creating discovery visualizations: {e}")
            plt.close()
            return viz_paths
    def _compare_timestamps(self, df, time_column, start_time, end_time):
        """
        Safely compare timestamps by ensuring consistent types.

        Args:
            df (pd.DataFrame): DataFrame containing timestamp column
            time_column (str): Name of the timestamp column
            start_time: Start time for filtering (can be string or timestamp)
            end_time: End time for filtering (can be string or timestamp)

        Returns:
            pd.DataFrame: Filtered DataFrame
        """
        # Make a copy to avoid modifying the original
        result_df = df.copy()

        # Ensure timestamp column is datetime
        if time_column in result_df.columns:
            if not pd.api.types.is_datetime64_any_dtype(result_df[time_column]):
                result_df[time_column] = pd.to_datetime(result_df[time_column], errors='coerce')
                # Remove rows with invalid timestamps
                result_df = result_df.dropna(subset=[time_column])
        else:
            self.logger.warning(f"Time column '{time_column}' not found in DataFrame")
            return pd.DataFrame()  # Return empty DataFrame

        # Convert comparison times to datetime if they are strings
        if isinstance(start_time, str):
            try:
                start_time = pd.to_datetime(start_time, errors='coerce')
                if pd.isna(start_time):
                    self.logger.warning(f"Could not parse start time: {start_time}")
                    return pd.DataFrame()
            except Exception as e:
                self.logger.warning(f"Error converting start time: {e}")
                return pd.DataFrame()

        if isinstance(end_time, str):
            try:
                end_time = pd.to_datetime(end_time, errors='coerce')
                if pd.isna(end_time):
                    self.logger.warning(f"Could not parse end time: {end_time}")
                    return pd.DataFrame()
            except Exception as e:
                self.logger.warning(f"Error converting end time: {e}")
                return pd.DataFrame()

        # Filter using datetime objects
        try:
            filtered_df = result_df[(result_df[time_column] >= start_time) &
                                (result_df[time_column] <= end_time)]
            return filtered_df
        except Exception as e:
            self.logger.warning(f"Error filtering by time range: {e}")
            return pd.DataFrame()
    def _create_discovery_visualizations(self, results_dict):
        """Create discovery command visualizations with robust error handling."""
        viz_paths = []

        # Combine discovery results
        all_discovery_data = []
        for job_name, results in results_dict.items():
            if not results.empty and 'process.name' in results.columns:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_discovery_data.append(results_copy)

        if not all_discovery_data:
            self.logger.info("No discovery data available for visualization")
            return viz_paths

        try:
            combined_data = pd.concat(all_discovery_data, ignore_index=True)

            # MODIFIED: More robust timestamp handling
            if '@timestamp' in combined_data.columns:
                try:
                    combined_data = self._ensure_datetime_format(combined_data)
                except Exception as e:
                    self.logger.warning(f"Error formatting timestamps: {e}")

            # Get anomalies if available
            has_anomalies = False
            if 'final_anomaly' in combined_data.columns:
                anomalies = combined_data[combined_data['final_anomaly']]
                has_anomalies = not anomalies.empty

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # 1. Discovery commands by category
            if 'discovery_category' in combined_data.columns:
                try:
                    plt.figure(figsize=(12, 8))

                    category_counts = combined_data['discovery_category'].astype(str).fillna('unknown').value_counts()

                    category_counts.plot(kind='bar', alpha=0.7,
                                            color='blue' if not has_anomalies else 'orange')
                    plt.title('Discovery Commands by Category', fontsize=14, fontweight='bold')
                    plt.xlabel('Category')
                    plt.ylabel('Number of Commands')
                    plt.xticks(rotation=45)
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"discovery_categories_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)
                except Exception as e:
                    self.logger.warning(f"Error creating category visualization: {e}")
                    plt.close()

            # 2. Top discovery commands
            if 'process.name' in combined_data.columns:
                try:
                    plt.figure(figsize=(12, 8))

                    cmd_counts = combined_data['process.name'].astype(str).fillna('unknown').value_counts().head(15)

                    cmd_counts.plot(kind='barh', alpha=0.7,
                                    color='blue' if not has_anomalies else 'orange')
                    plt.title('Top 15 Discovery Commands', fontsize=14, fontweight='bold')
                    plt.xlabel('Number of Executions')
                    plt.ylabel('Command')
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"discovery_commands_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)
                except Exception as e:
                    self.logger.warning(f"Error creating commands visualization: {e}")
                    plt.close()

            # 3. Discovery commands by user
            if 'user.name' in combined_data.columns:
                try:
                    plt.figure(figsize=(12, 8))

                    user_counts = combined_data['user.name'].astype(str).fillna('unknown').value_counts().head(10)

                    user_counts.plot(kind='bar', alpha=0.7,
                                        color='blue' if not has_anomalies else 'orange')
                    plt.title('Discovery Commands by User', fontsize=14, fontweight='bold')
                    plt.xlabel('User')
                    plt.ylabel('Number of Commands')
                    plt.xticks(rotation=45)
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"discovery_users_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)
                except Exception as e:
                    self.logger.warning(f"Error creating user visualization: {e}")
                    plt.close()

            self.logger.info(f"Generated {len(viz_paths)} discovery visualizations")
            return viz_paths

        except Exception as e:
            self.logger.error(f"Error creating discovery visualizations: {e}")
            plt.close('all')  # Close any open figures
            return viz_paths

    def _create_markdown_report(self, summary, comparative_stats, specific_insights, llm_analysis, viz_paths, data_type):
        """
        Create a comprehensive markdown report from the analysis results.

        Args:
            summary (dict): Summary statistics
            comparative_stats (dict): Comparative analysis results
            specific_insights (dict): Data type specific insights
            llm_analysis (dict): LLM-based analysis
            viz_paths (list): Paths to visualizations
            data_type (str): Type of data

        Returns:
            str: Markdown report content
        """
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = f"""# Linux {data_type.title()} Anomaly Detection Report

    Generated: {timestamp_str}

    ## Summary

    """

        # Summary stats
        if summary:
            report += f"- **Total anomalies detected**: {summary.get('total_anomalies', 0)}\n"
            report += f"- **Total normal events**: {summary.get('total_normal', 0)}\n"
            report += f"- **Anomaly percentage**: {summary.get('anomaly_percentage', 0):.2f}%\n"

            time_range = summary.get("time_range", {})
            if time_range.get("start") and time_range.get("end"):
                report += f"- **Analysis period**: {time_range['start']} to {time_range['end']}\n"

            if "entities_with_anomalies" in summary:
                report += f"- **Unique entities with anomalies**: {summary['entities_with_anomalies']}\n"

            if "top_anomalous_entities" in summary:
                report += "\n### Top Anomalous Entities\n\n"
                for entity, count in list(summary["top_anomalous_entities"].items())[:5]:
                    report += f"- **{entity}**: {count} anomalies\n"

        # AI Summary
        if llm_analysis and 'summary' in llm_analysis:
            report += "\n### AI Analysis Summary\n\n"
            report += f"{llm_analysis['summary']}\n"

        # Comparative Analysis
        if comparative_stats:
            report += "\n## Comparative Analysis\n\n"

            if 'event_count' in comparative_stats:
                ec = comparative_stats['event_count']
                report += "### Event Count Comparison\n\n"
                report += f"- **Average anomalous event count**: {ec['anomalous'].get('mean', 0):.2f}\n"
                report += f"- **Average normal event count**: {ec['normal'].get('mean', 0):.2f}\n"
                report += f"- **Ratio (anomalous/normal)**: {ec['ratio']:.2f}x\n"

            if 'temporal' in comparative_stats:
                temp = comparative_stats['temporal']
                report += "\n### Temporal Patterns\n\n"
                report += f"- **Anomalies during business hours**: {temp.get('business_hours_anomalies', 0) * 100:.1f}%\n"
                report += f"- **Normal activity during business hours**: {temp.get('business_hours_normal', 0) * 100:.1f}%\n"

                if 'significant_hours' in temp:
                    report += "\n**Hours with unusual activity patterns:**\n\n"
                    for hour, details in temp['significant_hours'].items():
                        ratio = details.get('ratio', 0)
                        direction = "higher" if ratio > 1 else "lower"
                        report += f"- **Hour {hour}**: {abs(ratio):.1f}x {direction} anomaly rate than normal\n"

            if 'entities' in comparative_stats:
                report += "\n### Entity Distribution Comparison\n\n"
                for entity_type, details in comparative_stats['entities'].items():
                    report += f"#### {entity_type} Distribution\n\n"
                    if 'unique_to_anomalies' in details:
                        report += f"**{entity_type}s unique to anomalies:**\n\n"
                        for entity in details['unique_to_anomalies'][:5]:
                            report += f"- {entity}\n"
                    report += "\n"

        # Specific insights
        if specific_insights:
            report += "\n## Specific Insights\n\n"
            if data_type == "process":
                if 'unusual_processes' in specific_insights:
                    report += "### Unusual Processes\n\n"
                    for process, count in list(specific_insights['unusual_processes'].items())[:5]:
                        report += f"- **{process}**: {count} anomalies\n"

                if 'root_privilege_anomalies' in specific_insights:
                    rp = specific_insights['root_privilege_anomalies']
                    report += f"\n**Root privilege anomalies**: {rp['count']} ({rp['percentage']:.1f}%)\n"

                if 'non_system_path_anomalies' in specific_insights:
                    nsp = specific_insights['non_system_path_anomalies']
                    report += f"\n**Non-system path executions**: {nsp['count']} ({nsp['percentage']:.1f}%)\n"

                if 'tmp_directory_execution' in specific_insights:
                    tmp = specific_insights['tmp_directory_execution']
                    report += f"\n**Temporary directory executions**: {tmp['count']} ({tmp['percentage']:.1f}%)\n"

            elif data_type == "network":
                if 'unusual_countries' in specific_insights:
                    report += "### Unusual Destination Countries\n\n"
                    for country, count in list(specific_insights['unusual_countries'].items())[:5]:
                        report += f"- **{country}**: {count} connections\n"

                if 'unusual_ports' in specific_insights:
                    report += "\n### Unusual Destination Ports\n\n"
                    for port, count in list(specific_insights['unusual_ports'].items())[:5]:
                        report += f"- **Port {port}**: {count} connections\n"

                if 'port_categories' in specific_insights:
                    pc = specific_insights['port_categories']
                    report += f"\n**Well-known ports**: {pc['well_known']} ({pc['well_known_percentage']:.1f}%)\n"
                    report += f"**Uncommon ports**: {pc['uncommon']} ({pc['uncommon_percentage']:.1f}%)\n"

                if 'data_transfer' in specific_insights:
                    dt = specific_insights['data_transfer']
                    report += f"\n**Total data transferred**: {dt['total_bytes']} bytes\n"
                    report += f"**Average per connection**: {dt['avg_bytes_per_connection']:.1f} bytes\n"
                    report += f"**Maximum transfer size**: {dt['max_bytes']} bytes\n"

            elif data_type == "user":
                if 'unusual_users' in specific_insights:
                    report += "### Unusual User Activity\n\n"
                    for user, count in list(specific_insights['unusual_users'].items())[:5]:
                        report += f"- **{user}**: {count} anomalies\n"

                if 'sudo_anomalies' in specific_insights:
                    sudo = specific_insights['sudo_anomalies']
                    report += f"\n**Sudo command anomalies**: {sudo['count']} ({sudo['percentage']:.1f}%)\n"

                if 'compiler_anomalies' in specific_insights:
                    comp = specific_insights['compiler_anomalies']
                    report += f"\n**Compiler activity anomalies**: {comp['count']} ({comp['percentage']:.1f}%)\n"

                if 'after_hours_anomalies' in specific_insights:
                    ah = specific_insights['after_hours_anomalies']
                    report += f"\n**After-hours activity anomalies**: {ah['count']} ({ah['percentage']:.1f}%)\n"

            elif data_type == "discovery":
                if 'unusual_discovery_commands' in specific_insights:
                    report += "### Unusual Discovery Commands\n\n"
                    for cmd, count in list(specific_insights['unusual_discovery_commands'].items())[:5]:
                        report += f"- **{cmd}**: {count} occurrences\n"

                if 'discovery_categories' in specific_insights:
                    report += "\n### Discovery Categories\n\n"
                    for category, count in list(specific_insights['discovery_categories'].items())[:5]:
                        report += f"- **{category}**: {count} occurrences\n"

                if 'discovery_users' in specific_insights:
                    report += "\n### Users Performing Discovery\n\n"
                    for user, count in list(specific_insights['discovery_users'].items())[:5]:
                        report += f"- **{user}**: {count} discovery commands\n"

            elif data_type == "metadata":
                if 'unusual_metadata_processes' in specific_insights:
                    report += "### Unusual Metadata Access Processes\n\n"
                    for process, count in list(specific_insights['unusual_metadata_processes'].items())[:5]:
                        report += f"- **{process}**: {count} occurrences\n"

                if 'credential_harvesting' in specific_insights:
                    ch = specific_insights['credential_harvesting']
                    report += f"\n**Potential credential harvesting**: {ch['count']} ({ch['percentage']:.1f}%)\n"

                if 'metadata_service_types' in specific_insights:
                    report += "\n### Metadata Service Types\n\n"
                    for svc, count in list(specific_insights['metadata_service_types'].items())[:5]:
                        report += f"- **{svc}**: {count} accesses\n"

        # LLM Additional Sections
        if llm_analysis:
            if 'patterns' in llm_analysis:
                report += "\n## AI-Identified Patterns\n\n"
                report += f"{llm_analysis['patterns']}\n"
            if 'implications' in llm_analysis:
                report += "\n## Security Implications\n\n"
                report += f"{llm_analysis['implications']}\n"
            if 'recommendations' in llm_analysis:
                report += "\n## Investigation Recommendations\n\n"
                report += f"{llm_analysis['recommendations']}\n"
            if 'false_positive_improvements' in llm_analysis:
                report += "\n## False Positive Filtering Suggestions\n\n"
                report += f"{llm_analysis['false_positive_improvements']}\n"

        # Visualizations
        if viz_paths:
            report += "\n## Visualizations\n\n"
            for i, path in enumerate(viz_paths):
                viz_name = os.path.basename(path)
                relative_path = os.path.relpath(path, self.report_dir)
                report += f"\n### Visualization {i+1}: {viz_name}\n\n"
                report += f"![{viz_name}]({relative_path})\n"

        # Footer
        report += """
    ## Next Steps

    1. Investigate the top anomalies identified in this report
    2. Review potential false positives and tune detection thresholds if needed
    3. Implement recommended security controls
    4. Schedule a follow-up analysis to verify improvements

    ---

    *Report generated by Linux Anomaly Detection System*
    """

        return report

    def _generate_llm_analysis(self, summary, comparative_stats, specific_insights, suspected_false_positives, anomalies, data_type):
        """
        Generate LLM-based analysis of the anomalies if Ollama is available.

        Args:
            summary (dict): Summary statistics
            comparative_stats (dict): Comparative analysis results
            specific_insights (dict): Data type specific insights
            suspected_false_positives (dict): Potential false positives analysis
            anomalies (pd.DataFrame): Anomalous data
            data_type (str): Type of data

        Returns:
            dict: LLM analysis results or empty dict if LLM not available
        """
        # Check if Ollama is available
        global OLLAMA_AVAILABLE, ollama_client
        if not OLLAMA_AVAILABLE or ollama_client is None:
            return {}

        # Check if LLM analysis is enabled in config
        if not self.config.get("llm", {}).get("enable_analysis", False):
            return {}

        llm_analysis = {}

        try:
            # Prepare context for LLM
            context = {
                "summary": summary,
                "comparative_stats": comparative_stats,
                "specific_insights": specific_insights,
                "suspected_false_positives": suspected_false_positives,
                "data_type": data_type,
                "total_anomalies": len(anomalies),
                "timestamp": datetime.now().isoformat()
            }

            # Add a sample of anomalies for context
            top_anomalies = []
            if not anomalies.empty:
                if "anomaly_score" in anomalies.columns:
                    sample = anomalies.nlargest(5, "anomaly_score")
                elif "combined_score" in anomalies.columns:
                    sample = anomalies.nlargest(5, "combined_score")
                else:
                    sample = anomalies.head(5)

                # Extract relevant fields from sample
                for _, row in sample.iterrows():
                    anomaly_sample = {}
                    for field in ["@timestamp", "process.name", "user.name", "host.hostname",
                                "destination.ip", "destination.port", "anomaly_score", "combined_score"]:
                        if field in row and not pd.isna(row[field]):
                            anomaly_sample[field] = row[field]

                    top_anomalies.append(anomaly_sample)

            context["top_anomalies"] = top_anomalies

            # Create the prompt
            prompt = f"""
            You are a cybersecurity analyst reviewing Linux anomaly detection results.
            Analyze the following anomaly detection data and provide insights.

            Data type: {data_type}
            Total anomalies: {context['total_anomalies']}

            # Summary Statistics
            {json.dumps(summary, indent=2)}

            # Comparative Analysis
            {json.dumps(comparative_stats, indent=2)}

            # Specific Insights
            {json.dumps(specific_insights, indent=2)}

            # Potential False Positives
            {json.dumps(suspected_false_positives, indent=2)}

            # Top Anomalies Sample
            {json.dumps(top_anomalies, indent=2)}

            Please provide:
            1. A concise summary of the anomalies (2-3 sentences)
            2. Key patterns or trends identified
            3. Potential security implications
            4. Recommendations for investigation
            5. Suggested false positive filtering improvements

            Format your response as JSON with these five keys, and keep each section brief and focused.
            """

            # Call Ollama with a safer default model and timeouts
            model = self.config.get("llm", {}).get("model", "llama3.2")
            # Some Ollama clients support timeout via kwargs; wrap in try/except
            try:
                response = ollama_client.generate(
                    model=model,
                    prompt=prompt,
                    max_tokens=1000,
                    temperature=0.2,
                    timeout=30
                )
            except TypeError:
                # Fallback if client doesn't accept timeout
                response = ollama_client.generate(
                    model=model,
                    prompt=prompt,
                    max_tokens=1000,
                    temperature=0.2
                )

            # Parse the response
            if response and 'response' in response:
                raw = response['response']
                # If response looks like JSON, try to parse; otherwise use heuristics
                try:
                    parsed_response = json.loads(raw)
                    if isinstance(parsed_response, dict):
                        llm_analysis = parsed_response
                    else:
                        llm_analysis = {"summary": str(parsed_response)}
                except Exception:
                    # Try to extract JSON block from text
                    try:
                        start = raw.find('{')
                        end = raw.rfind('}')
                        if start != -1 and end != -1 and end > start:
                            candidate = raw[start:end+1]
                            parsed_response = json.loads(candidate)
                            llm_analysis = parsed_response if isinstance(parsed_response, dict) else {"summary": raw}
                        else:
                            llm_analysis = {"summary": raw, "note": "LLM output could not be parsed as JSON"}
                    except Exception:
                        llm_analysis = {"summary": raw, "note": "LLM output could not be parsed as JSON"}

            return llm_analysis

        except Exception as e:
            self.logger.warning(f"Error generating LLM analysis: {e}")
            return {"error": str(e)}
    def _safe_get_viz_dir(self):
        viz_dir = self.config.get('output', {}).get('visualization_dir', 'results')
        if not isinstance(viz_dir, str):
            viz_dir = self.config.get('output', {}).get('visualizations_dir', 'results')
        if not isinstance(viz_dir, str):
            viz_dir = os.path.join(str(self.config.get('output', {}).get('results_dir', 'results')), 'visualizations')
        os.makedirs(viz_dir, exist_ok=True)
        return str(viz_dir)
    def _analyze_false_positives(self, anomalies):
        """
        FIXED: Analyze anomalies to identify potential false positives.

        ROOT CAUSE: .str accessor was called on columns containing non-string values (NaN, numbers)

        FIX: Validate column types and convert to strings before string operations
        """
        if anomalies.empty:
            return {}

        false_positives = {}

        try:
            # Low score anomalies
            if 'anomaly_score' in anomalies.columns:
                low_score_threshold = 0.3
                low_score_anomalies = anomalies[anomalies['anomaly_score'] < low_score_threshold]

                if not low_score_anomalies.empty:
                    false_positives['low_score_anomalies'] = {
                        'count': len(low_score_anomalies),
                        'percentage': len(low_score_anomalies) / len(anomalies) * 100,
                        'examples': low_score_anomalies.head(3).to_dict('records') if len(low_score_anomalies) > 0 else []
                    }

            # FIX 1: Robust process name handling
            if 'process.name' in anomalies.columns:
                # Convert to string and handle NaN values
                process_series = anomalies['process.name'].astype(str).fillna('')

                benign_processes = [
                    'cron', 'systemd', 'bash', 'sh', 'systemctl', 'grep', 'ls', 'cat', 'find',
                    'ps', 'python3', 'sleep', 'apt-get', 'apt', 'dpkg', 'systemd-udevd'
                ]

                # Safe string matching
                benign_mask = process_series.isin(benign_processes)
                benign_matches = anomalies[benign_mask]

                if not benign_matches.empty:
                    false_positives['common_benign_processes'] = {
                        'count': len(benign_matches),
                        'percentage': len(benign_matches) / len(anomalies) * 100,
                        'process_counts': benign_matches['process.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    }

            # FIX 2: Safe scheduled task detection
            if 'is_business_hours' in anomalies.columns and 'process.name' in anomalies.columns:
                # Ensure process.name is string type
                process_series = anomalies['process.name'].astype(str).fillna('')

                scheduled_task_indicators = ['cron', 'scheduled', 'systemd-cron', 'at', 'anacron']
                pattern = '|'.join(scheduled_task_indicators)

                # Safe string operations
                try:
                    scheduled_mask = process_series.astype(str).fillna('').str.contains(pattern, case=False, na=False)
                    business_hours_mask = anomalies['is_business_hours'].fillna(True).astype(bool)

                    potential_scheduled = anomalies[scheduled_mask & (~business_hours_mask)]


                    if not potential_scheduled.empty:
                        false_positives['potential_scheduled_tasks'] = {
                            'count': len(potential_scheduled),
                            'percentage': len(potential_scheduled) / len(anomalies) * 100,
                            'examples': potential_scheduled.head(3).to_dict('records') if len(potential_scheduled) > 0 else []
                        }
                except Exception as e:
                    self.logger.warning(f"Error in scheduled task detection: {e}")

            # FIX 3: Safe maintenance detection
            if 'process.name' in anomalies.columns:
                process_series = anomalies['process.name'].astype(str).fillna('')

                maintenance_indicators = [
                    'apt', 'dpkg', 'update', 'upgrade', 'yum', 'dnf', 'systemctl', 'service',
                    'logrotate', 'backup', 'cleaner', 'purge', 'chown', 'chmod'
                ]
                pattern = '|'.join(maintenance_indicators)

                try:
                    maintenance_mask = process_series.astype(str).fillna('').str.contains(pattern, case=False, na=False)
                    potential_maintenance = anomalies[maintenance_mask]

                    if not potential_maintenance.empty:
                        false_positives['potential_system_maintenance'] = {
                            'count': len(potential_maintenance),
                            'percentage': len(potential_maintenance) / len(anomalies) * 100,
                            'examples': potential_maintenance.head(3).to_dict('records') if len(potential_maintenance) > 0 else []
                        }
                except Exception as e:
                    self.logger.warning(f"Error in maintenance detection: {e}")

            # FIX 4: Safe command line analysis
            if 'process.command_line' in anomalies.columns:
                cmd_series = anomalies['process.command_line'].astype(str).fillna('')

                update_indicators = [
                    'update', 'upgrade', 'apt-get', 'unattended', 'auto-update',
                    'software updater', 'package manager'
                ]
                pattern = '|'.join(update_indicators)

                try:
                    update_mask = cmd_series.astype(str).fillna('').str.contains(pattern, case=False, na=False)
                    potential_updates = anomalies[update_mask]

                    if not potential_updates.empty:
                        false_positives['potential_automatic_updates'] = {
                            'count': len(potential_updates),
                            'percentage': len(potential_updates) / len(anomalies) * 100,
                            'examples': potential_updates.head(3).to_dict('records') if len(potential_updates) > 0 else []
                        }
                except Exception as e:
                    self.logger.warning(f"Error in update detection: {e}")

            return false_positives

        except Exception as e:
            self.logger.warning(f"Error analyzing false positives: {e}")
            return {}
    def _generate_comparative_analysis(self, anomalies, normal_data):
        """
        Generate comparative analysis between anomalous and normal data.

        FIXED:
        - Added robust type checking and conversions
        - Safe handling of empty DataFrames and invalid operations

        ROOT CAUSE:
        - Boolean operations (ufunc 'invert') failed on mixed data types
        """

        if anomalies.empty or normal_data.empty:
            return {}

        comparison = {}

        try:
            # --- FIX 1: Event count comparison ---
            if 'event_count' in anomalies.columns and 'event_count' in normal_data.columns:
                anomaly_counts = pd.to_numeric(anomalies['event_count'], errors='coerce').dropna()
                normal_counts = pd.to_numeric(normal_data['event_count'], errors='coerce').dropna()

                if not anomaly_counts.empty and not normal_counts.empty:
                    comparison['event_count'] = {
                        'anomalous': {
                            k: float(v) if hasattr(v, '__float__') else v
                            for k, v in anomaly_counts.describe().to_dict().items()
                        },
                        'normal': normal_counts.describe().to_dict(),
                        'ratio': anomaly_counts.mean() / normal_counts.mean()
                                if normal_counts.mean() > 0 else 0
                    }

            # --- FIX 2: Temporal patterns analysis ---
            if '@timestamp' in anomalies.columns and '@timestamp' in normal_data.columns:
                anomalies_copy = self._ensure_datetime_format(anomalies.copy())
                normal_copy = self._ensure_datetime_format(normal_data.copy())

                if anomalies_copy.empty or normal_copy.empty:
                    self.logger.warning("Timestamp conversion failed for temporal analysis")
                    return comparison

                anomalies_copy['hour'] = anomalies_copy['@timestamp'].dt.hour
                normal_copy['hour'] = normal_copy['@timestamp'].dt.hour

                anomaly_hours = anomalies_copy['hour'].astype(str).fillna('unknown').value_counts().to_dict()
                normal_hours = normal_copy['hour'].astype(str).fillna('unknown').value_counts().to_dict()

                significant_hours = {}
                total_anomalies, total_normal = len(anomalies_copy), len(normal_copy)

                for hour in range(24):
                    anomaly_count = anomaly_hours.get(hour, 0)
                    normal_count = normal_hours.get(hour, 0)

                    anomaly_pct = anomaly_count / total_anomalies if total_anomalies > 0 else 0
                    normal_pct = normal_count / total_normal if total_normal > 0 else 0

                    if normal_pct > 0:
                        ratio = anomaly_pct / normal_pct
                    elif anomaly_pct > 0:
                        ratio = float('inf')
                    else:
                        ratio = 1.0

                    if ratio > 2 or ratio < 0.5:
                        significant_hours[hour] = {
                            'anomaly_count': int(anomaly_count),
                            'normal_count': int(normal_count),
                            'anomaly_pct': float(anomaly_pct),
                            'normal_pct': float(normal_pct),
                            'ratio': float(ratio) if ratio != float('inf') else 999.0
                        }

                # --- FIX 3: Business hours calculation ---
                try:
                    anomalies_copy['hour'] = pd.to_numeric(anomalies_copy['hour'], errors='coerce').fillna(0)
                    normal_copy['hour'] = pd.to_numeric(normal_copy['hour'], errors='coerce').fillna(0)

                    anomaly_business = anomalies_copy['hour'].between(9, 17, inclusive='both').astype(bool)
                    normal_business = normal_copy['hour'].between(9, 17, inclusive='both').astype(bool)

                    float(anomaly_business.sum()) / len(anomalies_copy) if len(anomalies_copy) > 0 else 0
                    float(normal_business.sum()) / len(normal_copy) if len(normal_copy) > 0 else 0

                except Exception as e:
                    self.logger.warning(f"Error in business hours calculation: {e}")
                    _business_hours_anomalies, _business_hours_normal = 0, 0

            # --- FIX 4: Entity distribution comparison ---
            entity_columns = {
                'process.name': 'Process',
                'user.name': 'User',
                'host.hostname': 'Host',
                'destination.ip': 'Destination IP',
                'destination.geo.country_name': 'Country'
            }

            entity_comparisons = {}
            for col, label in entity_columns.items():
                if col in anomalies.columns and col in normal_data.columns:
                    try:
                        anomaly_entities = anomalies[col].astype(str).fillna('unknown')
                        normal_entities = normal_data[col].astype(str).fillna('unknown')

                        top_anomalous = anomaly_entities.value_counts().head(5).to_dict()
                        top_normal = normal_entities.value_counts().head(5).to_dict()

                        anomalous_set, normal_set = set(top_anomalous.keys()), set(top_normal.keys())
                        unique_to_anomalies = anomalous_set - normal_set

                        entity_comparisons[label] = {
                            'top_anomalous': top_anomalous,
                            'top_normal': top_normal,
                            'unique_to_anomalies': list(unique_to_anomalies)
                        }
                    except Exception as e:
                        self.logger.warning(f"Error comparing {label} entities: {e}")

            if entity_comparisons:
                comparison['entities'] = entity_comparisons

            return comparison

        except Exception as e:
            self.logger.warning(f"Error generating comparative analysis: {e}")
            return {}

    def _ensure_datetime_format(self, df):
        if '@timestamp' in df.columns:
            if not pd.api.types.is_datetime64_any_dtype(df['@timestamp']):
                try:
                    # Try multiple formats to handle both timezone-aware and naive
                    df['@timestamp'] = pd.to_datetime(df['@timestamp'],
                                                    format='mixed',
                                                    errors='coerce')
                except Exception as e:
                    self.logger.warning(f"Error converting timestamps: {e}")
                    # Fallback: try without timezone parsing
                    df['@timestamp'] = pd.to_datetime(df['@timestamp'],
                                                    errors='coerce',
                                                    utc=False)

            # Remove any NaT values
            df = df.dropna(subset=['@timestamp'])

        return df
    def _create_timeline_visualization(self, results_dict, data_type):
        """Create a comprehensive timeline visualization with robust error handling."""
        # Combine all results
        all_data = []
        for job_name, results in results_dict.items():
            if not results.empty and '@timestamp' in results.columns:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_data.append(results_copy)

        if not all_data:
            self.logger.warning(f"No data available with timestamps for {data_type} visualization")
            return None

        try:
            combined_data = pd.concat(all_data, ignore_index=True)

            # MODIFIED: Apply robust datetime formatting
            combined_data = self._ensure_datetime_format(combined_data)

            # ADDED: Check if we still have valid timestamps after processing
            if combined_data.empty or combined_data['@timestamp'].isna().all():
                self.logger.warning(f"No valid timestamps found after processing for {data_type}")
                return None

            # Create the timeline plot
            return self._create_timeline_plot(combined_data, data_type,
                                            datetime.now().strftime("%Y%m%d_%H%M%S"))
        except Exception as e:
            self.logger.error(f"Error creating timeline visualization: {e}")
            plt.close('all')  # Close any open figures
            return None
    def _create_baseline_report(self, data, data_type):
        """
        NEW METHOD: Create a baseline report when no anomalies are detected.

        Args:
            data (pd.DataFrame): Normal data
            data_type (str): Type of data

        Returns:
            str: Markdown report content
        """
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        report_md = f"""# Linux {data_type.title()} Baseline Report

Generated: {timestamp_str}

## Summary

✅ **No anomalies detected** - All {len(data)} events appear normal.

- **Total events processed**: {len(data)}
- **Anomalies detected**: 0
- **System status**: Normal operation
- **Analysis period**: {data['@timestamp'].min() if '@timestamp' in data.columns else 'Unknown'} to {data['@timestamp'].max() if '@timestamp' in data.columns else 'Unknown'}

## Normal Activity Overview
"""

        # Add entity-specific baseline info
        entity_columns = {
            "process": "process.name",
            "network": "destination.geo.country_name",
            "user": "user.name",
            "discovery": "process.name",
            "metadata": "process.name"
        }

        entity_col = entity_columns.get(data_type, "host.hostname")

        if entity_col in data.columns:
            top_entities = data[entity_col].astype(str).fillna('unknown').value_counts().head(10)
            report_md += f"\n### Top {data_type.title()} Entities\n\n"
            for entity, count in top_entities.items():
                report_md += f"- **{entity}**: {count} events\n"

        # Add event count distribution
        if 'event_count' in data.columns:
            report_md += "\n### Event Distribution\n\n"
            report_md += f"- **Average events per bucket**: {data['event_count'].mean():.2f}\n"
            report_md += f"- **Maximum events in bucket**: {data['event_count'].max()}\n"
            report_md += f"- **Total unique entities**: {data[entity_col].nunique() if entity_col in data.columns else 'Unknown'}\n"

        # Add host distribution
        if 'host.hostname' in data.columns:
            unique_hosts = data['host.hostname'].nunique()
            report_md += "\n### Host Coverage\n\n"
            report_md += f"- **Hosts monitored**: {unique_hosts}\n"

            top_hosts = data['host.hostname'].astype(str).fillna('unknown').value_counts().head(5)
            report_md += "\n**Most active hosts**:\n"
            for host, count in top_hosts.items():
                report_md += f"- {host}: {count} events\n"

        # Add data type specific baseline metrics
        if data_type == "process":
            if 'is_root_user' in data.columns:
                root_events = data['is_root_user'].sum()
                report_md += "\n### Process Baseline Metrics\n\n"
                report_md += f"- **Root user events**: {root_events} ({root_events/len(data)*100:.1f}%)\n"

            if 'is_system_path' in data.columns:
                system_events = data['is_system_path'].sum()
                report_md += f"- **System path executions**: {system_events} ({system_events/len(data)*100:.1f}%)\n"

        elif data_type == "network":
            if 'destination.port' in data.columns:
                unique_ports = data['destination.port'].nunique()
                report_md += "\n### Network Baseline Metrics\n\n"
                report_md += f"- **Unique destination ports**: {unique_ports}\n"

                common_ports = data['destination.port'].astype(str).fillna('unknown').value_counts().head(5)
                report_md += "\n**Most common ports**:\n"
                for port, count in common_ports.items():
                    report_md += f"- Port {port}: {count} connections\n"

        elif data_type == "user":
            if 'user.name' in data.columns:
                unique_users = data['user.name'].nunique()
                report_md += "\n### User Baseline Metrics\n\n"
                report_md += f"- **Active users**: {unique_users}\n"

                top_users = data['user.name'].astype(str).fillna('unknown').value_counts().head(5)
                report_md += "\n**Most active users**:\n"
                for user, count in top_users.items():
                    report_md += f"- {user}: {count} events\n"

        report_md += """

## Analysis Notes

This baseline report shows normal system activity with no detected anomalies. This could indicate:

1. **Stable Environment**: The system is operating within normal parameters
2. **Effective Security**: Current security controls are preventing anomalous activity
3. **Baseline Period**: This data can be used to establish normal behavior patterns
4. **Threshold Tuning**: Consider lowering detection thresholds if more sensitive detection is needed

## Recommendations

- **Continue Monitoring**: Maintain current detection coverage
- **Baseline Establishment**: Use this data to refine normal behavior models
- **Threshold Review**: Consider if detection sensitivity needs adjustment
- **Historical Comparison**: Compare with previous periods to identify trends

---

*Baseline report generated by Linux Anomaly Detection System*
"""

        return report_md
    def _create_network_visualizations(self, results_dict):
        """Create network activity visualizations with anomaly highlighting."""
        viz_paths = []

        # Combine network results
        all_network_data = []
        for job_name, results in results_dict.items():
            if not results.empty:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_network_data.append(results_copy)

        if not all_network_data:
            logger.warning("No network data available for visualization")
            return viz_paths

        combined_data = pd.concat(all_network_data, ignore_index=True)
        combined_data = self._ensure_datetime_format(combined_data)

        # Get anomalies if available
        has_anomalies = False
        if 'final_anomaly' in combined_data.columns:
            anomalies = combined_data[combined_data['final_anomaly']]
            has_anomalies = not anomalies.empty
            if has_anomalies:
                logger.info(f"Found {len(anomalies)} network anomalies to visualize")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 1. Destination ports distribution
            if 'destination.port' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                # Get top 15 ports by frequency
                port_counts = combined_data['destination.port'].astype(str).fillna('unknown').value_counts().head(15)

                # Determine colors based on anomalies
                if has_anomalies and 'destination.port' in anomalies.columns:
                    anomalous_ports = set(anomalies['destination.port'].unique())
                    colors = ['red' if port in anomalous_ports else 'blue' for port in port_counts.index]
                else:
                    colors = 'blue'

                # Create bar chart
                ax = port_counts.plot(kind='barh', color=colors, alpha=0.7)
                plt.title('Top 15 Destination Ports', fontsize=14, fontweight='bold')
                plt.xlabel('Number of Connections')
                plt.ylabel('Port')

                # Add annotations for well-known ports
                well_known_ports = {
                    22: 'SSH',
                    23: 'Telnet',
                    25: 'SMTP',
                    53: 'DNS',
                    80: 'HTTP',
                    123: 'NTP',
                    443: 'HTTPS',
                    445: 'SMB',
                    3389: 'RDP',
                    8080: 'HTTP Proxy'
                }

                for i, port in enumerate(port_counts.index):
                    if port in well_known_ports:
                        ax.text(port_counts[port] + 0.5, i, f" ({well_known_ports[port]})",
                            va='center', fontsize=9)

                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_ports_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 2. Geo distribution (if available)
            if 'destination.geo.country_name' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                country_counts = combined_data['destination.geo.country_name'].astype(str).fillna('unknown').value_counts().head(10)

                # Determine colors based on anomalies
                if has_anomalies and 'destination.geo.country_name' in anomalies.columns:
                    anomalous_countries = set(anomalies['destination.geo.country_name'].unique())
                    colors = ['red' if country in anomalous_countries else 'blue'
                            for country in country_counts.index]
                else:
                    colors = 'blue'

                ax = country_counts.plot(kind='bar', color=colors, alpha=0.7)
                plt.title('Top 10 Destination Countries', fontsize=14, fontweight='bold')
                plt.xlabel('Country')
                plt.ylabel('Number of Connections')
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_countries_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 3. Network activity by process
            if all(col in combined_data.columns for col in ['process.name', 'event_count']):
                plt.figure(figsize=(12, 8))

                # Aggregate by process
                process_counts = combined_data.groupby('process.name')['event_count'].sum().sort_values(ascending=False).head(15)

                # Determine colors based on anomalies
                if has_anomalies and 'process.name' in anomalies.columns:
                    anomalous_processes = set(anomalies['process.name'].unique())
                    colors = ['red' if proc in anomalous_processes else 'blue'
                            for proc in process_counts.index]
                else:
                    colors = 'blue'

                ax = process_counts.plot(kind='barh', color=colors, alpha=0.7)
                plt.title('Top 15 Processes by Network Activity', fontsize=14, fontweight='bold')
                plt.xlabel('Number of Events')
                plt.ylabel('Process')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_processes_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 4. Network activity timeline
            if all(col in combined_data.columns for col in ['@timestamp', 'event_count']):
                plt.figure(figsize=(14, 6))

                # Group by hour
                combined_data['hour'] = combined_data['@timestamp'].dt.floor('H')
                hourly_data = combined_data.groupby('hour')['event_count'].sum()

                # Create main line plot
                ax = hourly_data.plot(kind='line', marker='o', color='blue', alpha=0.7)

                # Add anomalies if available
                if has_anomalies and '@timestamp' in anomalies.columns:
                    # Group anomalies by hour
                    anomalies['hour'] = anomalies['@timestamp'].dt.floor('H')
                    hourly_anomalies = anomalies.groupby('hour')['event_count'].sum()

                    if not hourly_anomalies.empty:
                        # Plot anomalies as red points
                        hourly_anomalies.plot(kind='scatter', color='red', s=80,
                                            label='Anomalies', ax=ax)

                plt.title('Network Activity Timeline', fontsize=14, fontweight='bold')
                plt.xlabel('Time')
                plt.ylabel('Number of Events')
                plt.grid(True, alpha=0.3)
                plt.legend()
                plt.gcf().autofmt_xdate()
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_timeline_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 5. Network direction distribution
            if 'network.direction' in combined_data.columns:
                plt.figure(figsize=(10, 6))

                direction_counts = combined_data['network.direction'].astype(str).fillna('unknown').value_counts()

                # Set colors
                colors = ['#3498db', '#e74c3c']  # Blue for outbound, Red for inbound

                # Create pie chart
                plt.pie(direction_counts, labels=direction_counts.index, autopct='%1.1f%%',
                    startangle=90, shadow=True, colors=colors)
                plt.title('Network Traffic Direction', fontsize=14, fontweight='bold')
                plt.axis('equal')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_direction_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 6. Network protocol distribution
            if 'network.transport' in combined_data.columns:
                plt.figure(figsize=(10, 6))

                protocol_counts = combined_data['network.transport'].astype(str).fillna('unknown').value_counts()

                # Set colors
                colors = ['#3498db', '#e74c3c', '#2ecc71', '#f1c40f', '#9b59b6']  # Different colors for protocols

                # Create pie chart
                plt.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%',
                    startangle=90, shadow=True, colors=colors[:len(protocol_counts)])
                plt.title('Network Protocols', fontsize=14, fontweight='bold')
                plt.axis('equal')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_protocols_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 7. Anomaly score distribution (if anomalies exist)
            if has_anomalies and 'anomaly_score' in combined_data.columns:
                plt.figure(figsize=(12, 6))

                # Get all scores
                scores = combined_data['anomaly_score'].dropna()

                if len(scores) > 0:
                    # Create histogram with appropriate bins
                    n, bins, patches = plt.hist(scores, bins=50, alpha=0.7, color='blue')

                    # Color the bins with anomalies in red
                    threshold = min(anomalies['anomaly_score']) if not anomalies.empty else 0.8

                    for i in range(len(patches)):
                        if bins[i] >= threshold:
                            patches[i].set_facecolor('red')

                    plt.axvline(x=threshold, color='red', linestyle='--',
                            label=f'Anomaly Threshold ({threshold:.2f})')

                    plt.title('Network Anomaly Score Distribution', fontsize=14, fontweight='bold')
                    plt.xlabel('Anomaly Score')
                    plt.ylabel('Count')
                    plt.legend()
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"network_anomaly_scores_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 8. Network activity heatmap by hour and day
            if '@timestamp' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                # Extract hour and day of week
                combined_data['hour'] = combined_data['@timestamp'].dt.hour
                combined_data['day_of_week'] = combined_data['@timestamp'].dt.dayofweek

                # Create pivot table for heatmap
                day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                heatmap_data = combined_data.pivot_table(
                    values='event_count',
                    index='day_of_week',
                    columns='hour',
                    aggfunc='sum',
                    fill_value=0
                )

                # Reindex to ensure all hours and days are represented
                all_hours = list(range(24))
                all_days = list(range(7))
                heatmap_data = heatmap_data.reindex(index=all_days, columns=all_hours, fill_value=0)

                # Use better day names
                heatmap_data.index = [day_names[i] for i in heatmap_data.index]

                # Create heatmap
                ax = sns.heatmap(heatmap_data, cmap='YlOrRd', linewidths=0.5,
                            annot=False, fmt=".0f", cbar_kws={'label': 'Event Count'})

                plt.title('Network Activity by Hour and Day', fontsize=14, fontweight='bold')
                plt.xlabel('Hour of Day')
                plt.ylabel('Day of Week')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"network_activity_heatmap_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            logger.info(f"Generated {len(viz_paths)} network visualizations")
            return viz_paths

        except Exception as e:
            logger.error(f"Error creating network visualizations: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            plt.close()
            return viz_paths
    def create_data_type_visualizations(self, results, data_type):
        """
        Create visualizations for a specific data type with improved datetime handling.
        """
        if not results:
            logger.warning(f"No results to visualize for {data_type}")
            return []

        viz_paths = []
        plt.style.use('ggplot')

        try:
            # Extract anomalies across all jobs
            all_anomalies = []
            for job_name, df in results.items():
                if df.empty:
                    continue

                # Make sure we have a final_anomaly column
                if 'final_anomaly' not in df.columns:
                    df['final_anomaly'] = False

                job_anomalies = df[df['final_anomaly']].copy()
                if not job_anomalies.empty:
                    # Add job identifier
                    job_anomalies['job_id'] = job_name
                    all_anomalies.append(job_anomalies)

            if not all_anomalies:
                logger.warning(f"No anomalies found for {data_type} visualization")
                return []

            # Combine all anomalies
            try:
                combined_anomalies = pd.concat(all_anomalies, ignore_index=True)
            except Exception as e:
                logger.error(f"Error combining anomalies for visualization: {e}")
                # Fall back to using the first dataframe if concatenation fails
                combined_anomalies = all_anomalies[0]

            # FIXED: Ensure timestamps are datetime objects
            if '@timestamp' in combined_anomalies.columns:
                # Convert any non-datetime timestamps to datetime
                if not pd.api.types.is_datetime64_any_dtype(combined_anomalies['@timestamp']):
                    logger.warning("Converting @timestamp to datetime for visualization")
                    combined_anomalies['@timestamp'] = pd.to_datetime(combined_anomalies['@timestamp'], errors='coerce')

                # Remove rows with invalid timestamps
                combined_anomalies = combined_anomalies.dropna(subset=['@timestamp'])

                # Make sure we have data after timestamp cleaning
                if combined_anomalies.empty:
                    logger.warning("No valid timestamp data for visualization")
                    return []

                # Add explicit datetime columns for visualization
                combined_anomalies['datetime'] = combined_anomalies['@timestamp']
                combined_anomalies['hour'] = combined_anomalies['datetime'].dt.hour
                combined_anomalies['date'] = combined_anomalies['datetime'].dt.date

                # Visualization 1: Anomalies by job type
                try:
                    plt.figure(figsize=(10, 6))
                    job_counts = combined_anomalies['job_id'].astype(str).fillna('unknown').value_counts()
                    ax = job_counts.plot(kind='bar')
                    ax.set_title(f'{data_type.title()} Anomalies by Detection Job')
                    ax.set_ylabel('Count')
                    ax.set_xlabel('Job')
                    plt.tight_layout()

                    # Save visualization
                    viz_file = f"{data_type}_anomalies_by_job_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                    viz_path = os.path.join(self._safe_get_viz_dir(), viz_file)
                    plt.savefig(viz_path)
                    plt.close()
                    viz_paths.append(viz_path)

                except Exception as e:
                    logger.error(f"Error creating job visualization: {e}")

                # Visualization 2: Hourly anomaly distribution
                try:
                    # FIXED: Only attempt hourly visualization if datetime conversion succeeded
                    if 'hour' in combined_anomalies.columns:
                        plt.figure(figsize=(10, 6))
                        hourly_counts = combined_anomalies['hour'].astype(str).fillna('unknown').value_counts().sort_index()
                        ax = hourly_counts.plot(kind='bar')
                        ax.set_title(f'{data_type.title()} Anomalies by Hour of Day')
                        ax.set_ylabel('Count')
                        ax.set_xlabel('Hour')
                        plt.tight_layout()

                        # Save visualization
                        viz_file = f"{data_type}_anomalies_by_hour_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                        viz_path = viz_path = os.path.join(self._safe_get_viz_dir(), viz_file)
                        plt.savefig(viz_path)
                        plt.close()
                        viz_paths.append(viz_path)

                except Exception as e:
                    logger.warning(f"Error creating hourly {data_type} visualization: {e}")

                # Data type specific visualizations
                if data_type == "process":
                    # Top anomalous processes
                    try:
                        if 'process.name' in combined_anomalies.columns:
                            plt.figure(figsize=(10, 6))
                            process_counts = combined_anomalies['process.name'].astype(str).fillna('unknown').value_counts().head(10)
                            ax = process_counts.plot(kind='bar')
                            ax.set_title('Top 10 Anomalous Processes')
                            ax.set_ylabel('Count')
                            ax.set_xlabel('Process')
                            plt.tight_layout()

                            # Save visualization
                            viz_file = f"top_anomalous_processes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                            viz_path = os.path.join(str(self.config.get('output', {}).get('results_dir', 'results')), viz_file)

                            plt.savefig(viz_path)
                            plt.close()
                            viz_paths.append(viz_path)

                    except Exception as e:
                        logger.error(f"Error creating process visualization: {e}")

                elif data_type == "user":
                    # Top anomalous users
                    try:
                        if 'user.name' in combined_anomalies.columns:
                            plt.figure(figsize=(10, 6))
                            user_counts = combined_anomalies['user.name'].astype(str).fillna('unknown').value_counts().head(10)
                            ax = user_counts.plot(kind='bar')
                            ax.set_title('Top 10 Anomalous Users')
                            ax.set_ylabel('Count')
                            ax.set_xlabel('User')
                            plt.tight_layout()

                            # Save visualization
                            viz_file = f"top_anomalous_users_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                            viz_path = os.path.join(self.config.get('output', {}).get('visualizations_dir', 'results'), viz_file)
                            plt.savefig(viz_path)
                            plt.close()
                            viz_paths.append(viz_path)

                        # User activity type breakdown
                        plt.figure(figsize=(10, 6))
                        activity_cols = ['is_sudo_command', 'is_compiler_activity', 'is_root_user']
                        activity_data = []

                        for col in activity_cols:
                            if col in combined_anomalies.columns:
                                count = combined_anomalies[col].sum()
                                activity_data.append((col.replace('is_', '').replace('_', ' ').title(), count))

                        if activity_data:
                            labels, values = zip(*activity_data, strict=False)
                            plt.bar(labels, values)
                            plt.title('Anomalous User Activity Types')
                            plt.ylabel('Count')
                            plt.tight_layout()

                            # Save visualization
                            viz_file = f"user_activity_types_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                            viz_path = os.path.join(self.config.get('output', {}).get('visualizations_dir', 'results'), viz_file)
                            plt.savefig(viz_path)
                            plt.close()
                            viz_paths.append(viz_path)

                    except Exception as e:
                        logger.error(f"Error creating user visualization: {e}")

                elif data_type == "discovery":
                    # Discovery command categories
                    try:
                        if 'process.name' in combined_anomalies.columns:
                            plt.figure(figsize=(10, 6))
                            cmd_counts = combined_anomalies['process.name'].astype(str).fillna('unknown').value_counts().head(10)
                            ax = cmd_counts.plot(kind='bar')
                            ax.set_title('Top 10 Anomalous Discovery Commands')
                            ax.set_ylabel('Count')
                            ax.set_xlabel('Command')
                            plt.tight_layout()

                            # Save visualization
                            viz_file = f"top_discovery_commands_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                            viz_path = os.path.join(self.config.get('output', {}).get('visualizations_dir', 'results'), viz_file)
                            plt.savefig(viz_path)
                            plt.close()
                            viz_paths.append(viz_path)

                        # Create discovery category distribution if available
                        if 'discovery_category' in combined_anomalies.columns:
                            plt.figure(figsize=(10, 6))
                            category_counts = combined_anomalies['discovery_category'].astype(str).fillna('unknown').value_counts()
                            ax = category_counts.plot(kind='pie', autopct='%1.1f%%')
                            ax.set_title('Discovery Command Categories')
                            plt.tight_layout()

                            # Save visualization
                            viz_file = f"discovery_categories_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                            viz_path = os.path.join(str(self.config.get('output', {}).get('results_dir', 'results')), viz_file)

                            plt.savefig(viz_path)
                            plt.close()
                            viz_paths.append(viz_path)

                    except Exception as e:
                        logger.error(f"Error creating discovery visualization: {e}")

            logger.info(f"Generated {len(viz_paths)} visualizations for {data_type}")
            return viz_paths

        except Exception as e:
            logger.error(f"Error in visualization creation for {data_type}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return viz_paths
    def _create_metadata_visualizations(self, results_dict):
        """Create metadata access visualizations."""
        viz_paths = []

        # Combine metadata results
        all_metadata_data = []
        for job_name, results in results_dict.items():
            if not results.empty:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_metadata_data.append(results_copy)

        if not all_metadata_data:
            return viz_paths

        combined_data = pd.concat(all_metadata_data, ignore_index=True)
        combined_data = self._ensure_datetime_format(combined_data)

        # Get anomalies if available
        has_anomalies = False
        if 'final_anomaly' in combined_data.columns:
            anomalies = combined_data[combined_data['final_anomaly']]
            has_anomalies = not anomalies.empty

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 1. Metadata service types
            if 'metadata_service_type' in combined_data.columns:
                plt.figure(figsize=(10, 6))

                service_counts = combined_data['metadata_service_type'].astype(str).fillna('unknown').value_counts()

                service_counts.plot(kind='pie', autopct='%1.1f%%',
                                    startangle=90, shadow=True)
                plt.title('Metadata Access by Service Type', fontsize=14, fontweight='bold')
                plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"metadata_service_types_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 2. Metadata access by process
            if 'process.name' in combined_data.columns:
                plt.figure(figsize=(12, 8))

                process_counts = combined_data['process.name'].astype(str).fillna('unknown').value_counts().head(15)

                process_counts.plot(kind='barh', alpha=0.7,
                                        color='blue' if not has_anomalies else 'orange')
                plt.title('Top 15 Processes Accessing Metadata', fontsize=14, fontweight='bold')
                plt.xlabel('Number of Accesses')
                plt.ylabel('Process')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"metadata_processes_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 3. Metadata access by user
            if 'user.name' in combined_data.columns:
                plt.figure(figsize=(10, 6))

                user_counts = combined_data['user.name'].astype(str).fillna('unknown').value_counts().head(10)

                user_counts.plot(kind='bar', alpha=0.7,
                                    color='blue' if not has_anomalies else 'orange')
                plt.title('Metadata Access by User', fontsize=14, fontweight='bold')
                plt.xlabel('User')
                plt.ylabel('Number of Accesses')
                plt.xticks(rotation=45)
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"metadata_users_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 4. Potential credential harvesting
            if 'potential_cred_harvest' in combined_data.columns:
                plt.figure(figsize=(8, 6))

                cred_harvest = combined_data['potential_cred_harvest'].astype(str).fillna('unknown').value_counts()
                labels = ['No Credential Access', 'Potential Credential Access']

                plt.pie(cred_harvest, labels=labels, autopct='%1.1f%%',
                    startangle=90, shadow=True,
                    colors=['green', 'red'] if len(cred_harvest) > 1 else ['green'])
                plt.title('Potential Credential Harvesting Activity', fontsize=14, fontweight='bold')
                plt.axis('equal')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"metadata_cred_harvest_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 5. Metadata access timeline
            if '@timestamp' in combined_data.columns:
                plt.figure(figsize=(14, 6))

                # Group by hour and count
                combined_data['hour'] = combined_data['@timestamp'].dt.floor('H')
                hourly_counts = combined_data.groupby('hour').size()

                hourly_counts.plot(kind='line', marker='o', alpha=0.7)
                plt.title('Metadata Access Timeline', fontsize=14, fontweight='bold')
                plt.xlabel('Time')
                plt.ylabel('Number of Accesses')
                plt.grid(True, alpha=0.3)
                plt.gcf().autofmt_xdate()
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"metadata_timeline_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            return viz_paths

        except Exception as e:
            logger.error(f"Error creating metadata visualizations: {e}")
            plt.close()
            return viz_paths
    def _safe_visualization_create(self, viz_function, *args, **kwargs):
        """
        NEW METHOD: Safely create visualizations with error handling.

        Args:
            viz_function: Function to call for visualization
            *args, **kwargs: Arguments for the visualization function

        Returns:
            list: Paths to created visualizations (empty if error)
        """
        try:
            return viz_function(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Visualization creation failed: {e}")
            return []
    def _generate_specific_insights(self, anomalies, data_type):
        """
        Generate data type specific insights from anomalies.

        Args:
            anomalies (pd.DataFrame): Anomalous data
            data_type (str): Type of data

        Returns:
            dict: Data type specific insights
        """
        if anomalies.empty:
            return {}

        insights = {}

        try:
            # Process-specific insights
            if data_type == "process":
                # Check for unusual processes
                if 'process.name' in anomalies.columns:
                    unusual_processes = anomalies['process.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_processes'] = unusual_processes

                # Check for root privileges
                if 'is_root_user' in anomalies.columns:
                    root_count = anomalies['is_root_user'].sum()
                    insights['root_privilege_anomalies'] = {
                        'count': int(root_count),
                        'percentage': float(root_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for unusual execution paths
                if 'is_system_path' in anomalies.columns:
                    non_system_path_count = len(anomalies) - anomalies['is_system_path'].sum()
                    insights['non_system_path_anomalies'] = {
                        'count': int(non_system_path_count),
                        'percentage': float(non_system_path_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for temp directory execution
                if 'is_tmp_execution' in anomalies.columns:
                    tmp_execution_count = anomalies['is_tmp_execution'].sum()
                    if tmp_execution_count > 0:
                        insights['tmp_directory_execution'] = {
                            'count': int(tmp_execution_count),
                            'percentage': float(tmp_execution_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                        }

            # Network-specific insights
            elif data_type == "network":
                # Check for unusual destination countries
                if 'destination.geo.country_name' in anomalies.columns:
                    unusual_countries = anomalies['destination.geo.country_name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_countries'] = unusual_countries

                # Check for unusual ports
                if 'destination.port' in anomalies.columns:
                    unusual_ports = anomalies['destination.port'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_ports'] = unusual_ports

                    # Check for well-known vs. uncommon ports
                    well_known_ports = [21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3389, 5900, 8080]
                    well_known_count = anomalies['destination.port'].isin(well_known_ports).sum()
                    uncommon_count = len(anomalies) - well_known_count

                    insights['port_categories'] = {
                        'well_known': int(well_known_count),
                        'uncommon': int(uncommon_count),
                        'well_known_percentage': float(well_known_count / len(anomalies) * 100) if len(anomalies) > 0 else 0,
                        'uncommon_percentage': float(uncommon_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for data transfer volumes
                if 'network.bytes' in anomalies.columns:
                    total_bytes = anomalies['network.bytes'].sum()
                    avg_bytes = anomalies['network.bytes'].mean()
                    max_bytes = anomalies['network.bytes'].max()

                    insights['data_transfer'] = {
                        'total_bytes': int(total_bytes),
                        'avg_bytes_per_connection': float(avg_bytes),
                        'max_bytes': int(max_bytes)
                    }

            # User-specific insights
            elif data_type == "user":
                # Check for unusual users
                if 'user.name' in anomalies.columns:
                    unusual_users = anomalies['user.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_users'] = unusual_users

                # Check for sudo usage
                if 'is_sudo_command' in anomalies.columns:
                    sudo_count = anomalies['is_sudo_command'].sum()
                    insights['sudo_anomalies'] = {
                        'count': int(sudo_count),
                        'percentage': float(sudo_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for compiler activity
                if 'is_compiler_activity' in anomalies.columns:
                    compiler_count = anomalies['is_compiler_activity'].sum()
                    insights['compiler_anomalies'] = {
                        'count': int(compiler_count),
                        'percentage': float(compiler_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for after-hours activity
                if 'is_business_hours' in anomalies.columns:
                    after_hours_count = len(anomalies) - anomalies['is_business_hours'].sum()
                    insights['after_hours_anomalies'] = {
                        'count': int(after_hours_count),
                        'percentage': float(after_hours_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

            # Discovery-specific insights
            elif data_type == "discovery":
                # Check for unusual discovery commands
                if 'process.name' in anomalies.columns:
                    unusual_commands = anomalies['process.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_discovery_commands'] = unusual_commands

                # Check for discovery categories
                if 'discovery_category' in anomalies.columns:
                    category_counts = anomalies['discovery_category'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['discovery_categories'] = category_counts

                # Check for users performing discovery
                if 'user.name' in anomalies.columns:
                    discovery_users = anomalies['user.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['discovery_users'] = discovery_users

            # Metadata-specific insights
            elif data_type == "metadata":
                # Check for unusual metadata access
                if 'process.name' in anomalies.columns:
                    unusual_processes = anomalies['process.name'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['unusual_metadata_processes'] = unusual_processes

                # Check for credential harvesting
                if 'potential_cred_harvest' in anomalies.columns:
                    cred_harvest_count = anomalies['potential_cred_harvest'].sum()
                    insights['credential_harvesting'] = {
                        'count': int(cred_harvest_count),
                        'percentage': float(cred_harvest_count / len(anomalies) * 100) if len(anomalies) > 0 else 0
                    }

                # Check for metadata service types
                if 'metadata_service_type' in anomalies.columns:
                    service_counts = anomalies['metadata_service_type'].astype(str).fillna('unknown').value_counts().to_dict()
                    insights['metadata_service_types'] = service_counts

            return insights

        except Exception as e:
            # FIXED: Use self.logger instead of self.logger
            self.logger.warning(f"Error generating data type specific insights: {e}")
            return {}

    def _safe_create_process_visualizations(self, results_dict):
        """Safe wrapper for process visualizations."""
        return self._safe_visualization_create(self._create_process_visualizations, results_dict)

    def _safe_create_network_visualizations(self, results_dict):
        """Safe wrapper for network visualizations."""
        return self._safe_visualization_create(self._create_network_visualizations, results_dict)

    def _safe_create_user_visualizations(self, results_dict):
        """Safe wrapper for user visualizations."""
        return self._safe_visualization_create(self._create_user_visualizations, results_dict)

    def _safe_create_discovery_visualizations(self, results_dict):
        """Safe wrapper for discovery visualizations."""
        return self._safe_visualization_create(self._create_discovery_visualizations, results_dict)

    def _safe_create_metadata_visualizations(self, results_dict):
        """Safe wrapper for metadata visualizations."""
        return self._safe_visualization_create(self._create_metadata_visualizations, results_dict)

    def _create_anomaly_process_viz(self, anomalies, combined_data, timestamp):
        """Helper method for anomaly-specific process visualizations"""
        viz_paths = []

        try:
            # 1. Top anomalous processes
            if 'process.name' in anomalies.columns:
                plt.figure(figsize=(12, 8))
                # Convert to string and handle NaN
                process_series = anomalies['process.name'].astype(str).fillna('unknown')
                top_processes = process_series.astype(str).fillna('unknown').value_counts().head(15)

                if not top_processes.empty:
                    top_processes.plot(kind='barh', color='red', alpha=0.7)
                    plt.title('Top 15 Anomalous Processes', fontsize=14, fontweight='bold')
                    plt.xlabel('Number of Anomalies')
                    plt.ylabel('Process Name')
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_anomalies_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 2. Process anomalies by host
            if 'host.hostname' in anomalies.columns:
                plt.figure(figsize=(12, 8))
                host_series = anomalies['host.hostname'].astype(str).fillna('unknown')
                host_anomalies = host_series.astype(str).fillna('unknown').value_counts().head(10)

                if not host_anomalies.empty:
                    host_anomalies.plot(kind='bar', color='orange', alpha=0.7)
                    plt.title('Anomalous Processes by Host', fontsize=14, fontweight='bold')
                    plt.xlabel('Host')
                    plt.ylabel('Number of Anomalies')
                    plt.xticks(rotation=45)
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_hosts_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 3. FIX 2: Safe hourly pattern analysis
            if '@timestamp' in combined_data.columns:
                try:
                    plt.figure(figsize=(14, 6))

                    # Ensure we have valid timestamps
                    if not combined_data['@timestamp'].isna().all():
                        # Extract hour safely
                        combined_data['hour'] = combined_data['@timestamp'].dt.hour
                        anomalies['hour'] = anomalies['@timestamp'].dt.hour

                        # Get normal data
                        normal_data = combined_data[not combined_data.get('final_anomaly', False)]

                        # Count by hour
                        normal_hours = normal_data['hour'].astype(str).fillna('unknown').value_counts().sort_index()
                        anomaly_hours = anomalies['hour'].astype(str).fillna('unknown').value_counts().sort_index()

                        # Create bar chart
                        x = range(24)
                        width = 0.35

                        normal_counts = [normal_hours.get(i, 0) for i in x]
                        anomaly_counts = [anomaly_hours.get(i, 0) for i in x]

                        plt.bar([i - width/2 for i in x], normal_counts,
                            width, label='Normal', alpha=0.7, color='green')
                        plt.bar([i + width/2 for i in x], anomaly_counts,
                            width, label='Anomalies', alpha=0.7, color='red')

                        plt.title('Process Activity by Hour of Day', fontsize=14, fontweight='bold')
                        plt.xlabel('Hour of Day')
                        plt.ylabel('Number of Events')
                        plt.legend()
                        plt.xticks(x)
                        plt.tight_layout()

                        path = os.path.join(self.viz_dir, f"process_hourly_{timestamp}.png")
                        plt.savefig(path, dpi=300, bbox_inches='tight')
                        plt.close()
                        viz_paths.append(path)

                except Exception as e:
                    self.logger.warning(f"Error creating hourly visualization: {e}")
                    plt.close()

            return viz_paths

        except Exception as e:
            self.logger.error(f"Error in anomaly process visualization: {e}")
            plt.close('all')
            return viz_paths

    def _create_process_visualizations(self, results_dict):
        """
        FIXED: Create process-specific visualizations with robust timestamp handling.

        ROOT CAUSE: Still using direct pd.to_datetime() instead of our fixed method

        FIX: Replace direct conversion with _ensure_datetime_format() call
        """
        viz_paths = []

        # Combine process results
        all_process_data = []
        for job_name, results in results_dict.items():
            if not results.empty and 'process.name' in results.columns:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_process_data.append(results_copy)

        if not all_process_data:
            return viz_paths

        try:
            combined_data = pd.concat(all_process_data, ignore_index=True)

            # FIX: Use our robust datetime formatting method instead of direct conversion
            if '@timestamp' in combined_data.columns:
                try:
                    combined_data = self._ensure_datetime_format(combined_data)
                except Exception as e:
                    self.logger.warning(f"Timestamp conversion failed for process visualization: {e}")
                    # Continue without timestamp-based features

            # Check for anomalies
            has_anomalies = 'final_anomaly' in combined_data.columns
            if has_anomalies:
                anomalies = combined_data[combined_data['final_anomaly']]
                has_anomalies = not anomalies.empty
            else:
                anomalies = pd.DataFrame()  # Empty dataframe

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            # 1. Top anomalous processes (if we have anomalies)
            if has_anomalies and 'process.name' in anomalies.columns:
                plt.figure(figsize=(12, 8))
                # Safe string conversion
                process_series = anomalies['process.name'].astype(str).fillna('unknown')
                top_processes = process_series.astype(str).fillna('unknown').value_counts().head(15)

                if not top_processes.empty:
                    top_processes.plot(kind='barh', color='red', alpha=0.7)
                    plt.title('Top 15 Anomalous Processes', fontsize=14, fontweight='bold')
                    plt.xlabel('Number of Anomalies')
                    plt.ylabel('Process Name')
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_anomalies_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 2. Process anomalies by host
            if has_anomalies and 'host.hostname' in combined_data.columns:
                plt.figure(figsize=(12, 8))
                host_series = anomalies['host.hostname'].astype(str).fillna('unknown')
                host_anomalies = host_series.astype(str).fillna('unknown').value_counts().head(10)

                if not host_anomalies.empty:
                    host_anomalies.plot(kind='bar', color='orange', alpha=0.7)
                    plt.title('Anomalous Processes by Host', fontsize=14, fontweight='bold')
                    plt.xlabel('Host')
                    plt.ylabel('Number of Anomalies')
                    plt.xticks(rotation=45)
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_hosts_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 3. Process execution patterns (only if we have valid timestamps)
            if '@timestamp' in combined_data.columns and not combined_data['@timestamp'].isna().all():
                try:
                    plt.figure(figsize=(14, 6))

                    # Safe hour extraction
                    combined_data['hour'] = combined_data['@timestamp'].dt.hour

                    if has_anomalies:
                        # Add hour to anomalies dataframe
                        anomalies_with_hour = anomalies.copy()
                        if '@timestamp' in anomalies_with_hour.columns:
                            anomalies_with_hour = self._ensure_datetime_format(anomalies_with_hour)
                            anomalies_with_hour['hour'] = anomalies_with_hour['@timestamp'].dt.hour

                        normal_data = combined_data[not combined_data.get("final_anomaly", False)]
                        normal_hours = normal_data['hour'].astype(str).fillna('unknown').value_counts().sort_index()
                        anomaly_hours = anomalies_with_hour['hour'].astype(str).fillna('unknown').value_counts().sort_index()

                        x = range(24)
                        width = 0.35

                        plt.bar([i - width/2 for i in x], [normal_hours.get(i, 0) for i in x],
                            width, label='Normal', alpha=0.7, color='green')
                        plt.bar([i + width/2 for i in x], [anomaly_hours.get(i, 0) for i in x],
                            width, label='Anomalies', alpha=0.7, color='red')

                        plt.title('Process Activity by Hour of Day', fontsize=14, fontweight='bold')
                        plt.xlabel('Hour of Day')
                        plt.ylabel('Number of Events')
                        plt.legend()
                        plt.xticks(x)
                        plt.tight_layout()

                        path = os.path.join(self.viz_dir, f"process_hourly_{timestamp}.png")
                        plt.savefig(path, dpi=300, bbox_inches='tight')
                        plt.close()
                        viz_paths.append(path)
                    else:
                        # Baseline hourly chart
                        hour_counts = combined_data['hour'].astype(str).fillna('unknown').value_counts().sort_index()

                        plt.bar(range(24), [hour_counts.get(i, 0) for i in range(24)],
                                alpha=0.7, color='blue')

                        plt.title('Process Activity by Hour of Day (Baseline)', fontsize=14, fontweight='bold')
                        plt.xlabel('Hour of Day')
                        plt.ylabel('Number of Events')
                        plt.xticks(range(24))
                        plt.tight_layout()

                        path = os.path.join(self.viz_dir, f"process_baseline_hourly_{timestamp}.png")
                        plt.savefig(path, dpi=300, bbox_inches='tight')
                        plt.close()
                        viz_paths.append(path)

                except Exception as e:
                    self.logger.warning(f"Error creating hourly process visualization: {e}")
                    plt.close()

            return viz_paths

        except Exception as e:
            self.logger.error(f"Error creating process visualizations: {e}")
            plt.close('all')  # Clean up any open figures
            return viz_paths
    def _generate_anomaly_description(self, anomaly):
        """
        Generate a detailed description for a detected anomaly.

        Args:
            anomaly (pd.Series): A single anomaly record

        Returns:
            str: Human-readable description of the anomaly
        """
        description = []

        try:
            # Get basic anomaly information
            timestamp = anomaly.get('@timestamp', 'Unknown time')
            if isinstance(timestamp, pd.Timestamp):
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp_str = str(timestamp)

            # Add anomaly header with type and score
            anomaly_type = anomaly.get('detection_job', 'Unknown detection')
            score = anomaly.get('combined_score', anomaly.get('anomaly_score', 0))

            description.append(f"[{timestamp_str}] {anomaly_type.replace('_', ' ').title()} (Score: {score:.2f})")

            # Add entity information based on data type
            if 'data_type' in anomaly:
                data_type = anomaly['data_type']
            else:
                # Try to infer data type from detection job
                job = anomaly.get('detection_job', '')
                if 'process' in job:
                    data_type = 'process'
                elif 'network' in job:
                    data_type = 'network'
                elif 'user' in job:
                    data_type = 'user'
                elif 'discovery' in job:
                    data_type = 'discovery'
                elif 'metadata' in job:
                    data_type = 'metadata'
                else:
                    data_type = 'unknown'

            # Add entity-specific details
            if data_type == 'process':
                if 'process.name' in anomaly:
                    description.append(f"Process: {anomaly['process.name']}")
                if 'process.command_line' in anomaly:
                    cmd = anomaly['process.command_line']
                    # Truncate long command lines
                    if len(cmd) > 100:
                        cmd = cmd[:97] + '...'
                    description.append(f"Command: {cmd}")

            elif data_type == 'network':
                if 'destination.ip' in anomaly:
                    description.append(f"Destination IP: {anomaly['destination.ip']}")
                if 'destination.port' in anomaly:
                    description.append(f"Destination Port: {anomaly['destination.port']}")
                if 'destination.geo.country_name' in anomaly:
                    description.append(f"Country: {anomaly['destination.geo.country_name']}")

            elif data_type == 'user':
                if 'user.name' in anomaly:
                    description.append(f"User: {anomaly['user.name']}")
                if 'is_root_user' in anomaly and anomaly['is_root_user']:
                    description.append("Root privileges used")
                if 'is_sudo_command' in anomaly and anomaly['is_sudo_command']:
                    description.append("Sudo command execution")

            elif data_type == 'discovery':
                if 'process.name' in anomaly:
                    description.append(f"Discovery Command: {anomaly['process.name']}")
                if 'discovery_category' in anomaly:
                    description.append(f"Category: {anomaly['discovery_category']}")

            elif data_type == 'metadata':
                if 'process.name' in anomaly:
                    description.append(f"Process: {anomaly['process.name']}")
                if 'metadata_service_type' in anomaly:
                    description.append(f"Metadata Service: {anomaly['metadata_service_type']}")
                if 'potential_cred_harvest' in anomaly and anomaly['potential_cred_harvest']:
                    description.append("⚠️ Potential credential harvesting")

            # Add host information
            if 'host.hostname' in anomaly:
                description.append(f"Host: {anomaly['host.hostname']}")

            # Add detection method info if available
            methods = []
            if 'ml_detection' in anomaly and anomaly['ml_detection']:
                methods.append("Machine Learning")
            if 'stat_detection' in anomaly and anomaly['stat_detection']:
                methods.append("Statistical")
            if 'ts_detection' in anomaly and anomaly['ts_detection']:
                methods.append("Time Series")

            if methods:
                description.append(f"Detection Methods: {', '.join(methods)}")

            # Add reason if available
            if 'anomaly_reason' in anomaly and anomaly['anomaly_reason']:
                description.append(f"Reason: {anomaly['anomaly_reason']}")

            # Add features with high contribution to anomaly
            high_deviation_features = []
            for col in anomaly.index:
                if col.endswith('_deviation') and anomaly[col] > 2.0:
                    feature_name = col.replace('_deviation', '')
                    high_deviation_features.append(f"{feature_name} ({anomaly[col]:.2f}x)")

            if high_deviation_features:
                description.append(f"Anomalous Features: {', '.join(high_deviation_features[:3])}")

            # Return formatted description
            return "\n".join(description)

        except Exception as e:
            self.logger.warning(f"Error generating anomaly description: {e}")
            return f"Anomaly detected at {timestamp_str if 'timestamp_str' in locals() else 'unknown time'}"

    def _create_timeline_plot(self, data, data_type, timestamp_str):
        """Create a timeline visualization of activities with robust error handling."""
        if data.empty:
            return None

        try:
            plt.figure(figsize=(15, 8))

            # Ensure datetime format is correct
            data = self._ensure_datetime_format(data)

            if '@timestamp' not in data.columns or data['@timestamp'].isna().all():
                self.logger.warning("No valid timestamp column for timeline visualization")
                plt.close()
                return None

            # Sort by timestamp
            data = data.sort_values('@timestamp')

            # Prepare data for plotting
            dates = data['@timestamp']

            # Determine if we have anomaly scores
            if 'anomaly_score' in data.columns:
                scores = data['anomaly_score']
                has_anomalies = True
            else:
                # Just use event count as "score"
                scores = data.get('event_count', pd.Series([1] * len(data)))
                has_anomalies = False

            # Determine color based on anomaly status
            if has_anomalies and 'final_anomaly' in data.columns:
                colors = ['red' if a else 'blue' for a in data['final_anomaly']]
            else:
                colors = 'blue'

            # Create scatter plot
            plt.scatter(dates, scores, c=colors, alpha=0.7, s=50)

            # Add labels and title
            plt.title(f'{data_type.title()} Activity Timeline', fontsize=14, fontweight='bold')
            plt.xlabel('Time')

            if has_anomalies:
                plt.ylabel('Anomaly Score')
            else:
                plt.ylabel('Event Count')

            # Format x-axis
            plt.gcf().autofmt_xdate()

            # Add grid
            plt.grid(True, alpha=0.3)

            # Save the plot
            output_path = os.path.join(self.viz_dir, f"{data_type}_timeline_{timestamp_str}.png")
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()

            return output_path

        except Exception as e:
            self.logger.error(f"Error creating timeline plot: {e}")
            plt.close('all')  # Close any open figures
            return None
    def _create_baseline_process_viz(self, data, timestamp):
        """FIXED: Create baseline process visualization when no anomalies are detected."""
        if data.empty:
            return []

        viz_paths = []

        try:
            # 1. Top processes by event count
            if 'process.name' in data.columns:
                plt.figure(figsize=(12, 8))
                process_series = data['process.name'].astype(str).fillna('unknown')
                top_processes = process_series.astype(str).fillna('unknown').value_counts().head(15)

                if not top_processes.empty:
                    top_processes.plot(kind='barh', color='green', alpha=0.7)
                    plt.title('Top 15 Processes (Baseline)', fontsize=14, fontweight='bold')
                    plt.xlabel('Number of Events')
                    plt.ylabel('Process Name')
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_baseline_top_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 2. Process activity by host
            if 'host.hostname' in data.columns:
                plt.figure(figsize=(12, 8))
                host_series = data['host.hostname'].astype(str).fillna('unknown')
                host_process = host_series.astype(str).fillna('unknown').value_counts().head(10)

                if not host_process.empty:
                    host_process.plot(kind='bar', color='blue', alpha=0.7)
                    plt.title('Process Activity by Host (Baseline)', fontsize=14, fontweight='bold')
                    plt.xlabel('Host')
                    plt.ylabel('Number of Events')
                    plt.xticks(rotation=45)
                    plt.tight_layout()

                    path = os.path.join(self.viz_dir, f"process_baseline_hosts_{timestamp}.png")
                    plt.savefig(path, dpi=300, bbox_inches='tight')
                    plt.close()
                    viz_paths.append(path)

            # 3. FIX 3: Safe hourly distribution
            if '@timestamp' in data.columns:
                try:
                    plt.figure(figsize=(14, 6))

                    # Use robust datetime conversion
                    data = self._ensure_datetime_format(data)

                    if not data.empty and not data['@timestamp'].isna().all():
                        data['hour'] = data['@timestamp'].dt.hour
                        hour_counts = data['hour'].astype(str).fillna('unknown').value_counts().sort_index()

                        plt.bar(range(24), [hour_counts.get(i, 0) for i in range(24)],
                                alpha=0.7, color='green')

                        plt.title('Process Activity by Hour of Day (Baseline)', fontsize=14, fontweight='bold')
                        plt.xlabel('Hour of Day')
                        plt.ylabel('Number of Events')
                        plt.xticks(range(24))
                        plt.tight_layout()

                        path = os.path.join(self.viz_dir, f"process_baseline_hourly_{timestamp}.png")
                        plt.savefig(path, dpi=300, bbox_inches='tight')
                        plt.close()
                        viz_paths.append(path)

                except Exception as e:
                    self.logger.warning(f"Error creating baseline hourly chart: {e}")
                    plt.close()

            return viz_paths

        except Exception as e:
            self.logger.error(f"Error creating baseline process visualization: {e}")
            plt.close('all')
            return viz_paths

    def _create_user_visualizations(self, results_dict):
        """Create user activity visualizations."""
        viz_paths = []

        # Combine user results
        all_user_data = []
        for job_name, results in results_dict.items():
            if not results.empty and 'user.name' in results.columns:
                results_copy = results.copy()
                results_copy['job'] = job_name
                all_user_data.append(results_copy)

        if not all_user_data:
            return viz_paths

        combined_data = pd.concat(all_user_data, ignore_index=True)

        # Get anomalies if available
        if 'final_anomaly' in combined_data.columns:
            anomalies = combined_data[combined_data['final_anomaly']]
            has_anomalies = not anomalies.empty
        else:
            has_anomalies = False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            # 1. User activity overview
            plt.figure(figsize=(12, 8))

            if 'user.name' in combined_data.columns:
                combined_data['user.name'] = combined_data['user.name'].apply(
                    lambda x: self.type_handler.safe_string_conversion(x) if pd.notna(x) else 'unknown'
                )
                top_users = combined_data['user.name'].astype(str).fillna('unknown').value_counts().head(10)

                top_users.plot(kind='barh', alpha=0.7,
                                color='blue' if not has_anomalies else 'orange')
                plt.title('Top 10 Active Users', fontsize=14, fontweight='bold')
                plt.xlabel('Number of Events')
                plt.ylabel('User Name')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"user_activity_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 2. Root vs non-root activity
            if 'is_root_user' in combined_data.columns:
                plt.figure(figsize=(10, 6))

                root_count = combined_data['is_root_user'].sum()
                non_root_count = len(combined_data) - root_count

                plt.bar(['Root User', 'Non-Root User'], [root_count, non_root_count],
                    alpha=0.7, color=['red', 'green'])

                plt.title('Root vs Non-Root User Activity', fontsize=14, fontweight='bold')
                plt.ylabel('Number of Events')
                plt.tight_layout()

                path = os.path.join(self.viz_dir, f"user_root_activity_{timestamp}.png")
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(path)

            # 3. Specialized activity types if available
            activity_types = []
            if 'is_sudo_command' in combined_data.columns:
                activity_types.append('is_sudo_command')
            if 'is_compiler_activity' in combined_data.columns:
                activity_types.append('is_compiler_activity')
            if 'is_dev_tool' in combined_data.columns:
                activity_types.append('is_dev_tool')

            if activity_types:
                plt.figure(figsize=(12, 8))

                activity_counts = [combined_data[col].sum() for col in activity_types]
                activity_labels = [col.replace('is_', '').replace('_', ' ').title() for col in activity_types]

                plt.bar(activity_labels, activity_counts, alpha=0.7, color=['purple', 'orange', 'brown'][:len(activity_types)])

                plt.title('Specialized User Activities', fontsize=14, fontweight='bold')
                plt.ylabel('Number of Events')
                plt.tight_layout()

                viz_file = f"user_specialized_activity_{timestamp}.png"
                viz_path = ConfigManager.get_visualization_path(self.config, viz_file)
                plt.savefig(path, dpi=300, bbox_inches='tight')
                plt.close()
                viz_paths.append(viz_path)

            return viz_paths

        except Exception as e:
            logger.error(f"Error creating user visualizations: {e}")
            plt.close()
            return viz_paths



# Add standalone functions that were imported by anomaly_detector.py
def generate_linux_report(results, config, data_type="process"):
    """
    Generate comprehensive Linux anomaly detection report.

    Args:
        results (pd.DataFrame or dict): Results data
        config (dict): Configuration dictionary
        data_type (str): Type of data

    Returns:
        tuple: (report_file_path, csv_file_path)
    """
    # apply_all_fixes expects a single DataFrame. If we were given a dict of
    # job results, apply fixes to each DataFrame value individually. This
    # prevents passing a dict into apply_all_fixes which leads to unexpected
    # types downstream (e.g. dicts instead of DataFrames).
    visualizer = LinuxAnomalyVisualizer(config)

    if isinstance(results, pd.DataFrame):
        # Safe to apply fixes directly
        results, fixed_config = apply_all_fixes(results, config, data_type)
        results_dict = {f"{data_type}_detection": results}
    elif isinstance(results, dict):
        # Apply fixes per-job for DataFrame values
        results_dict = {}
        for k, v in results.items():
            if isinstance(v, pd.DataFrame):
                try:
                    fixed_df, _ = apply_all_fixes(v, config, data_type)
                    results_dict[k] = fixed_df
                except Exception:
                    # If fixing fails, keep original value and let later
                    # normalization handle it
                    results_dict[k] = v
            else:
                results_dict[k] = v
    else:
        # Unknown type: treat as empty mapping
        results_dict = {}

    # Defensive normalization: ensure every value in results_dict is a pandas DataFrame
    normalized = {}
    for k, v in (results_dict or {}).items():
        # If it's already a DataFrame, keep it
        if isinstance(v, pd.DataFrame):
            normalized[k] = v
            continue

        # If it's a tuple like (df, saveable), take first element if DataFrame
        if isinstance(v, tuple) and len(v) > 0 and isinstance(v[0], pd.DataFrame):
            normalized[k] = v[0]
            continue

        # If it's a dict, try to convert to DataFrame
        if isinstance(v, dict):
            try:
                normalized[k] = pd.DataFrame.from_dict(v)
                continue
            except Exception:
                # As a last resort wrap it into a single-row DataFrame
                normalized[k] = pd.DataFrame([v])
                continue

        # If it's a list, try to make DataFrame
        if isinstance(v, list):
            try:
                normalized[k] = pd.DataFrame(v)
                continue
            except Exception:
                normalized[k] = pd.DataFrame([{'value': v}])
                continue

        # Unknown type: create empty DataFrame to keep the pipeline running
        normalized[k] = pd.DataFrame()

    return visualizer.generate_comprehensive_report(normalized, data_type)

def create_linux_visualizations(results, config, data_type="process"):
    """
    Create visualizations for Linux anomaly detection results.

    Args:
        results (pd.DataFrame or dict): Results data
        config (dict): Configuration dictionary
        data_type (str): Type of data

    Returns:
        list: Paths to created visualizations
    """
    # apply_all_fixes works on a single DataFrame. If given a dict of job
    # results, apply fixes per-job only for DataFrame values to avoid
    # transforming dict inputs into incorrect types.
    visualizer = LinuxAnomalyVisualizer(config)

    if isinstance(results, pd.DataFrame):
        results, _ = apply_all_fixes(results, config, data_type)
        results_dict = {f"{data_type}_detection": results}
    elif isinstance(results, dict):
        results_dict = {}
        for k, v in results.items():
            if isinstance(v, pd.DataFrame):
                try:
                    fixed_df, _ = apply_all_fixes(v, config, data_type)
                    results_dict[k] = fixed_df
                except Exception:
                    results_dict[k] = v
            else:
                results_dict[k] = v
    else:
        results_dict = {}

    # Defensive normalization: ensure every value in results_dict is a pandas DataFrame
    normalized = {}
    for k, v in (results_dict or {}).items():
        if isinstance(v, pd.DataFrame):
            normalized[k] = v
            continue
        if isinstance(v, tuple) and len(v) > 0 and isinstance(v[0], pd.DataFrame):
            normalized[k] = v[0]
            continue
        if isinstance(v, dict):
            try:
                normalized[k] = pd.DataFrame.from_dict(v)
                continue
            except Exception:
                normalized[k] = pd.DataFrame([v])
                continue
        if isinstance(v, list):
            try:
                normalized[k] = pd.DataFrame(v)
                continue
            except Exception:
                normalized[k] = pd.DataFrame([{'value': v}])
                continue
        normalized[k] = pd.DataFrame()

    return visualizer.create_data_type_visualizations(normalized, data_type)

def visualize_linux_results(results, config, entity=None, data_type="process"):
    """
    Create basic timeline visualization for Linux anomaly results.
    Backward compatibility function.

    Args:
        results (pd.DataFrame): Results with anomaly flags and scores
        config (dict): Configuration dictionary
        entity (str, optional): Specific entity to filter by
        data_type (str): Type of data

    Returns:
        str: Path to the saved visualization
    """
    if results.empty:
        logger.warning("No results to visualize")
        return None

    if not config.get("output", {}).get("visualization", True):
        return None

    visualizer = LinuxAnomalyVisualizer(config)

    # Filter for specific entity if provided
    entity_columns = {
        "process": "process.name",
        "network": "destination.geo.country_name",
        "user": "user.name",
        "discovery": "process.name",
        "metadata": "process.name"
    }

    entity_col = entity_columns.get(data_type, "host.hostname")

    if entity and entity_col in results.columns:
        filtered_results = results[results[entity_col] == entity].copy()
        if filtered_results.empty:
            logger.warning(f"No results for {entity}")
            return None
    else:
        filtered_results = results.copy()

    return visualizer._create_timeline_plot(
        filtered_results,
        data_type,
        datetime.now().strftime("%Y%m%d_%H%M%S")
    )

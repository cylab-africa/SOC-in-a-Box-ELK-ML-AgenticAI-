"""
ATT&CK-based synthetic attack data generator.

Creates labeled attack samples embedded in real background data for model
evaluation, adversarial training, and red-team simulation. All generated
events use realistic feature ranges rather than cartoonish extremes.

MITRE ATT&CK techniques covered:
  T1059.004 - Unix Shell (shell_injection)
  T1053.003 - Cron (cron_persistence)
  T1048     - Exfiltration Over Alternative Protocol (slow_exfil)
  T1078     - Valid Accounts (credential_reuse)
  T1046     - Network Service Discovery (discovery_sweep)
  T1018     - Remote System Discovery (discovery_sweep)
  T1021.004 - SSH (lateral_movement)
  T1568.002 - Domain Generation Algorithms (dga_beacon)
  T1059     - Command and Scripting Interpreter (lolbin_chain)
"""

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

DEFAULT_ATTACK_DENSITY = 0.02

# Registry of scenario name -> (technique_id, generator_function_name)
SCENARIO_REGISTRY: dict[str, str] = {
    "shell_injection": "T1059.004",
    "cron_persistence": "T1053.003",
    "slow_exfil": "T1048",
    "credential_reuse": "T1078",
    "discovery_sweep": "T1046",
    "lateral_movement": "T1021.004",
    "dga_beacon": "T1568.002",
    "lolbin_chain": "T1059",
}


class AttackGenerator:
    """Generates synthetic attack events embedded in real background data.

    Each generated DataFrame contains all columns from the background data plus:
      - ``is_attack`` (bool): True for attack rows.
      - ``attack_technique`` (str): MITRE ATT&CK technique ID, or '' for benign.

    MITRE ATT&CK: multiple techniques (see module docstring).
    """

    def __init__(self, random_seed: int = 42) -> None:
        """Initialize AttackGenerator.

        Args:
            random_seed: Seed for reproducible synthetic data generation.
        """
        self._rng = np.random.default_rng(random_seed)

    def available_scenarios(self) -> list[str]:
        """Return the list of supported attack scenario names.

        Returns:
            Sorted list of scenario name strings.
        """
        return sorted(SCENARIO_REGISTRY.keys())

    def generate(
        self,
        scenario: str,
        n_samples: int,
        background_df: pd.DataFrame,
        attack_density: float = DEFAULT_ATTACK_DENSITY,
    ) -> pd.DataFrame:
        """Generate synthetic attack events embedded in real background data.

        Args:
            scenario: Attack scenario name. See ``available_scenarios()``.
            n_samples: Total number of rows to return (background + attack).
            background_df: Real background data used to sample benign rows and
                derive realistic feature distributions.
            attack_density: Fraction of output rows that are attack events.
                Default is 0.02 (2%).

        Returns:
            DataFrame with all original columns plus ``is_attack`` and
            ``attack_technique``.

        Raises:
            ValueError: If scenario is not recognized.
        """
        if scenario not in SCENARIO_REGISTRY:
            raise ValueError(
                f"Unknown scenario '{scenario}'. "
                f"Available: {self.available_scenarios()}"
            )
        if not 0.0 < attack_density < 1.0:
            raise ValueError(f"attack_density must be in (0, 1), got {attack_density}")

        n_attack = max(1, int(n_samples * attack_density))
        n_benign = n_samples - n_attack

        # Sample benign background rows (with replacement if needed)
        benign_rows = background_df.sample(
            n=n_benign,
            replace=len(background_df) < n_benign,
            random_state=int(self._rng.integers(0, 2**31)),
        ).copy()
        benign_rows["is_attack"] = False
        benign_rows["attack_technique"] = ""

        # Generate attack rows
        technique_id = SCENARIO_REGISTRY[scenario]
        generator_name = f"_generate_{scenario}"
        generator = getattr(self, generator_name)
        attack_rows = generator(n_attack, background_df)
        attack_rows["is_attack"] = True
        attack_rows["attack_technique"] = technique_id

        combined = pd.concat([benign_rows, attack_rows], ignore_index=True)
        combined = combined.sample(
            frac=1,
            random_state=int(self._rng.integers(0, 2**31)),
        ).reset_index(drop=True)

        logger.info(
            f"Generated {n_attack} attack rows ({scenario}/{technique_id}) "
            f"and {n_benign} benign rows, total {len(combined)}"
        )
        return combined

    # ------------------------------------------------------------------
    # Private scenario generators
    # ------------------------------------------------------------------

    def _base_rows(self, n: int, background_df: pd.DataFrame) -> pd.DataFrame:
        """Sample n background rows as a starting point for attack mutation.

        Args:
            n: Number of rows to sample.
            background_df: Background DataFrame to sample from.

        Returns:
            Sampled DataFrame copy.
        """
        return background_df.sample(
            n=n,
            replace=len(background_df) < n,
            random_state=int(self._rng.integers(0, 2**31)),
        ).copy()

    def _numeric_cols(self, df: pd.DataFrame) -> list[str]:
        """Return names of numeric columns in df.

        Args:
            df: Input DataFrame.

        Returns:
            List of numeric column names.
        """
        return df.select_dtypes(include="number").columns.tolist()

    def _perturb(
        self, df: pd.DataFrame, col: str, scale: float, min_val: float | None = None
    ) -> None:
        """Perturb a numeric column in-place by adding scaled noise.

        Args:
            df: DataFrame to modify in-place.
            col: Column name to perturb.
            scale: Multiplier for perturbation magnitude relative to column std.
            min_val: Optional minimum value to clip the result.
        """
        if col not in df.columns or not pd.api.types.is_numeric_dtype(df[col]):
            return
        std = float(df[col].std()) if df[col].std() > 0 else 1.0
        noise = self._rng.normal(0, scale * std, size=len(df))
        df[col] = df[col] + noise
        if min_val is not None:
            df[col] = df[col].clip(lower=min_val)

    def _generate_shell_injection(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate shell injection attack rows (T1059.004).

        Characteristics: high-entropy commands, unusual process lineage
        (web server -> shell -> network tool), elevated command length.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        # Elevate entropy-related numeric features
        for col in ["cmd_entropy", "entropy", "command_entropy"]:
            self._perturb(rows, col, scale=2.0, min_val=0.0)
        # Increase command length
        for col in ["cmd_length", "command_length", "cmdline_length"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        # Elevate process tree depth indicators
        for col in ["proc_tree_depth", "process_depth", "parent_depth"]:
            self._perturb(rows, col, scale=1.5, min_val=0.0)
        return rows

    def _generate_cron_persistence(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate cron-based persistence attack rows (T1053.003).

        Characteristics: cron-related process name, unusual execution hour
        (late night / early morning), unusual user context.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        # Set execution to odd hours (0-5 AM) if hour column exists
        for col in ["hour", "exec_hour", "event_hour"]:
            if col in rows.columns and pd.api.types.is_numeric_dtype(rows[col]):
                rows[col] = self._rng.integers(0, 5, size=len(rows))
        # Slightly elevate process rarity scores
        for col in ["process_rarity", "rare_process_score", "proc_rarity"]:
            self._perturb(rows, col, scale=2.0, min_val=0.0)
        return rows

    def _generate_slow_exfil(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate slow exfiltration attack rows (T1048).

        Characteristics: periodic low-volume outbound to rare destination,
        elevated bytes_out ratio, connection to unusual port.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        for col in ["bytes_out", "network_bytes_out", "bytes_sent"]:
            self._perturb(rows, col, scale=2.5, min_val=0.0)
        for col in ["dest_rarity", "destination_rarity", "ip_rarity"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        for col in ["bytes_ratio", "out_in_ratio"]:
            self._perturb(rows, col, scale=2.0, min_val=0.0)
        return rows

    def _generate_credential_reuse(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate credential reuse attack rows (T1078).

        Characteristics: authentication from a new source IP, correct
        credentials, unusual time-of-day, potentially new geographic region.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        # Elevate source IP novelty
        for col in ["source_ip_rarity", "src_ip_rarity", "new_src_ip"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        # Set auth to unusual hour
        for col in ["hour", "auth_hour", "event_hour"]:
            if col in rows.columns and pd.api.types.is_numeric_dtype(rows[col]):
                rows[col] = self._rng.integers(1, 4, size=len(rows))
        for col in ["geo_rarity", "location_rarity"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        return rows

    def _generate_discovery_sweep(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate network/system discovery sweep attack rows (T1046, T1018).

        Characteristics: burst of recon commands (whoami, id, ifconfig,
        netstat), elevated distinct command count, elevated connection count.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        for col in ["distinct_commands", "unique_commands", "cmd_diversity"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        for col in ["connection_count", "network_connections", "conn_count"]:
            self._perturb(rows, col, scale=4.0, min_val=0.0)
        for col in ["recon_score", "discovery_score"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        return rows

    def _generate_lateral_movement(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate lateral movement attack rows (T1021.004).

        Characteristics: sequential SSH connections to multiple internal hosts,
        elevated distinct dest host count, short inter-connection intervals.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        for col in ["distinct_dest_hosts", "unique_destinations", "dest_host_count"]:
            self._perturb(rows, col, scale=4.0, min_val=0.0)
        for col in ["ssh_count", "lateral_connections"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        for col in ["internal_conn_rate", "internal_connection_rate"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        return rows

    def _generate_dga_beacon(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate DGA beaconing attack rows (T1568.002).

        Characteristics: DNS queries with high domain name entropy, periodic
        timing pattern, elevated query rate to unknown domains.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        for col in ["dns_entropy", "domain_entropy", "query_entropy"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        for col in ["dns_query_rate", "dns_count", "query_count"]:
            self._perturb(rows, col, scale=2.5, min_val=0.0)
        for col in ["domain_rarity", "nxdomain_ratio"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        return rows

    def _generate_lolbin_chain(
        self, n: int, background_df: pd.DataFrame
    ) -> pd.DataFrame:
        """Generate living-off-the-land binary chain attack rows (T1059).

        Characteristics: bash->python->curl->base64 style execution chains,
        elevated process chain depth, encoded command patterns.

        Args:
            n: Number of attack rows to generate.
            background_df: Background data for distribution reference.

        Returns:
            DataFrame of attack rows without is_attack/attack_technique.
        """
        rows = self._base_rows(n, background_df)
        for col in ["proc_tree_depth", "process_depth", "chain_depth"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        for col in ["encoded_cmd_ratio", "base64_usage", "encoded_ratio"]:
            self._perturb(rows, col, scale=4.0, min_val=0.0)
        for col in ["lolbin_score", "interpreter_chain_length"]:
            self._perturb(rows, col, scale=3.0, min_val=0.0)
        return rows

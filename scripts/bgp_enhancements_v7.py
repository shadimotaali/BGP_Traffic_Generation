"""
BGP Traffic Generation Enhancements - v7 Improvements
=====================================================

This module contains specific improvements to address correlation gaps
between synthetic and real BGP traffic.

Usage:
    from bgp_enhancements_v7 import *
    
    # In your traffic generation code:
    rare_as = generate_rare_as_with_clustering(topology, current_time, rare_as_history)
    edit_dist = sample_edit_distance_realistic()
    # etc.
"""

import random
import numpy as np
from scipy.stats import weibull_min, expon, pareto
from collections import defaultdict, deque
from typing import List, Dict, Tuple, Optional
import time


# =============================================================================
# 1. RARE AS IMPROVEMENTS
# =============================================================================

class RareASManager:
    """
    Manages rare AS appearances with temporal clustering and Zipf distribution.
    Addresses correlation gaps in rare AS metrics.
    """
    
    def __init__(self, topology, zipf_exponent=1.2, cluster_window=60.0):
        self.topology = topology
        self.zipf_exponent = zipf_exponent
        self.cluster_window = cluster_window  # seconds
        
        # Track recent rare AS appearances: (as_num, timestamp)
        self.rare_as_history = deque(maxlen=1000)
        
        # Identify rare ASes (Tier 3 or specific designation)
        self.rare_as_pool = self._identify_rare_ases()
        
        # Pre-compute Zipf weights
        self.zipf_weights = self._compute_zipf_weights()
    
    def _identify_rare_ases(self) -> List[int]:
        """Identify which ASes are considered 'rare' in the topology."""
        rare_ases = []
        for asn, info in self.topology.items():
            # Consider Tier 3 ASes as rare
            if info.get('tier', 0) >= 3:
                rare_ases.append(asn)
        return rare_ases
    
    def _compute_zipf_weights(self) -> List[float]:
        """
        Compute Zipf distribution weights for rare AS selection.
        Creates heavy-tailed distribution where few ASes appear often.
        """
        n = len(self.rare_as_pool)
        weights = [1.0 / (i + 1)**self.zipf_exponent for i in range(n)]
        # Normalize
        total = sum(weights)
        return [w / total for w in weights]
    
    def generate_rare_as(self, current_time: float) -> Optional[int]:
        """
        Generate a rare AS with temporal clustering.
        
        Returns:
            AS number or None if no rare AS should appear
        """
        # Clean old entries outside cluster window
        cutoff_time = current_time - self.cluster_window
        while self.rare_as_history and self.rare_as_history[0][1] < cutoff_time:
            self.rare_as_history.popleft()
        
        # Get recently seen rare ASes
        recent_rare = [as_num for as_num, _ in self.rare_as_history]
        
        # If we recently saw rare ASes, high probability to reuse
        if recent_rare and random.random() < 0.6:
            selected_as = random.choice(recent_rare)
        else:
            # Use Zipf distribution for new selection
            selected_as = random.choices(
                self.rare_as_pool,
                weights=self.zipf_weights,
                k=1
            )[0]
        
        # Record this appearance
        self.rare_as_history.append((selected_as, current_time))
        
        return selected_as
    
    def get_rare_as_stats(self) -> Dict:
        """Get statistics about rare AS appearances."""
        if not self.rare_as_history:
            return {'count': 0, 'unique': 0, 'avg_freq': 0.0}
        
        as_counts = defaultdict(int)
        for as_num, _ in self.rare_as_history:
            as_counts[as_num] += 1
        
        return {
            'count': len(self.rare_as_history),
            'unique': len(as_counts),
            'avg_freq': np.mean(list(as_counts.values())) if as_counts else 0.0
        }


# =============================================================================
# 2. EDIT DISTANCE IMPROVEMENTS
# =============================================================================

def sample_edit_distance_realistic() -> int:
    """
    Sample edit distance following realistic BGP distribution.
    
    Based on real BGP data:
    - ED=0: 15% (duplicates, no change)
    - ED=1: 40% (most common: single AS prepend/remove)
    - ED=2: 25% (moderate change)
    - ED=3-6: exponentially decreasing
    
    Returns:
        Edit distance value (0-6)
    """
    edit_distance_probs = {
        0: 0.15,  # No change
        1: 0.40,  # Most common
        2: 0.25,
        3: 0.12,
        4: 0.05,
        5: 0.02,
        6: 0.01
    }
    
    return random.choices(
        list(edit_distance_probs.keys()),
        weights=list(edit_distance_probs.values()),
        k=1
    )[0]


def scale_edit_distance_with_volume(base_edit_distance: int, 
                                   num_announcements: int) -> int:
    """
    Scale edit distance based on announcement volume.
    More announcements → more path diversity → higher edit distances.
    
    Args:
        base_edit_distance: Base edit distance value
        num_announcements: Number of announcements in current window
        
    Returns:
        Adjusted edit distance
    """
    # Volume factor increases logarithmically with announcements
    volume_factor = min(2.0, 1.0 + np.log1p(num_announcements / 100.0))
    
    # Apply factor with some randomness
    adjusted = int(base_edit_distance * volume_factor * random.uniform(0.9, 1.1))
    
    # Clamp to valid range
    return max(0, min(6, adjusted))


# =============================================================================
# 3. WITHDRAWAL CASCADE MODELING
# =============================================================================

class WithdrawalCascadeGenerator:
    """
    Models withdrawal cascades where one withdrawal triggers related withdrawals.
    Addresses correlation gaps in withdrawal-related metrics.
    """
    
    def __init__(self, topology, initial_cascade_prob=0.3, decay_factor=0.7):
        self.topology = topology
        self.initial_cascade_prob = initial_cascade_prob
        self.decay_factor = decay_factor
    
    def generate_cascade(self, 
                        initial_prefix: str, 
                        prefix_states: Dict) -> List[Tuple[str, str]]:
        """
        Generate a withdrawal cascade.
        
        Args:
            initial_prefix: The prefix that triggers the cascade
            prefix_states: Dictionary of all prefix states
            
        Returns:
            List of (prefix, action) tuples, e.g., [('10.0.0.0/24', 'withdraw'), ...]
        """
        withdrawals = [(initial_prefix, 'withdraw')]
        
        # Find related prefixes
        related_prefixes = self._find_related_prefixes(initial_prefix, prefix_states)
        
        cascade_prob = self.initial_cascade_prob
        for related_prefix in related_prefixes:
            if random.random() < cascade_prob:
                withdrawals.append((related_prefix, 'withdraw'))
                cascade_prob *= self.decay_factor  # Decay probability
                
                # Cascade can trigger further cascades (limited depth)
                if len(withdrawals) < 10 and random.random() < 0.3:
                    # Recursively find related prefixes
                    sub_related = self._find_related_prefixes(related_prefix, prefix_states)
                    for sub_prefix in sub_related[:3]:  # Limit sub-cascade
                        if random.random() < cascade_prob * 0.5:
                            withdrawals.append((sub_prefix, 'withdraw'))
        
        return withdrawals
    
    def _find_related_prefixes(self, 
                              prefix: str, 
                              prefix_states: Dict) -> List[str]:
        """
        Find prefixes related to the given prefix.
        Related means: same origin AS, overlapping IP space, or similar AS path.
        """
        if prefix not in prefix_states:
            return []
        
        prefix_state = prefix_states[prefix]
        related = []
        
        for other_prefix, other_state in prefix_states.items():
            if other_prefix == prefix:
                continue
            
            # Check if related by origin AS
            if (hasattr(prefix_state, 'origin_as') and 
                hasattr(other_state, 'origin_as') and
                prefix_state.origin_as == other_state.origin_as):
                related.append(other_prefix)
                continue
            
            # Check if related by AS path similarity
            if (hasattr(prefix_state, 'as_path') and 
                hasattr(other_state, 'as_path')):
                # Same AS path = related
                if prefix_state.as_path == other_state.as_path:
                    related.append(other_prefix)
                    continue
                
                # Overlapping path = somewhat related
                path1 = set(prefix_state.as_path.split()) if prefix_state.as_path else set()
                path2 = set(other_state.as_path.split()) if other_state.as_path else set()
                overlap = len(path1 & path2) / max(len(path1 | path2), 1)
                if overlap > 0.5:
                    related.append(other_prefix)
        
        # Shuffle to avoid always cascading in same order
        random.shuffle(related)
        return related[:20]  # Limit to top 20 related


# =============================================================================
# 4. TEMPORAL PATTERN IMPROVEMENTS
# =============================================================================

class TemporalPatternManager:
    """
    Manages temporal patterns including time-of-day effects and bursty traffic.
    """
    
    @staticmethod
    def get_activity_multiplier(current_hour_utc: int) -> float:
        """
        Get activity multiplier based on time of day.
        Peak hours: 12:00-18:00 UTC (business hours overlap)
        Low hours: 00:00-06:00 UTC
        
        Args:
            current_hour_utc: Hour of day in UTC (0-23)
            
        Returns:
            Activity multiplier (0.3-1.5)
        """
        hour_multipliers = {
            0: 0.4, 1: 0.3, 2: 0.3, 3: 0.3, 4: 0.4, 5: 0.5,
            6: 0.7, 7: 0.9, 8: 1.1, 9: 1.2, 10: 1.3, 11: 1.4,
            12: 1.5, 13: 1.5, 14: 1.5, 15: 1.4, 16: 1.3, 17: 1.2,
            18: 1.0, 19: 0.9, 20: 0.8, 21: 0.7, 22: 0.6, 23: 0.5
        }
        return hour_multipliers.get(current_hour_utc % 24, 1.0)
    
    @staticmethod
    def generate_bursty_inter_arrival(base_rate: float = 0.1, 
                                     burstiness: float = 0.7) -> float:
        """
        Generate inter-arrival time with heavy-tailed (bursty) distribution.
        
        Args:
            base_rate: Base rate parameter
            burstiness: Burstiness factor (0.7 = very bursty, 1.5 = less bursty)
            
        Returns:
            Inter-arrival time in seconds
        """
        # Weibull with shape < 1 creates heavy tail (bursty)
        return weibull_min.rvs(burstiness, scale=base_rate)
    
    @staticmethod
    def add_realistic_jitter(base_time: float, jitter_factor: float = 0.1) -> float:
        """
        Add realistic timing jitter.
        
        Args:
            base_time: Base time value
            jitter_factor: Proportion of jitter (0.1 = ±10%)
            
        Returns:
            Time with jitter added
        """
        jitter = np.random.uniform(-jitter_factor, jitter_factor) * base_time
        return max(0.001, base_time + jitter)  # Ensure positive


# =============================================================================
# 5. ENHANCED PREFIX BEHAVIOR
# =============================================================================

class EnhancedPrefixBehavior:
    """
    More realistic prefix behavior modeling with correlated properties.
    """
    
    def __init__(self):
        # Use beta distribution: most prefixes are stable
        self.stability_score = random.betavariate(8, 2)  # Peaks near 1.0
        
        # Flap tendency: few prefixes flap
        self.flap_tendency = random.betavariate(2, 8)  # Peaks near 0.0
        
        # Update frequency (updates per hour)
        self.update_frequency = random.expovariate(1/100)  # Mean = 100 updates/hour
        
        # Correlate behaviors: flappers update more
        if self.flap_tendency > 0.7:
            self.update_frequency *= 3.0
            self.stability_score *= 0.5
        
        # Track last update time
        self.last_update_time = 0.0
        
        # Withdrawal tendency
        self.withdrawal_tendency = self.flap_tendency * 0.5
    
    def should_update(self, current_time: float) -> bool:
        """
        Determine if prefix should generate an update.
        
        Args:
            current_time: Current simulation time
            
        Returns:
            True if update should occur
        """
        time_since_last = current_time - self.last_update_time
        
        # Probability increases with time, modulated by stability
        base_prob = 1.0 - np.exp(-time_since_last / (1 / self.update_frequency))
        adjusted_prob = base_prob * (1.0 - self.stability_score)
        
        if random.random() < adjusted_prob:
            self.last_update_time = current_time
            return True
        return False
    
    def should_flap(self) -> bool:
        """Determine if this update should be a flap event."""
        return random.random() < self.flap_tendency
    
    def should_withdraw(self) -> bool:
        """Determine if this update should be a withdrawal."""
        return random.random() < self.withdrawal_tendency


# =============================================================================
# 6. AS PATH ENHANCEMENTS
# =============================================================================

class ASPathEnhancer:
    """
    Enhancements for AS path generation and manipulation.
    """
    
    @staticmethod
    def should_prepend_path(reason: str = 'traffic_engineering') -> int:
        """
        Decide if and how much to prepend the AS path.
        
        Args:
            reason: Reason for prepending
            
        Returns:
            Number of times to prepend (0 = no prepending)
        """
        prepend_probabilities = {
            'traffic_engineering': 0.15,
            'backup_path': 0.08,
            'customer_request': 0.05,
            'load_balancing': 0.10
        }
        
        base_prob = prepend_probabilities.get(reason, 0.05)
        
        if random.random() < base_prob:
            # Prepend count follows geometric distribution
            # Most common: 1-2 prepends, rare: 5+ prepends
            prepend_count = min(np.random.geometric(0.5), 10)
            return prepend_count
        return 0
    
    @staticmethod
    def apply_prepending(as_path: str, prepend_count: int) -> str:
        """
        Apply AS path prepending.
        
        Args:
            as_path: Original AS path (space-separated AS numbers)
            prepend_count: Number of times to prepend origin AS
            
        Returns:
            Modified AS path with prepending
        """
        if prepend_count > 0 and as_path:
            path_list = as_path.split()
            if path_list:
                origin_as = path_list[-1]
                prepends = [origin_as] * prepend_count
                return ' '.join(path_list + prepends)
        return as_path
    
    @staticmethod
    def get_realistic_path_length(tier_distance: int) -> int:
        """
        Generate realistic AS path length based on tier distance.
        
        Args:
            tier_distance: Distance in tier hierarchy
            
        Returns:
            AS path length
        """
        # Base mean on tier distance
        if tier_distance == 1:
            mean_length = 3
        elif tier_distance == 2:
            mean_length = 4
        else:
            mean_length = 5
        
        # Add variation with truncated normal distribution
        length = int(np.clip(
            np.random.normal(mean_length, 1.5),
            2,   # Min path length
            15   # Max path length
        ))
        return length


# =============================================================================
# 7. CORRELATION-AWARE EVENT GENERATION
# =============================================================================

class CorrelatedEventGenerator:
    """
    Generates BGP events with realistic correlations between different event types.
    """
    
    def __init__(self):
        # Define correlation structure
        # When event X happens, probability of event Y increases
        self.event_correlations = {
            'withdrawal': {
                'flap': 0.3,
                'nadas': 0.2,
                'path_change': 0.15
            },
            'announcement': {
                'duplicate': 0.05,
                'edit_dist_1': 0.4,
                'edit_dist_2': 0.25
            },
            'flap': {
                'path_change': 0.5,
                'imp_wd': 0.3,
                'withdrawal': 0.4
            },
            'nadas': {
                'duplicate': 0.15,
                'announcement': 0.6
            }
        }
        
        # Track recent events for correlation
        self.recent_events = defaultdict(list)
        self.correlation_window = 10.0  # seconds
    
    def record_event(self, event_type: str, current_time: float):
        """Record that an event occurred."""
        self.recent_events[event_type].append(current_time)
        
        # Clean old events
        cutoff = current_time - self.correlation_window
        self.recent_events[event_type] = [
            t for t in self.recent_events[event_type] if t >= cutoff
        ]
    
    def get_correlated_event_probability(self, 
                                        event_type: str, 
                                        current_time: float) -> float:
        """
        Get increased probability of event based on recent correlated events.
        
        Args:
            event_type: Type of event to check
            current_time: Current simulation time
            
        Returns:
            Probability multiplier (1.0 = baseline, >1.0 = increased)
        """
        multiplier = 1.0
        
        # Check each event type that can trigger this one
        for trigger_event, correlations in self.event_correlations.items():
            if event_type in correlations:
                # Count recent occurrences of trigger event
                recent_count = len([
                    t for t in self.recent_events.get(trigger_event, [])
                    if current_time - t < self.correlation_window
                ])
                
                if recent_count > 0:
                    # Increase probability based on correlation strength
                    correlation_strength = correlations[event_type]
                    multiplier += correlation_strength * recent_count
        
        return min(multiplier, 3.0)  # Cap at 3x baseline


# =============================================================================
# 8. DUPLICATE GENERATION ENHANCEMENT
# =============================================================================

def generate_duplicates_correlated_with_announcements(num_announcements: int) -> int:
    """
    Generate number of duplicates correlated with announcement count.
    
    Real data shows ~0.3 correlation between announcements and duplicates.
    More announcements → more chances for duplicates, but with diminishing returns.
    
    Args:
        num_announcements: Number of announcements in window
        
    Returns:
        Number of duplicates to generate
    """
    # Base duplicate rate increases logarithmically with announcements
    expected_dup_rate = 0.05 + 0.02 * np.log1p(num_announcements)
    expected_dup_rate = min(expected_dup_rate, 0.15)  # Cap at 15%
    
    # Use binomial distribution for realistic variance
    num_duplicates = np.random.binomial(num_announcements, expected_dup_rate)
    
    return num_duplicates


# =============================================================================
# 9. FLAPPING WITH CORRELATIONS
# =============================================================================

def generate_flap_with_correlations(prefix: str,
                                   current_path: str,
                                   topology: Dict,
                                   nadas_prob: float = 0.4,
                                   path_change_prob: float = 0.3) -> List[Dict]:
    """
    Generate a flapping sequence with realistic correlations.
    
    Flapping should correlate with:
    - Withdrawals (by definition)
    - NADAS (new AS during re-announcement)
    - Path changes (during stabilization)
    - Implicit withdrawals
    
    Args:
        prefix: The flapping prefix
        current_path: Current AS path
        topology: Network topology
        nadas_prob: Probability of introducing new AS during flap
        path_change_prob: Probability of path change during stabilization
        
    Returns:
        List of event dictionaries
    """
    flap_sequence = []
    
    # 1. Initial withdrawal
    flap_sequence.append({
        'type': 'withdrawal',
        'prefix': prefix,
        'as_path': current_path
    })
    
    # 2. Re-announcement (possibly with new AS = NADAS)
    new_path = current_path
    if random.random() < nadas_prob:
        # Introduce new AS (NADAS)
        new_as = _select_new_as_for_path(current_path, topology)
        new_path = f"{current_path} {new_as}"
        
        flap_sequence.append({
            'type': 'announcement',
            'prefix': prefix,
            'as_path': new_path,
            'nadas': True
        })
    else:
        flap_sequence.append({
            'type': 'announcement',
            'prefix': prefix,
            'as_path': new_path,
            'nadas': False
        })
    
    # 3. Possible path changes during stabilization
    if random.random() < path_change_prob:
        # Create path variant
        varied_path = _vary_path_slightly(new_path)
        
        flap_sequence.append({
            'type': 'announcement',
            'prefix': prefix,
            'as_path': varied_path,
            'path_change': True
        })
    
    return flap_sequence


def _select_new_as_for_path(current_path: str, topology: Dict) -> int:
    """Select a new AS to add to path (for NADAS events)."""
    # Get ASes in current path
    path_ases = set(current_path.split()) if current_path else set()
    
    # Select from topology ASes not in path
    available_ases = [
        asn for asn in topology.keys()
        if str(asn) not in path_ases
    ]
    
    if available_ases:
        return random.choice(available_ases)
    else:
        # Fallback: random AS number
        return random.randint(64512, 65535)


def _vary_path_slightly(as_path: str) -> str:
    """Create a slight variation of AS path."""
    if not as_path:
        return as_path
    
    path_list = as_path.split()
    if len(path_list) < 2:
        return as_path
    
    # Random variation strategies
    strategy = random.choice(['prepend', 'remove_prepend', 'swap'])
    
    if strategy == 'prepend' and path_list:
        # Prepend origin AS
        path_list.append(path_list[-1])
    elif strategy == 'remove_prepend' and len(path_list) > 2:
        # Remove last AS if it's a prepend
        if path_list[-1] == path_list[-2]:
            path_list.pop()
    elif strategy == 'swap' and len(path_list) > 2:
        # Swap two adjacent ASes (simulate path change)
        idx = random.randint(0, len(path_list) - 2)
        path_list[idx], path_list[idx + 1] = path_list[idx + 1], path_list[idx]
    
    return ' '.join(path_list)


# =============================================================================
# 10. PREFIX CLUSTERING
# =============================================================================

def generate_clustered_prefixes(origin_as: int, 
                               num_prefixes: int,
                               clustering_factor: float = 0.8) -> List[str]:
    """
    Generate prefixes that are clustered by origin AS.
    Same AS should announce adjacent IP blocks.
    
    Args:
        origin_as: Origin AS number
        num_prefixes: Number of prefixes to generate
        clustering_factor: How tightly clustered (0.0-1.0)
        
    Returns:
        List of prefix strings
    """
    prefixes = []
    
    # Determine number of base /16 blocks
    num_clusters = max(1, int(num_prefixes * (1.0 - clustering_factor)))
    
    for cluster_idx in range(num_clusters):
        # Random /16 base
        base_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}"
        
        # How many prefixes in this cluster?
        prefixes_in_cluster = num_prefixes // num_clusters
        if cluster_idx < (num_prefixes % num_clusters):
            prefixes_in_cluster += 1
        
        # Generate adjacent /24s within this /16
        for i in range(prefixes_in_cluster):
            third_octet = i % 256
            prefix = f"{base_ip}.{third_octet}.0/24"
            prefixes.append(prefix)
    
    random.shuffle(prefixes)
    return prefixes[:num_prefixes]


# =============================================================================
# USAGE EXAMPLE
# =============================================================================

if __name__ == "__main__":
    # Example usage
    print("BGP Traffic Generation Enhancements v7")
    print("=" * 50)
    
    # Example topology
    example_topology = {
        1299: {'tier': 1, 'neighbors': []},
        6939: {'tier': 2, 'neighbors': []},
        41336: {'tier': 3, 'neighbors': []},
        35060: {'tier': 3, 'neighbors': []},
    }
    
    # 1. Rare AS management
    print("\n1. Rare AS Generation:")
    rare_mgr = RareASManager(example_topology)
    current_time = time.time()
    for i in range(5):
        rare_as = rare_mgr.generate_rare_as(current_time + i * 10)
        print(f"   t={i*10}s: AS {rare_as}")
    
    # 2. Edit distance
    print("\n2. Edit Distance Sampling:")
    for i in range(5):
        ed = sample_edit_distance_realistic()
        print(f"   Sample {i+1}: ED = {ed}")
    
    # 3. Withdrawal cascade
    print("\n3. Withdrawal Cascade:")
    cascade_gen = WithdrawalCascadeGenerator(example_topology)
    # Note: would need actual prefix_states in real usage
    
    # 4. Temporal patterns
    print("\n4. Time-of-Day Multipliers:")
    for hour in [0, 6, 12, 18]:
        mult = TemporalPatternManager.get_activity_multiplier(hour)
        print(f"   Hour {hour:02d}:00 UTC: {mult:.2f}x activity")
    
    # 5. Prefix behavior
    print("\n5. Prefix Behavior Profiles:")
    for i in range(3):
        behavior = EnhancedPrefixBehavior()
        print(f"   Prefix {i+1}: stability={behavior.stability_score:.2f}, "
              f"flap_tendency={behavior.flap_tendency:.2f}")
    
    print("\n" + "=" * 50)
    print("✅ All enhancements loaded successfully!")
    print("\nIntegrate these functions into your v6 traffic generator.")

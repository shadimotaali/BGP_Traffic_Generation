# =============================================================================
# CORRELATION FIXES V5 - BGP Traffic Generation
# =============================================================================
#
# This module contains the fixed functions to address correlation gaps between
# synthetic and real BGP traffic data.
#
# KEY FIXES:
# 1. Decouple withdrawals from flaps (0.995 → 0.42 target)
# 2. Add more "single/new" announcements (reduce imp_wd over-correlation)
# 3. Correlate duplicates with imp_wd_spath (0.07 → 0.58 target)
# 4. Fix edit distance distributions (add clustering)
# 5. Add standalone withdrawals without flaps
#
# =============================================================================

from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
import random
import numpy as np

# =============================================================================
# UPDATED TARGET CORRELATIONS FROM REAL DATA
# =============================================================================

REAL_CORRELATIONS_V5 = {
    ('withdrawals', 'flaps'): 0.424,           # Was 0.995, need to REDUCE
    ('withdrawals', 'nadas'): 0.654,
    ('imp_wd_dpath', 'unique_as_path_max'): 0.319,  # Was 0.876, need to REDUCE
    ('announcements', 'imp_wd'): 0.371,        # Was 0.906, need to REDUCE
    ('dups', 'imp_wd_spath'): 0.582,           # Was 0.067, need to INCREASE
    ('edit_distance_dict_3', 'edit_distance_dict_4'): 0.463,  # Was -0.026, need to INCREASE
    ('edit_distance_max', 'edit_distance_dict_3'): 0.356,
    ('imp_wd_dpath', 'edit_distance_dict_3'): 0.455,
    ('imp_wd', 'edit_distance_dict_3'): 0.400,
    ('dups', 'flaps'): 0.441,
    ('unique_as_path_max', 'edit_distance_avg'): 0.326,
    ('withdrawals', 'dups'): 0.361,
    ('withdrawals', 'imp_wd'): 0.328,
    ('dups', 'nadas'): 0.320,
    ('imp_wd', 'flaps'): 0.302,
    ('dups', 'edit_distance_dict_2'): 0.312,
}


# =============================================================================
# FIX 1 & 2: UPDATED PREFIX BEHAVIOR PROFILE
# =============================================================================

@dataclass
class PrefixBehaviorProfileV5:
    """
    V5: Updated prefix behavior profile with fixes for correlation gaps.

    KEY CHANGES:
    - Added 'single' activity level (40% of prefixes) - reduces announcements↔imp_wd
    - Added 'permanent_withdrawal' flag - reduces withdrawals↔flaps correlation
    - Added 'duplicate_with_imp_wd_spath' flag - creates dups↔imp_wd_spath correlation
    - Added edit_distance_cluster - creates ED clustering
    """
    # Activity level - NOW includes 'single' for first-time announcements
    activity_level: str = 'normal'  # 'single', 'low', 'normal', 'high', 'unstable'

    # Stability characteristics
    is_flapping: bool = False
    flap_intensity: int = 0  # 0-5 flap cycles

    # FIX 1: Withdrawal behavior - NOW separate from flapping
    has_explicit_withdrawals: bool = False
    withdrawal_count: int = 0
    is_permanent_withdrawal: bool = False  # NEW: Withdrawal without re-announcement

    # Path diversity
    target_nadas: int = 4
    path_variation: str = 'stable'

    # Implicit withdrawal patterns
    imp_wd_probability: float = 0.2
    imp_wd_spath_probability: float = 0.15
    imp_wd_dpath_probability: float = 0.15

    # FIX 3: Duplicate correlation with imp_wd_spath
    duplicate_with_imp_wd_spath: bool = False  # NEW: Generate dups when path shortens
    duplicate_count_on_spath: int = 0  # NEW: How many dups to generate

    # FIX 4: Edit distance clustering
    edit_distance_cluster: str = 'small'  # 'small' (0-2), 'medium' (2-3), 'large' (3-6)

    # Announcement count
    target_announcements: int = 3


def sample_prefix_behavior_profile_v5() -> PrefixBehaviorProfileV5:
    """
    V5: Sample prefix behavior with FIXED correlations.

    KEY CHANGES FROM V4:
    1. 40% of prefixes are 'single' (just ONE announcement, no imp_wd possible)
    2. Withdrawals can be permanent (no subsequent announcement = not a flap)
    3. When imp_wd_spath happens, generate correlated duplicates
    4. Edit distances are sampled from clusters (3 and 4 co-occur)
    """
    profile = PrefixBehaviorProfileV5()

    stability_roll = random.random()

    # ==========================================================================
    # FIX 2: Add 'single' category - 40% of prefixes have just ONE announcement
    # This dramatically reduces the announcements↔imp_wd correlation from 0.91→0.37
    # ==========================================================================
    if stability_roll < 0.40:
        # === SINGLE/NEW PREFIX (40%) ===
        # These are first-time announcements with NO follow-up
        # CANNOT have implicit withdrawals (only 1 announcement)
        profile.activity_level = 'single'
        profile.target_announcements = 1  # Just ONE announcement
        profile.is_flapping = False
        profile.flap_intensity = 0
        profile.has_explicit_withdrawals = False
        profile.is_permanent_withdrawal = False
        profile.withdrawal_count = 0
        profile.imp_wd_probability = 0.0  # CANNOT have imp_wd with 1 announcement
        profile.imp_wd_spath_probability = 0.0
        profile.imp_wd_dpath_probability = 0.0
        profile.target_nadas = random.randint(2, 4)
        profile.path_variation = 'stable'
        profile.duplicate_with_imp_wd_spath = False
        profile.edit_distance_cluster = 'none'  # No ED possible

    elif stability_roll < 0.50:
        # === UNSTABLE PREFIX (10%) - reduced from 15% ===
        profile.activity_level = 'unstable'
        profile.is_flapping = True
        profile.flap_intensity = random.randint(2, 5)

        # FIX 1: Not ALL withdrawals come from flapping
        # Some are permanent (route goes down)
        profile.has_explicit_withdrawals = True
        extra_withdrawals = random.randint(0, 2)  # Withdrawals NOT from flaps
        profile.withdrawal_count = profile.flap_intensity + extra_withdrawals
        profile.is_permanent_withdrawal = random.random() < 0.2  # 20% permanent

        profile.target_nadas = random.randint(8, 15)
        profile.path_variation = 'high'
        profile.imp_wd_probability = 0.5
        profile.imp_wd_spath_probability = 0.35
        profile.imp_wd_dpath_probability = 0.4
        profile.target_announcements = random.randint(6, 12)

        # FIX 3: Unstable prefixes generate dups with path shortening
        profile.duplicate_with_imp_wd_spath = True
        profile.duplicate_count_on_spath = random.randint(1, 3)

        # FIX 4: Unstable prefixes have LARGE edit distance cluster
        profile.edit_distance_cluster = random.choices(
            ['medium', 'large'], weights=[0.3, 0.7]
        )[0]

    elif stability_roll < 0.65:
        # === MODERATELY UNSTABLE (15%) ===
        profile.activity_level = 'high'
        profile.is_flapping = random.random() < 0.4  # Reduced flapping probability
        profile.flap_intensity = random.randint(1, 3) if profile.is_flapping else 0

        # FIX 1: Separate withdrawal generation from flapping
        profile.has_explicit_withdrawals = random.random() < 0.5
        if profile.has_explicit_withdrawals:
            # Can have withdrawals without flaps
            profile.withdrawal_count = random.randint(1, 3)
            profile.is_permanent_withdrawal = random.random() < 0.3
        else:
            profile.withdrawal_count = 0
            profile.is_permanent_withdrawal = False

        profile.target_nadas = random.randint(5, 10)
        profile.path_variation = 'moderate'
        profile.imp_wd_probability = 0.35
        profile.imp_wd_spath_probability = 0.2
        profile.imp_wd_dpath_probability = 0.25
        profile.target_announcements = random.randint(4, 8)

        # FIX 3: Sometimes generate dups with path shortening
        profile.duplicate_with_imp_wd_spath = random.random() < 0.5
        profile.duplicate_count_on_spath = random.randint(1, 2) if profile.duplicate_with_imp_wd_spath else 0

        # FIX 4: Medium edit distance cluster
        profile.edit_distance_cluster = random.choices(
            ['small', 'medium', 'large'], weights=[0.3, 0.5, 0.2]
        )[0]

    elif stability_roll < 0.85:
        # === NORMAL PREFIX (20%) ===
        profile.activity_level = 'normal'
        profile.is_flapping = random.random() < 0.1  # Reduced
        profile.flap_intensity = random.randint(1, 2) if profile.is_flapping else 0

        profile.has_explicit_withdrawals = random.random() < 0.2
        profile.withdrawal_count = random.randint(0, 1) if profile.has_explicit_withdrawals else 0
        profile.is_permanent_withdrawal = random.random() < 0.4 if profile.has_explicit_withdrawals else False

        profile.target_nadas = random.randint(3, 6)
        profile.path_variation = 'moderate' if random.random() < 0.3 else 'stable'
        profile.imp_wd_probability = 0.2
        profile.imp_wd_spath_probability = 0.12
        profile.imp_wd_dpath_probability = 0.15
        profile.target_announcements = random.randint(2, 4)

        # FIX 3: Sometimes generate dups with path shortening
        profile.duplicate_with_imp_wd_spath = random.random() < 0.3
        profile.duplicate_count_on_spath = random.randint(0, 1)

        # FIX 4: Small edit distance cluster
        profile.edit_distance_cluster = random.choices(
            ['small', 'medium'], weights=[0.7, 0.3]
        )[0]

    else:
        # === STABLE PREFIX (15%) ===
        profile.activity_level = 'low'
        profile.is_flapping = False
        profile.flap_intensity = 0
        profile.has_explicit_withdrawals = random.random() < 0.05
        profile.withdrawal_count = 0
        profile.is_permanent_withdrawal = profile.has_explicit_withdrawals  # If withdrawing, it's permanent
        profile.target_nadas = random.randint(2, 4)
        profile.path_variation = 'stable'
        profile.imp_wd_probability = 0.05
        profile.imp_wd_spath_probability = 0.02
        profile.imp_wd_dpath_probability = 0.03
        profile.target_announcements = random.randint(1, 2)
        profile.duplicate_with_imp_wd_spath = False
        profile.edit_distance_cluster = 'small'

    return profile


# =============================================================================
# FIX 4: EDIT DISTANCE CLUSTER SAMPLING
# =============================================================================

def sample_edit_distance_from_cluster(cluster: str) -> int:
    """
    Sample edit distance from a cluster distribution.

    This creates the correlations between edit_distance_dict_3 and edit_distance_dict_4
    because they tend to co-occur in 'large' clusters.
    """
    if cluster == 'none':
        return 0
    elif cluster == 'small':
        # ED 0, 1, 2 with higher probability of 1
        return random.choices([0, 1, 2], weights=[0.25, 0.50, 0.25])[0]
    elif cluster == 'medium':
        # ED 2, 3 - transitional
        return random.choices([1, 2, 3], weights=[0.2, 0.45, 0.35])[0]
    else:  # 'large'
        # ED 3, 4, 5, 6 - KEY: 3 and 4 co-occur!
        return random.choices([3, 4, 5, 6], weights=[0.35, 0.35, 0.20, 0.10])[0]


# =============================================================================
# ENHANCED PREFIX TRACKER V5
# =============================================================================

class PrefixASTrackerV5:
    """V5 tracker with enhanced profile support."""

    def __init__(self):
        self.prefix_ases: Dict[str, Set[int]] = defaultdict(set)
        self.prefix_announcements: Dict[str, int] = defaultdict(int)
        self.prefix_profiles: Dict[str, PrefixBehaviorProfileV5] = {}

    def get_or_create_profile(self, prefix: str) -> PrefixBehaviorProfileV5:
        if prefix not in self.prefix_profiles:
            self.prefix_profiles[prefix] = sample_prefix_behavior_profile_v5()
        return self.prefix_profiles[prefix]

    def record_announcement(self, prefix: str, as_path: List[int]):
        self.prefix_announcements[prefix] += 1
        for asn in as_path:
            self.prefix_ases[prefix].add(asn)

    def get_current_nadas(self, prefix: str) -> int:
        return len(self.prefix_ases.get(prefix, set()))

    def needs_more_diversity(self, prefix: str) -> bool:
        profile = self.prefix_profiles.get(prefix)
        if not profile:
            return False
        return self.get_current_nadas(prefix) < profile.target_nadas

    def get_previously_used(self, prefix: str) -> Set[int]:
        return self.prefix_ases.get(prefix, set())


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def calculate_levenshtein_distance(path1: List[int], path2: List[int]) -> int:
    """Calculate Levenshtein edit distance between two AS paths."""
    if path1 is None or path2 is None:
        return 0
    m, n = len(path1), len(path2)
    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if path1[i-1] == path2[j-1]:
                dp[i][j] = dp[i-1][j-1]
            else:
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])

    return dp[m][n]


def vary_as_path_v5(
        base_path: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        variation_type: str = 'substitute',
        target_ed: Optional[int] = None) -> Tuple[List[int], int, bool]:
    """
    V5: Vary AS path with optional target edit distance.

    Returns: (new_path, actual_edit_distance, is_shorter)
    """
    new_path = base_path.copy()

    if variation_type == 'shorten' and len(base_path) > 2:
        # Remove 1-2 ASes from middle
        removes = 1 if target_ed is None or target_ed <= 1 else min(2, len(new_path) - 2)
        for _ in range(removes):
            if len(new_path) > 2:
                remove_idx = random.randint(1, len(new_path) - 2)
                new_path.pop(remove_idx)
        ed = calculate_levenshtein_distance(base_path, new_path)
        return new_path, ed, True

    elif variation_type == 'lengthen':
        # Add 1-2 ASes
        adds = 1 if target_ed is None or target_ed <= 1 else min(2, target_ed)
        for _ in range(adds):
            new_as = random.choice(rare_as_pool[:1000])
            attempts = 0
            while new_as in new_path and attempts < 10:
                new_as = random.choice(rare_as_pool[:1000])
                attempts += 1
            if new_as not in new_path:
                insert_pos = random.randint(1, len(new_path) - 1)
                new_path.insert(insert_pos, new_as)
        ed = calculate_levenshtein_distance(base_path, new_path)
        return new_path, ed, False

    elif variation_type == 'substitute' and len(base_path) > 1:
        # Substitute 1-2 ASes based on target ED
        subs = 1 if target_ed is None or target_ed <= 1 else min(2, target_ed, len(new_path) - 1)
        for _ in range(subs):
            sub_idx = random.randint(1, len(new_path) - 1)
            new_as = random.choice(tier2_ases)
            attempts = 0
            while new_as in new_path and attempts < 10:
                new_as = random.choice(tier2_ases)
                attempts += 1
            if new_as not in new_path:
                new_path[sub_idx] = new_as
        ed = calculate_levenshtein_distance(base_path, new_path)
        return new_path, ed, False

    else:  # random
        action = random.choice(['substitute', 'shorten', 'lengthen'])
        return vary_as_path_v5(base_path, tier2_ases, rare_as_pool, action, target_ed)


# =============================================================================
# FIX 1: UPDATED FLAPPING SEQUENCE (Decoupled from withdrawals)
# =============================================================================

def generate_flapping_sequence_v5(
        prefix: str,
        peer_ip: str,
        base_path: List[int],
        state_tracker,
        prefix_tracker: PrefixASTrackerV5,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        flap_count: int) -> List[dict]:
    """
    V5: Generate flapping with DECOUPLED withdrawal correlation.

    KEY FIXES:
    1. Not every flap cycle creates a withdrawal (skip some)
    2. Some withdrawals happen without flaps (standalone)
    3. Variable timing breaks perfect correlation
    """
    events = []
    current_time = 0.0
    last_path = None
    profile = prefix_tracker.get_or_create_profile(prefix)

    # FIX 1: Only 60-80% of flap cycles actually create withdrawals
    # This reduces the 0.995 correlation to ~0.42
    withdrawal_probability_per_flap = random.uniform(0.5, 0.7)

    for i in range(flap_count):
        # === ANNOUNCEMENT ===
        if i == 0:
            announce_path = base_path.copy()
        else:
            if profile.path_variation == 'high':
                var_type = random.choice(['substitute', 'shorten', 'lengthen', 'substitute'])
            else:
                var_type = random.choice(['substitute', 'substitute', 'shorten'])

            # Use target ED from cluster
            target_ed = sample_edit_distance_from_cluster(profile.edit_distance_cluster)
            announce_path, _, _ = vary_as_path_v5(base_path, tier2_ases, rare_as_pool, var_type, target_ed)

        prefix_tracker.record_announcement(prefix, announce_path)
        event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, announce_path, current_time)

        is_shorter = last_path is not None and len(announce_path) < len(last_path)
        edit_dist = calculate_levenshtein_distance(last_path, announce_path) if last_path else 0

        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': announce_path.copy(),
            'event_type': event_type,
            'edit_distance': edit_dist,
            'is_flap': True,
            'is_imp_wd_spath': is_shorter,
            'flap_cycle': i
        })

        # FIX 3: If path shortened AND profile says to, generate duplicates
        if is_shorter and profile.duplicate_with_imp_wd_spath:
            for dup_idx in range(profile.duplicate_count_on_spath):
                events.append({
                    'time': current_time + 0.01 * (dup_idx + 1),
                    'action': 'announce',
                    'prefix': prefix,
                    'as_path': announce_path.copy(),
                    'event_type': 'duplicate',
                    'edit_distance': 0,
                    'is_duplicate': True,
                    'is_imp_wd_spath_dup': True  # Marks correlation
                })

        last_path = announce_path.copy()
        current_time += random.uniform(0.5, 5.0)

        # FIX 1: Only CREATE WITHDRAWAL with probability < 1
        # This breaks the perfect withdrawal↔flaps correlation
        if random.random() < withdrawal_probability_per_flap:
            state_tracker.withdraw_prefix(peer_ip, prefix, current_time)
            events.append({
                'time': current_time,
                'action': 'withdraw',
                'prefix': prefix,
                'as_path': None,
                'event_type': 'explicit_withdraw',
                'edit_distance': 0,
                'is_flap': True,
                'flap_cycle': i
            })
            current_time += random.uniform(2.0, 15.0)
        else:
            # Skip withdrawal - just pause longer
            current_time += random.uniform(5.0, 20.0)

    # === FINAL STABLE ANNOUNCEMENT ===
    final_path = base_path.copy()
    if random.random() < 0.3:
        final_path, _, _ = vary_as_path_v5(base_path, tier2_ases, rare_as_pool, 'substitute')

    prefix_tracker.record_announcement(prefix, final_path)
    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, final_path, current_time)

    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': final_path.copy(),
        'event_type': event_type,
        'edit_distance': calculate_levenshtein_distance(last_path, final_path),
        'is_flap': True,
        'is_final_stable': True
    })

    return events


# =============================================================================
# FIX 1: STANDALONE WITHDRAWAL GENERATOR (Not from flaps)
# =============================================================================

def generate_standalone_withdrawal_v5(
        prefix: str,
        peer_ip: str,
        as_path: List[int],
        state_tracker,
        prefix_tracker: PrefixASTrackerV5,
        is_permanent: bool = False) -> List[dict]:
    """
    V5: Generate withdrawals that are NOT from flapping.

    This creates withdrawals without associated flaps, breaking
    the over-correlation (0.995 → 0.42).
    """
    events = []
    current_time = 0.0

    # First announce
    prefix_tracker.record_announcement(prefix, as_path)
    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, as_path, current_time)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': as_path.copy(),
        'event_type': event_type,
        'edit_distance': 0
    })

    current_time += random.uniform(1.0, 10.0)

    # Withdraw
    state_tracker.withdraw_prefix(peer_ip, prefix, current_time)
    events.append({
        'time': current_time,
        'action': 'withdraw',
        'prefix': prefix,
        'as_path': None,
        'event_type': 'explicit_withdraw',
        'edit_distance': 0,
        'is_permanent': is_permanent,
        'is_flap': False  # KEY: Not a flap!
    })

    # If permanent, no re-announcement
    # If not permanent, delayed re-announcement (long delay = not counted as flap)
    if not is_permanent:
        # Long delay breaks flap detection (typically > 30s)
        delay = random.uniform(30.0, 120.0)
        current_time += delay

        event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, as_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': as_path.copy(),
            'event_type': event_type,
            'edit_distance': 0,
            'is_delayed_recovery': True,
            'is_flap': False
        })

    return events


# =============================================================================
# FIX 3: PATH SHORTENING WITH CORRELATED DUPLICATES
# =============================================================================

def generate_path_shortening_with_duplicates_v5(
        prefix: str,
        peer_ip: str,
        base_path: List[int],
        state_tracker,
        prefix_tracker: PrefixASTrackerV5,
        tier2_ases: List[int],
        rare_as_pool: List[int]) -> List[dict]:
    """
    V5: Generate imp_wd_spath events WITH correlated duplicates.

    This creates the dups↔imp_wd_spath correlation (0.07 → 0.58).
    """
    events = []
    profile = prefix_tracker.get_or_create_profile(prefix)
    current_time = 0.0

    # Initial announcement with full path
    prefix_tracker.record_announcement(prefix, base_path)
    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, base_path, current_time)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': base_path.copy(),
        'event_type': event_type,
        'edit_distance': 0
    })

    current_time += random.uniform(0.5, 3.0)

    # Generate shorter path (imp_wd_spath)
    shorter_path, ed, _ = vary_as_path_v5(base_path, tier2_ases, rare_as_pool, 'shorten')

    # Announcement with shorter path
    prefix_tracker.record_announcement(prefix, shorter_path)
    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, shorter_path, current_time)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': shorter_path.copy(),
        'event_type': 'implicit_wd_spath',
        'edit_distance': ed,
        'is_imp_wd_spath': True
    })

    # FIX 3: Generate correlated duplicates
    # When path shortens, BGP speakers often send duplicates
    num_duplicates = random.choices([1, 2, 3], weights=[0.4, 0.4, 0.2])[0]

    for dup_idx in range(num_duplicates):
        current_time += random.uniform(0.001, 0.1)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': shorter_path.copy(),
            'event_type': 'duplicate',
            'edit_distance': 0,
            'is_duplicate': True,
            'is_imp_wd_spath_dup': True,  # Marks the correlation
            'dup_index': dup_idx + 1
        })

    return events


# =============================================================================
# FIX 4: CONVERGENCE WITH CLUSTERED EDIT DISTANCES
# =============================================================================

def generate_convergence_sequence_v5(
        prefix: str,
        peer_ip: str,
        initial_path: List[int],
        state_tracker,
        prefix_tracker: PrefixASTrackerV5,
        tier2_ases: List[int],
        rare_as_pool: List[int],
        num_updates: int) -> List[dict]:
    """
    V5: Generate convergence with CLUSTERED edit distances.

    This creates correlations between edit_distance_dict_3 and edit_distance_dict_4
    by sampling from the same cluster.
    """
    events = []
    current_time = 0.0
    current_path = initial_path.copy()
    last_path = None
    profile = prefix_tracker.get_or_create_profile(prefix)

    for step in range(num_updates):
        if step == 0:
            announce_path = initial_path.copy()
            target_ed = 0
        else:
            progress = step / (num_updates - 1) if num_updates > 1 else 1

            # FIX 4: Sample ED from profile's cluster
            target_ed = sample_edit_distance_from_cluster(profile.edit_distance_cluster)

            # Choose variation type based on progress and target ED
            if progress < 0.4:
                var_type = random.choice(['substitute', 'lengthen', 'substitute'])
            elif progress < 0.7:
                var_type = random.choice(['substitute', 'shorten', 'substitute'])
            else:
                var_type = 'substitute' if random.random() < 0.7 else 'shorten'

            announce_path, _, _ = vary_as_path_v5(
                current_path, tier2_ases, rare_as_pool, var_type, target_ed
            )

        prefix_tracker.record_announcement(prefix, announce_path)
        event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, announce_path, current_time)

        is_shorter = last_path is not None and len(announce_path) < len(last_path)
        edit_dist = calculate_levenshtein_distance(last_path, announce_path) if last_path else 0

        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': announce_path.copy(),
            'event_type': event_type,
            'edit_distance': edit_dist,
            'is_convergence': True,
            'convergence_step': step,
            'is_imp_wd_spath': is_shorter,
            'ed_cluster': profile.edit_distance_cluster
        })

        # FIX 3: If path shortened, maybe add duplicates
        if is_shorter and profile.duplicate_with_imp_wd_spath:
            for dup_idx in range(profile.duplicate_count_on_spath):
                events.append({
                    'time': current_time + 0.01 * (dup_idx + 1),
                    'action': 'announce',
                    'prefix': prefix,
                    'as_path': announce_path.copy(),
                    'event_type': 'duplicate',
                    'edit_distance': 0,
                    'is_duplicate': True,
                    'is_imp_wd_spath_dup': True
                })

        last_path = announce_path.copy()
        current_path = announce_path.copy()

        base_delay = 0.5 * (1.5 ** step)
        current_time += random.uniform(base_delay * 0.5, base_delay * 2.0)

    return events


# =============================================================================
# AS PATH GENERATION V5
# =============================================================================

def generate_as_path_for_profile_v5(
        origin_as: int,
        prefix: str,
        tracker: PrefixASTrackerV5,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        force_new_ases: bool = False) -> List[int]:
    """V5: Generate AS path respecting prefix profile."""
    path = [origin_as]
    profile = tracker.get_or_create_profile(prefix)
    previously_used = tracker.get_previously_used(prefix)
    needs_diversity = tracker.needs_more_diversity(prefix)

    # Path length based on profile
    if profile.activity_level == 'unstable':
        path_length = random.choices([4, 5, 6, 7], weights=[0.15, 0.30, 0.35, 0.20])[0]
    elif profile.activity_level == 'high':
        path_length = random.choices([4, 5, 6], weights=[0.25, 0.45, 0.30])[0]
    elif profile.activity_level == 'normal':
        path_length = random.choices([3, 4, 5], weights=[0.35, 0.45, 0.20])[0]
    elif profile.activity_level == 'single':
        path_length = random.choices([2, 3, 4], weights=[0.45, 0.40, 0.15])[0]
    else:  # low
        path_length = random.choices([2, 3, 4], weights=[0.40, 0.45, 0.15])[0]

    # Build path
    for hop in range(path_length - 1):
        position_ratio = hop / (path_length - 1) if path_length > 1 else 0

        # Decide new vs reuse based on diversity needs
        use_new = force_new_ases or (needs_diversity and random.random() < 0.6)

        if position_ratio < 0.3:  # Near origin
            if use_new and rare_as_pool:
                next_as = random.choice(rare_as_pool[:2000])
            else:
                candidates = [a for a in tier2_ases if a not in path]
                next_as = random.choice(candidates) if candidates else random.choice(tier2_ases)
        elif position_ratio < 0.7:  # Middle
            if use_new and rare_as_pool:
                next_as = random.choice(rare_as_pool[:1500])
            else:
                candidates = [a for a in tier2_ases if a not in path]
                next_as = random.choice(candidates) if candidates else random.choice(tier2_ases)
        else:  # Near collector
            if random.random() < 0.4:
                next_as = random.choice(tier1_ases)
            else:
                next_as = random.choice(tier2_ases[:50])

        if next_as not in path:
            path.append(next_as)

    return path


# =============================================================================
# MASTER TRAFFIC GENERATOR V5
# =============================================================================

def generate_enhanced_normal_traffic_v5(
        topology,
        ip_allocations,
        state_tracker,
        peer_ip: str,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        predefined_prefixes: List[str],
        target_events: int = 20) -> List[dict]:
    """
    V5: Generate traffic with ALL correlation fixes.

    KEY CHANGES FROM V4:
    1. 40% 'single' prefixes (reduces announcements↔imp_wd from 0.91→0.37)
    2. Flapping decoupled from withdrawals (reduces w↔flaps from 0.995→0.42)
    3. Standalone withdrawals (not from flaps)
    4. Duplicates correlated with imp_wd_spath (increases from 0.07→0.58)
    5. Edit distance clustering (creates ED 3↔4 correlation)
    """
    all_events = []
    prefix_tracker = PrefixASTrackerV5()

    for _ in range(target_events):
        prefix = random.choice(predefined_prefixes)

        # Get or create behavior profile for this prefix
        profile = prefix_tracker.get_or_create_profile(prefix)

        # Origin AS based on profile
        if profile.activity_level == 'unstable':
            origin_as = random.choice(rare_as_pool[:1500])
        elif profile.activity_level == 'high':
            origin_as = random.choice(rare_as_pool[:3000] if random.random() < 0.6 else tier2_ases)
        elif profile.activity_level == 'normal':
            origin_as = random.choice(tier2_ases if random.random() < 0.7 else rare_as_pool[:2000])
        elif profile.activity_level == 'single':
            origin_as = random.choice(tier2_ases if random.random() < 0.8 else tier1_ases)
        else:
            origin_as = random.choice(tier2_ases if random.random() < 0.8 else tier1_ases)

        # =================================================================
        # FIX 2: SINGLE ANNOUNCEMENTS (40% of traffic)
        # =================================================================
        if profile.activity_level == 'single':
            # Just ONE announcement - no implicit withdrawal possible
            as_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )
            prefix_tracker.record_announcement(prefix, as_path)
            event_type, edit_dist = state_tracker.announce_prefix(
                peer_ip, prefix, as_path, 0.0
            )
            all_events.append({
                'time': 0.0,
                'action': 'announce',
                'prefix': prefix,
                'as_path': as_path,
                'event_type': 'new',  # Always 'new' for single announcements
                'edit_distance': 0,
                'is_single': True
            })
            continue

        # =================================================================
        # FLAPPING (with FIX 1: decoupled withdrawals)
        # =================================================================
        if profile.is_flapping and profile.flap_intensity > 0:
            base_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool,
                force_new_ases=True
            )

            flap_events = generate_flapping_sequence_v5(
                prefix, peer_ip, base_path, state_tracker,
                prefix_tracker, tier1_ases, tier2_ases, rare_as_pool,
                flap_count=profile.flap_intensity
            )
            all_events.extend(flap_events)
            profile.flap_intensity = max(0, profile.flap_intensity - random.randint(1, 2))

        # =================================================================
        # FIX 1: STANDALONE WITHDRAWALS (not from flapping)
        # =================================================================
        elif profile.has_explicit_withdrawals and profile.withdrawal_count > 0:
            as_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )

            # Generate standalone withdrawal
            withdrawal_events = generate_standalone_withdrawal_v5(
                prefix, peer_ip, as_path, state_tracker,
                prefix_tracker, profile.is_permanent_withdrawal
            )
            all_events.extend(withdrawal_events)
            profile.withdrawal_count -= 1

        # =================================================================
        # FIX 3: PATH SHORTENING WITH DUPLICATES
        # =================================================================
        elif (profile.duplicate_with_imp_wd_spath and
              profile.imp_wd_spath_probability > 0 and
              random.random() < profile.imp_wd_spath_probability):
            base_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )

            if len(base_path) > 2:
                path_short_events = generate_path_shortening_with_duplicates_v5(
                    prefix, peer_ip, base_path, state_tracker,
                    prefix_tracker, tier2_ases, rare_as_pool
                )
                all_events.extend(path_short_events)
            else:
                # Fallback to simple announcement
                prefix_tracker.record_announcement(prefix, base_path)
                event_type, ed = state_tracker.announce_prefix(peer_ip, prefix, base_path, 0.0)
                all_events.append({
                    'time': 0.0,
                    'action': 'announce',
                    'prefix': prefix,
                    'as_path': base_path,
                    'event_type': event_type,
                    'edit_distance': ed
                })

        # =================================================================
        # CONVERGENCE (with FIX 4: clustered edit distances)
        # =================================================================
        elif random.random() < 0.15:
            initial_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )

            num_updates = random.randint(2, 5) if profile.activity_level in ['high', 'unstable'] else random.randint(2, 3)

            conv_events = generate_convergence_sequence_v5(
                prefix, peer_ip, initial_path, state_tracker,
                prefix_tracker, tier2_ases, rare_as_pool,
                num_updates=num_updates
            )
            all_events.extend(conv_events)

        # =================================================================
        # SIMPLE ANNOUNCEMENTS
        # =================================================================
        else:
            as_path = generate_as_path_for_profile_v5(
                origin_as, prefix, prefix_tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )

            event_type, edit_dist = state_tracker.announce_prefix(
                peer_ip, prefix, as_path, 0.0
            )
            all_events.append({
                'time': 0.0,
                'action': 'announce',
                'prefix': prefix,
                'as_path': as_path,
                'event_type': event_type,
                'edit_distance': edit_dist
            })

            # Extra announcements based on profile
            extra_count = random.randint(0, max(0, profile.target_announcements - 1))
            last_path = as_path

            for _ in range(extra_count):
                roll = random.random()

                if roll < profile.imp_wd_spath_probability and len(last_path) > 2:
                    # Path shortening
                    target_ed = sample_edit_distance_from_cluster(profile.edit_distance_cluster)
                    new_path, ed, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'shorten', target_ed)

                    prefix_tracker.record_announcement(prefix, new_path)
                    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, new_path, 0.0)

                    all_events.append({
                        'time': 0.0,
                        'action': 'announce',
                        'prefix': prefix,
                        'as_path': new_path,
                        'event_type': event_type,
                        'edit_distance': ed,
                        'is_imp_wd_spath': True
                    })

                    # FIX 3: Add correlated duplicates
                    if profile.duplicate_with_imp_wd_spath:
                        for dup_idx in range(profile.duplicate_count_on_spath):
                            all_events.append({
                                'time': 0.0 + 0.01 * (dup_idx + 1),
                                'action': 'announce',
                                'prefix': prefix,
                                'as_path': new_path.copy(),
                                'event_type': 'duplicate',
                                'edit_distance': 0,
                                'is_duplicate': True,
                                'is_imp_wd_spath_dup': True
                            })

                    last_path = new_path

                elif roll < profile.imp_wd_spath_probability + profile.imp_wd_dpath_probability:
                    # Different path length
                    target_ed = sample_edit_distance_from_cluster(profile.edit_distance_cluster)
                    new_path, ed, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'substitute', target_ed)
                    prefix_tracker.record_announcement(prefix, new_path)
                    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, new_path, 0.0)

                    all_events.append({
                        'time': 0.0,
                        'action': 'announce',
                        'prefix': prefix,
                        'as_path': new_path,
                        'event_type': event_type,
                        'edit_distance': ed,
                        'is_imp_wd_dpath': len(new_path) != len(last_path)
                    })
                    last_path = new_path

                elif roll < profile.imp_wd_probability:
                    # General implicit withdrawal
                    target_ed = sample_edit_distance_from_cluster(profile.edit_distance_cluster)
                    new_path, ed, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'random', target_ed)
                    prefix_tracker.record_announcement(prefix, new_path)
                    event_type, _ = state_tracker.announce_prefix(peer_ip, prefix, new_path, 0.0)

                    all_events.append({
                        'time': 0.0,
                        'action': 'announce',
                        'prefix': prefix,
                        'as_path': new_path,
                        'event_type': event_type,
                        'edit_distance': ed
                    })
                    last_path = new_path

                else:
                    # Duplicate announcement (same path)
                    all_events.append({
                        'time': 0.0,
                        'action': 'announce',
                        'prefix': prefix,
                        'as_path': last_path.copy(),
                        'event_type': 'duplicate',
                        'edit_distance': 0,
                        'is_duplicate': True
                    })

    return all_events


# =============================================================================
# SUMMARY
# =============================================================================

def print_v5_summary():
    """Print summary of V5 fixes."""
    print("=" * 70)
    print("CORRELATION FIXES V5 - SUMMARY")
    print("=" * 70)
    print()
    print("KEY FIXES IMPLEMENTED:")
    print()
    print("1. WITHDRAWALS ↔ FLAPS (0.995 → 0.42 target)")
    print("   - Not every flap cycle creates a withdrawal (60-70% probability)")
    print("   - Added standalone withdrawals (not from flapping)")
    print("   - Added permanent withdrawals (no re-announcement)")
    print()
    print("2. ANNOUNCEMENTS ↔ IMP_WD (0.91 → 0.37 target)")
    print("   - Added 'single' activity level (40% of prefixes)")
    print("   - Single prefixes have exactly 1 announcement (no imp_wd possible)")
    print()
    print("3. DUPS ↔ IMP_WD_SPATH (0.07 → 0.58 target)")
    print("   - When path shortens, generate 1-3 correlated duplicates")
    print("   - Added duplicate_with_imp_wd_spath flag to profiles")
    print()
    print("4. EDIT_DISTANCE_DICT CORRELATIONS")
    print("   - ED 3 and ED 4 now co-occur (sampled from same 'large' cluster)")
    print("   - Added edit_distance_cluster to profiles: 'small', 'medium', 'large'")
    print("   - Each cluster has specific ED distribution")
    print()
    print("TARGET CORRELATIONS:")
    for (f1, f2), corr in REAL_CORRELATIONS_V5.items():
        print(f"  {f1} ↔ {f2}: {corr:.3f}")
    print("=" * 70)


if __name__ == "__main__":
    print_v5_summary()

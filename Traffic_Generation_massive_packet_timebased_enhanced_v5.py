#!/usr/bin/env python3
"""
BGP Traffic Generator V5 - Correlation-Aware Implementation

This version fixes 13 HIGH PRIORITY correlation gaps identified between
synthetic and real BGP traffic data.

KEY FIXES:
1. withdrawals-nadas (0.67 real vs 0.06 synthetic):
   - Generate withdrawal → re-announcement with NEW AS diversity
   - NADAS counts distinct ASes after W→A sequences with different attributes

2. imp_wd_dpath-unique_as_path_max (0.32 real vs 0.89 synthetic):
   - Decouple path changes from path length changes
   - 70% of imp_wd_dpath should be SUBSTITUTIONS (same length)

3. withdrawals-flaps (0.42 real vs 0.99 synthetic):
   - Not every flap cycle creates explicit withdrawal
   - Use 50-60% probability for withdrawals within flaps

4. announcements-dups (0.33 real vs 0.85 synthetic):
   - Generate duplicates independently of path characteristics
   - Any prefix can have duplicates regardless of stability

5. withdrawals-imp_wd_spath (0.52 real vs 0.03 synthetic):
   - Co-locate path shortening events with withdrawal sequences
   - After withdrawals, often announce shorter paths

6. Edit distance correlations (absent in synthetic):
   - Generate edit distance events in BURSTS
   - ED 3 and ED 4 events cluster together
"""

import random
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional

# =============================================================================
# SECTION 1: AS POOLS
# =============================================================================

TIER1_ASES = [
    174, 209, 701, 1239, 1299, 2914, 3257, 3320, 3356, 3491,
    5511, 6453, 6461, 6762, 6830, 7018, 12956,
]

TIER2_ASES = [
    1273, 2497, 2516, 3549, 4134, 4323, 4637, 4766, 5400, 6939,
    7473, 7922, 8928, 9002, 9304, 13335, 15169, 16509, 20940, 32934,
]


def generate_rare_as_pool(size=5000):
    """Generate a pool of rare ASes from realistic ASN ranges."""
    rare_ases = set()
    rare_ases.update(random.sample(range(30000, 40000), min(800, size // 6)))
    rare_ases.update(random.sample(range(41000, 50000), min(800, size // 6)))
    rare_ases.update(random.sample(range(45000, 55000), min(800, size // 6)))
    rare_ases.update(random.sample(range(25000, 30000), min(800, size // 6)))
    rare_ases.update(random.sample(range(10000, 20000), min(800, size // 6)))
    rare_ases.update(random.sample(range(55000, 65000), min(800, size // 6)))
    rare_ases -= set(TIER1_ASES)
    rare_ases -= set(TIER2_ASES)
    return list(rare_ases)


RARE_AS_POOL = generate_rare_as_pool(5000)

# =============================================================================
# SECTION 2: TARGET CORRELATIONS FROM REAL DATA
# =============================================================================

REAL_CORRELATIONS = {
    ('withdrawals', 'nadas'): 0.671,
    ('imp_wd_dpath', 'unique_as_path_max'): 0.319,
    ('withdrawals', 'flaps'): 0.425,
    ('announcements', 'dups'): 0.335,
    ('withdrawals', 'imp_wd_spath'): 0.520,
    ('edit_distance_dict_3', 'edit_distance_dict_4'): 0.463,
    ('imp_wd_spath', 'flaps'): 0.488,
    ('withdrawals', 'imp_wd'): 0.329,
    ('imp_wd', 'flaps'): 0.302,
    ('nadas', 'flaps'): 0.352,
    ('edit_distance_max', 'edit_distance_dict_3'): 0.356,
    ('unique_as_path_max', 'edit_distance_avg'): 0.325,
    ('dups', 'nadas'): 0.322,
}


# =============================================================================
# SECTION 3: LEVENSHTEIN DISTANCE CALCULATOR
# =============================================================================

def calculate_edit_distance(path1: List[int], path2: List[int]) -> int:
    """Calculate Levenshtein edit distance between two AS paths."""
    if path1 is None or path2 is None:
        return 0
    m, n = len(path1), len(path2)
    if m == 0:
        return n
    if n == 0:
        return m

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


# =============================================================================
# SECTION 4: PREFIX BEHAVIOR PROFILES (V5 - FIXED)
# =============================================================================

@dataclass
class PrefixBehaviorProfileV5:
    """
    V5 Profile: Models joint behavior with FIXED correlation structure.

    KEY CHANGES FROM V4:
    - withdrawal_creates_nadas: True = withdrawal followed by announcement with NEW ASes
    - imp_wd_uses_substitution: True = path change without length change
    - flap_withdrawal_probability: NOT 100%! Only 50-60% of flaps create withdrawals
    - duplicate_independent: True = duplicates generated regardless of stability
    """
    # Activity level
    activity_level: str = 'normal'

    # Flapping with PARTIAL withdrawal correlation (FIX #3)
    is_flapping: bool = False
    flap_intensity: int = 0
    flap_withdrawal_probability: float = 0.55  # NOT 100%!

    # Withdrawal-NADAS correlation (FIX #1)
    has_explicit_withdrawals: bool = False
    withdrawal_count: int = 0
    withdrawal_creates_nadas: bool = True  # Re-announce with NEW ASes after W

    # Path diversity
    target_nadas: int = 4
    path_variation: str = 'stable'

    # imp_wd_dpath decoupled from path length (FIX #2)
    imp_wd_probability: float = 0.2
    imp_wd_spath_probability: float = 0.15
    imp_wd_dpath_probability: float = 0.15
    imp_wd_uses_substitution_ratio: float = 0.70  # 70% substitutions!

    # Withdrawal co-occurs with imp_wd_spath (FIX #5)
    imp_wd_spath_near_withdrawal: float = 0.45

    # Duplicates independent of stability (FIX #4)
    duplicate_probability: float = 0.15  # Any prefix can have duplicates

    # Edit distance clustering (FIX #6)
    edit_distance_burst_probability: float = 0.30

    target_announcements: int = 3


def sample_prefix_behavior_profile_v5() -> PrefixBehaviorProfileV5:
    """
    Sample V5 profile with FIXED correlation structure.

    KEY INSIGHT: Some correlations are JOINT (same underlying cause),
    others should be PARTIAL (moderate coupling).
    """
    profile = PrefixBehaviorProfileV5()
    stability_roll = random.random()

    if stability_roll < 0.15:
        # === UNSTABLE PREFIX (15%) ===
        profile.activity_level = 'unstable'
        profile.is_flapping = True
        profile.flap_intensity = random.randint(3, 6)
        profile.flap_withdrawal_probability = 0.55  # FIX: Not 100%!
        profile.has_explicit_withdrawals = True
        profile.withdrawal_count = random.randint(2, 5)  # Independent of flaps
        profile.withdrawal_creates_nadas = True
        profile.target_nadas = random.randint(10, 20)
        profile.path_variation = 'high'
        profile.imp_wd_probability = 0.6
        profile.imp_wd_spath_probability = 0.35
        profile.imp_wd_dpath_probability = 0.45
        profile.imp_wd_uses_substitution_ratio = 0.65  # Some length changes allowed
        profile.imp_wd_spath_near_withdrawal = 0.50
        profile.duplicate_probability = 0.20  # Higher but not deterministic
        profile.edit_distance_burst_probability = 0.45
        profile.target_announcements = random.randint(8, 15)

    elif stability_roll < 0.35:
        # === MODERATELY UNSTABLE (20%) ===
        profile.activity_level = 'high'
        profile.is_flapping = random.random() < 0.5
        profile.flap_intensity = random.randint(2, 4) if profile.is_flapping else 0
        profile.flap_withdrawal_probability = 0.50
        profile.has_explicit_withdrawals = random.random() < 0.5  # Independent!
        profile.withdrawal_count = random.randint(1, 3) if profile.has_explicit_withdrawals else 0
        profile.withdrawal_creates_nadas = random.random() < 0.70
        profile.target_nadas = random.randint(6, 12)
        profile.path_variation = 'moderate'
        profile.imp_wd_probability = 0.4
        profile.imp_wd_spath_probability = 0.25
        profile.imp_wd_dpath_probability = 0.30
        profile.imp_wd_uses_substitution_ratio = 0.70
        profile.imp_wd_spath_near_withdrawal = 0.40
        profile.duplicate_probability = 0.18
        profile.edit_distance_burst_probability = 0.35
        profile.target_announcements = random.randint(5, 10)

    elif stability_roll < 0.65:
        # === NORMAL PREFIX (30%) ===
        profile.activity_level = 'normal'
        profile.is_flapping = random.random() < 0.15
        profile.flap_intensity = random.randint(1, 2) if profile.is_flapping else 0
        profile.flap_withdrawal_probability = 0.45
        profile.has_explicit_withdrawals = random.random() < 0.25
        profile.withdrawal_count = random.randint(0, 1)
        profile.withdrawal_creates_nadas = random.random() < 0.55
        profile.target_nadas = random.randint(4, 8)
        profile.path_variation = 'moderate' if random.random() < 0.4 else 'stable'
        profile.imp_wd_probability = 0.25
        profile.imp_wd_spath_probability = 0.15
        profile.imp_wd_dpath_probability = 0.20
        profile.imp_wd_uses_substitution_ratio = 0.75
        profile.imp_wd_spath_near_withdrawal = 0.35
        profile.duplicate_probability = 0.12
        profile.edit_distance_burst_probability = 0.25
        profile.target_announcements = random.randint(2, 5)

    else:
        # === STABLE PREFIX (35%) ===
        profile.activity_level = 'low'
        profile.is_flapping = False
        profile.flap_intensity = 0
        profile.flap_withdrawal_probability = 0.40
        profile.has_explicit_withdrawals = random.random() < 0.10  # FIX: Some stable have W too
        profile.withdrawal_count = 1 if profile.has_explicit_withdrawals else 0
        profile.withdrawal_creates_nadas = random.random() < 0.40
        profile.target_nadas = random.randint(2, 5)
        profile.path_variation = 'stable'
        profile.imp_wd_probability = 0.1
        profile.imp_wd_spath_probability = 0.05
        profile.imp_wd_dpath_probability = 0.08
        profile.imp_wd_uses_substitution_ratio = 0.80
        profile.imp_wd_spath_near_withdrawal = 0.25
        profile.duplicate_probability = 0.08  # FIX: Stable can have duplicates too!
        profile.edit_distance_burst_probability = 0.15
        profile.target_announcements = random.randint(1, 3)

    return profile


# =============================================================================
# SECTION 5: PREFIX STATE TRACKER V5
# =============================================================================

class PrefixStateTrackerV5:
    """
    Enhanced tracker that properly tracks:
    - Explicit withdrawals and subsequent announcements (for NADAS)
    - Path changes with/without length changes (for imp_wd_spath vs imp_wd_dpath)
    - Edit distance events
    """

    def __init__(self):
        self.prefix_states: Dict[Tuple[str, str], dict] = {}
        self.prefix_ases: Dict[str, Set[int]] = defaultdict(set)
        self.prefix_profiles: Dict[str, PrefixBehaviorProfileV5] = {}
        self.stats = {
            'announcements': 0,
            'withdrawals': 0,
            'flaps': 0,
            'nadas': 0,  # W→A with different attributes
            'duplicates': 0,
            'imp_wd': 0,
            'imp_wd_spath': 0,
            'imp_wd_dpath': 0,
            'edit_distances': [],
        }

    def get_or_create_profile(self, prefix: str) -> PrefixBehaviorProfileV5:
        if prefix not in self.prefix_profiles:
            self.prefix_profiles[prefix] = sample_prefix_behavior_profile_v5()
        return self.prefix_profiles[prefix]

    def announce_prefix(self, peer_ip: str, prefix: str, as_path: List[int],
                       timestamp: float, after_withdrawal: bool = False) -> dict:
        """
        Process announcement with detailed event classification.

        Returns dict with event details for proper feature extraction.
        """
        key = (peer_ip, prefix)

        # Track ASes for this prefix
        for asn in as_path:
            self.prefix_ases[prefix].add(asn)

        result = {
            'event_type': 'new',
            'edit_distance': 0,
            'is_duplicate': False,
            'is_imp_wd': False,
            'is_imp_wd_spath': False,
            'is_imp_wd_dpath': False,
            'is_nadas': False,
            'is_flap': False,
        }

        self.stats['announcements'] += 1

        if key in self.prefix_states:
            old_state = self.prefix_states[key]
            old_path = old_state.get('path', [])
            was_withdrawn = old_state.get('withdrawn', False)

            # Calculate edit distance
            edit_dist = calculate_edit_distance(old_path, as_path)
            result['edit_distance'] = edit_dist
            self.stats['edit_distances'].append(edit_dist)

            # Check for NADAS (FIX #1)
            # NADAS = Withdrawal followed by Announcement with Different Attributes
            if was_withdrawn and after_withdrawal:
                if as_path != old_path:  # Different attributes
                    result['is_nadas'] = True
                    self.stats['nadas'] += 1
                    result['event_type'] = 'nadas'
                else:
                    # Same path after withdrawal = FLAP
                    result['is_flap'] = True
                    self.stats['flaps'] += 1
                    result['event_type'] = 'flap'

            # Check for duplicate
            elif as_path == old_path and not was_withdrawn:
                result['is_duplicate'] = True
                self.stats['duplicates'] += 1
                result['event_type'] = 'duplicate'

            # Check for implicit withdrawal
            elif as_path != old_path and not was_withdrawn:
                result['is_imp_wd'] = True
                self.stats['imp_wd'] += 1

                # Determine if same or different path length
                if len(as_path) < len(old_path):
                    result['is_imp_wd_spath'] = True
                    self.stats['imp_wd_spath'] += 1
                    result['event_type'] = 'imp_wd_spath'
                elif len(as_path) != len(old_path):
                    result['is_imp_wd_dpath'] = True
                    self.stats['imp_wd_dpath'] += 1
                    result['event_type'] = 'imp_wd_dpath'
                else:
                    # Same length, different path = imp_wd_dpath (substitution)
                    result['is_imp_wd_dpath'] = True
                    self.stats['imp_wd_dpath'] += 1
                    result['event_type'] = 'imp_wd_dpath_subst'

            # Update state
            old_state['path'] = as_path
            old_state['last_time'] = timestamp
            old_state['announce_count'] += 1
            old_state['withdrawn'] = False
            old_state['path_history'].append(as_path)
        else:
            # New prefix
            result['event_type'] = 'new'
            self.prefix_states[key] = {
                'path': as_path,
                'first_time': timestamp,
                'last_time': timestamp,
                'announce_count': 1,
                'withdraw_count': 0,
                'withdrawn': False,
                'path_history': [as_path],
            }

        return result

    def withdraw_prefix(self, peer_ip: str, prefix: str, timestamp: float) -> dict:
        """Process explicit withdrawal."""
        key = (peer_ip, prefix)
        result = {
            'event_type': 'withdrawal',
            'is_withdrawal': True,
        }

        self.stats['withdrawals'] += 1

        if key in self.prefix_states:
            state = self.prefix_states[key]
            state['withdraw_count'] += 1
            state['withdrawn'] = True
            state['withdrawn_time'] = timestamp

        return result

    def get_current_nadas(self, prefix: str) -> int:
        return len(self.prefix_ases.get(prefix, set()))

    def get_last_path(self, peer_ip: str, prefix: str) -> Optional[List[int]]:
        key = (peer_ip, prefix)
        state = self.prefix_states.get(key)
        if state:
            return state.get('path')
        return None

    def is_withdrawn(self, peer_ip: str, prefix: str) -> bool:
        key = (peer_ip, prefix)
        state = self.prefix_states.get(key)
        if state:
            return state.get('withdrawn', False)
        return False

    def print_stats(self):
        print("\n" + "=" * 60)
        print("PREFIX STATE TRACKER V5 STATISTICS")
        print("=" * 60)
        print(f"Total announcements:    {self.stats['announcements']}")
        print(f"Total withdrawals:      {self.stats['withdrawals']}")
        print(f"NADAS events:           {self.stats['nadas']}")
        print(f"Flaps:                  {self.stats['flaps']}")
        print(f"Duplicates:             {self.stats['duplicates']}")
        print(f"Implicit WD (total):    {self.stats['imp_wd']}")
        print(f"  - Same path len:      {self.stats['imp_wd_spath']}")
        print(f"  - Diff path len:      {self.stats['imp_wd_dpath']}")

        if self.stats['edit_distances']:
            eds = self.stats['edit_distances']
            print(f"Edit distance avg:      {np.mean(eds):.2f}")
            print(f"Edit distance max:      {max(eds)}")
            ed_counts = defaultdict(int)
            for ed in eds:
                ed_counts[ed] += 1
            print(f"Edit distance dist:     {dict(sorted(ed_counts.items()))}")
        print("=" * 60)


# =============================================================================
# SECTION 6: PATH GENERATION FUNCTIONS (V5 - FIXED)
# =============================================================================

def generate_as_path_v5(
        origin_as: int,
        prefix: str,
        tracker: PrefixStateTrackerV5,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        force_new_ases: bool = False,
        target_length: Optional[int] = None) -> List[int]:
    """
    Generate AS path with proper diversity control.

    FIX #1: When force_new_ases=True, use ASes NOT previously seen for this prefix.
    This is used after withdrawals to create NADAS correlation.
    """
    path = [origin_as]
    profile = tracker.get_or_create_profile(prefix)

    # Determine path length
    if target_length:
        path_length = target_length
    elif profile.activity_level == 'unstable':
        path_length = random.choices([4, 5, 6, 7], weights=[0.15, 0.30, 0.35, 0.20])[0]
    elif profile.activity_level == 'high':
        path_length = random.choices([4, 5, 6], weights=[0.25, 0.45, 0.30])[0]
    elif profile.activity_level == 'normal':
        path_length = random.choices([3, 4, 5], weights=[0.35, 0.45, 0.20])[0]
    else:
        path_length = random.choices([2, 3, 4], weights=[0.40, 0.45, 0.15])[0]

    # Get previously used ASes
    previously_used = tracker.prefix_ases.get(prefix, set())

    # Probability of using NEW AS
    if force_new_ases:
        new_as_prob = 0.85  # High prob of new AS to create NADAS correlation
    elif profile.path_variation == 'high':
        new_as_prob = 0.40
    elif profile.path_variation == 'moderate':
        new_as_prob = 0.30
    else:
        new_as_prob = 0.20

    for hop in range(path_length - 1):
        use_new = random.random() < new_as_prob

        if use_new or force_new_ases:
            # Select NEW AS (not previously seen for this prefix)
            if random.random() < 0.35:
                candidates = [a for a in rare_as_pool[:2000]
                            if a not in previously_used and a not in path]
            elif random.random() < 0.5:
                candidates = [a for a in tier2_ases
                            if a not in previously_used and a not in path]
            else:
                candidates = [a for a in tier1_ases
                            if a not in previously_used and a not in path]

            if candidates:
                next_as = random.choice(candidates)
            else:
                # Fallback to any unused AS in path
                all_ases = tier2_ases + tier1_ases + rare_as_pool[:500]
                candidates = [a for a in all_ases if a not in path]
                next_as = random.choice(candidates) if candidates else random.choice(tier2_ases)
        else:
            # Reuse existing AS
            reusable = [a for a in previously_used if a not in path and a != origin_as]
            if reusable:
                next_as = random.choice(reusable)
            else:
                next_as = random.choice(tier2_ases)
                while next_as in path:
                    next_as = random.choice(tier2_ases)

        path.append(next_as)

    return path


def vary_as_path_v5(
        base_path: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        variation_type: str = 'substitute',
        use_substitution_for_dpath: bool = True) -> Tuple[List[int], int, bool, str]:
    """
    Vary AS path with controlled edit distance.

    FIX #2: use_substitution_for_dpath controls whether imp_wd_dpath changes length.
    When True (70% of time), use substitution to keep same length.

    Returns: (new_path, edit_distance, is_shorter, actual_variation_type)
    """
    new_path = base_path.copy()

    if variation_type == 'substitute' or (variation_type == 'dpath' and use_substitution_for_dpath):
        # Substitution - keeps same path length (FIX #2)
        if len(new_path) > 1:
            sub_idx = random.randint(1, len(new_path) - 1)
            new_as = random.choice(tier2_ases + rare_as_pool[:500])
            attempts = 0
            while new_as in new_path and attempts < 10:
                new_as = random.choice(tier2_ases + rare_as_pool[:500])
                attempts += 1
            new_path[sub_idx] = new_as
        ed = calculate_edit_distance(base_path, new_path)
        return new_path, ed, False, 'substitute'

    elif variation_type == 'shorten' and len(base_path) > 2:
        # Remove 1 AS from middle
        remove_idx = random.randint(1, len(new_path) - 2)
        new_path.pop(remove_idx)
        ed = calculate_edit_distance(base_path, new_path)
        return new_path, ed, True, 'shorten'

    elif variation_type == 'lengthen':
        # Add 1 AS
        new_as = random.choice(rare_as_pool[:1000])
        while new_as in new_path:
            new_as = random.choice(rare_as_pool[:1000])
        insert_pos = random.randint(1, len(new_path) - 1)
        new_path.insert(insert_pos, new_as)
        ed = calculate_edit_distance(base_path, new_path)
        return new_path, ed, False, 'lengthen'

    elif variation_type == 'dpath' and not use_substitution_for_dpath:
        # Different path with length change (30% of dpath cases)
        action = random.choice(['lengthen', 'shorten'] if len(base_path) > 2 else ['lengthen'])
        return vary_as_path_v5(base_path, tier2_ases, rare_as_pool, action, False)

    else:
        # Random variation
        action = random.choice(['substitute', 'shorten', 'lengthen'])
        return vary_as_path_v5(base_path, tier2_ases, rare_as_pool, action, use_substitution_for_dpath)


def generate_path_with_target_edit_distance(
        base_path: List[int],
        target_ed: int,
        tier2_ases: List[int],
        rare_as_pool: List[int]) -> Tuple[List[int], int]:
    """
    Generate a path with approximately the target edit distance.
    Used for edit distance clustering (FIX #6).
    """
    if target_ed == 0:
        return base_path.copy(), 0

    new_path = base_path.copy()
    changes_made = 0

    for _ in range(target_ed):
        action = random.choice(['substitute', 'insert', 'delete'])

        if action == 'substitute' and len(new_path) > 1:
            idx = random.randint(1, len(new_path) - 1)
            new_as = random.choice(tier2_ases + rare_as_pool[:500])
            while new_as in new_path:
                new_as = random.choice(tier2_ases + rare_as_pool[:500])
            new_path[idx] = new_as
            changes_made += 1
        elif action == 'insert':
            new_as = random.choice(rare_as_pool[:1000])
            while new_as in new_path:
                new_as = random.choice(rare_as_pool[:1000])
            insert_pos = random.randint(1, len(new_path))
            new_path.insert(insert_pos, new_as)
            changes_made += 1
        elif action == 'delete' and len(new_path) > 2:
            del_idx = random.randint(1, len(new_path) - 1)
            new_path.pop(del_idx)
            changes_made += 1

    actual_ed = calculate_edit_distance(base_path, new_path)
    return new_path, actual_ed


# =============================================================================
# SECTION 7: EVENT GENERATORS (V5 - FIXED)
# =============================================================================

def generate_withdrawal_nadas_sequence(
        prefix: str,
        peer_ip: str,
        tracker: PrefixStateTrackerV5,
        origin_as: int,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int]) -> List[dict]:
    """
    FIX #1: Generate withdrawal → announcement with NEW AS diversity.
    This creates the withdrawals-nadas correlation (0.67).

    Key: After withdrawal, announce with DIFFERENT AS path containing NEW ASes.
    """
    events = []
    profile = tracker.get_or_create_profile(prefix)
    current_time = 0.0

    # First, ensure prefix is announced
    last_path = tracker.get_last_path(peer_ip, prefix)
    if last_path is None:
        # Initial announcement
        initial_path = generate_as_path_v5(
            origin_as, prefix, tracker,
            tier1_ases, tier2_ases, rare_as_pool
        )
        result = tracker.announce_prefix(peer_ip, prefix, initial_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': initial_path,
            **result
        })
        last_path = initial_path
        current_time += random.uniform(1.0, 5.0)

    # Withdrawal
    result = tracker.withdraw_prefix(peer_ip, prefix, current_time)
    events.append({
        'time': current_time,
        'action': 'withdraw',
        'prefix': prefix,
        'as_path': None,
        **result
    })
    current_time += random.uniform(2.0, 10.0)

    # Re-announce with NEW ASes (creates NADAS)
    if profile.withdrawal_creates_nadas:
        # Force new ASes in the path
        new_path = generate_as_path_v5(
            origin_as, prefix, tracker,
            tier1_ases, tier2_ases, rare_as_pool,
            force_new_ases=True  # KEY: This creates NADAS
        )
    else:
        # Same path (creates FLAP instead)
        new_path = last_path.copy()

    result = tracker.announce_prefix(peer_ip, prefix, new_path, current_time, after_withdrawal=True)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': new_path,
        **result
    })

    return events


def generate_flapping_sequence_v5(
        prefix: str,
        peer_ip: str,
        tracker: PrefixStateTrackerV5,
        origin_as: int,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        flap_count: int) -> List[dict]:
    """
    FIX #3: Flapping with PARTIAL withdrawal correlation.
    Not every flap cycle creates an explicit withdrawal!
    """
    events = []
    profile = tracker.get_or_create_profile(prefix)
    current_time = 0.0

    # Initial path
    base_path = generate_as_path_v5(
        origin_as, prefix, tracker,
        tier1_ases, tier2_ases, rare_as_pool,
        force_new_ases=True
    )
    last_path = base_path

    for i in range(flap_count):
        # Announce
        if i == 0:
            announce_path = base_path.copy()
        else:
            # Vary the path
            use_subst = random.random() < profile.imp_wd_uses_substitution_ratio
            announce_path, ed, is_shorter, _ = vary_as_path_v5(
                base_path, tier2_ases, rare_as_pool,
                'substitute' if use_subst else 'random',
                use_subst
            )

        is_after_wd = tracker.is_withdrawn(peer_ip, prefix)
        result = tracker.announce_prefix(peer_ip, prefix, announce_path, current_time,
                                         after_withdrawal=is_after_wd)

        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': announce_path,
            'flap_cycle': i,
            **result
        })

        last_path = announce_path
        current_time += random.uniform(0.5, 5.0)

        # FIX #3: Only some flap cycles create explicit withdrawal!
        if random.random() < profile.flap_withdrawal_probability:
            result = tracker.withdraw_prefix(peer_ip, prefix, current_time)
            events.append({
                'time': current_time,
                'action': 'withdraw',
                'prefix': prefix,
                'as_path': None,
                'flap_cycle': i,
                **result
            })
            current_time += random.uniform(2.0, 15.0)
        else:
            # Implicit recovery - no explicit withdrawal
            current_time += random.uniform(1.0, 8.0)

    # Final stable announcement
    final_path = base_path.copy()
    if random.random() < 0.3:
        final_path, _, _, _ = vary_as_path_v5(base_path, tier2_ases, rare_as_pool, 'substitute', True)

    is_after_wd = tracker.is_withdrawn(peer_ip, prefix)
    result = tracker.announce_prefix(peer_ip, prefix, final_path, current_time,
                                     after_withdrawal=is_after_wd)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': final_path,
        'is_final_stable': True,
        **result
    })

    return events


def generate_imp_wd_spath_near_withdrawal(
        prefix: str,
        peer_ip: str,
        tracker: PrefixStateTrackerV5,
        origin_as: int,
        tier2_ases: List[int],
        rare_as_pool: List[int]) -> List[dict]:
    """
    FIX #5: Generate imp_wd_spath events co-located with withdrawals.
    This creates the withdrawals-imp_wd_spath correlation (0.52).
    """
    events = []
    current_time = 0.0

    # Get or create initial path
    last_path = tracker.get_last_path(peer_ip, prefix)
    if last_path is None or len(last_path) < 3:
        # Need a longer path first
        last_path = generate_as_path_v5(
            origin_as, prefix, tracker,
            TIER1_ASES, tier2_ases, rare_as_pool,
            target_length=random.randint(4, 6)
        )
        result = tracker.announce_prefix(peer_ip, prefix, last_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': last_path,
            **result
        })
        current_time += random.uniform(1.0, 3.0)

    # Generate shorter path (imp_wd_spath)
    shorter_path, ed, _, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'shorten', False)
    result = tracker.announce_prefix(peer_ip, prefix, shorter_path, current_time)
    events.append({
        'time': current_time,
        'action': 'announce',
        'prefix': prefix,
        'as_path': shorter_path,
        **result
    })
    current_time += random.uniform(0.5, 2.0)

    # Now generate a withdrawal (co-located)
    result = tracker.withdraw_prefix(peer_ip, prefix, current_time)
    events.append({
        'time': current_time,
        'action': 'withdraw',
        'prefix': prefix,
        'as_path': None,
        **result
    })

    return events


def generate_edit_distance_burst(
        prefix: str,
        peer_ip: str,
        tracker: PrefixStateTrackerV5,
        origin_as: int,
        tier2_ases: List[int],
        rare_as_pool: List[int]) -> List[dict]:
    """
    FIX #6: Generate clustered edit distance events.
    ED 3 and ED 4 events tend to occur together.
    """
    events = []
    current_time = 0.0

    last_path = tracker.get_last_path(peer_ip, prefix)
    if last_path is None:
        last_path = generate_as_path_v5(
            origin_as, prefix, tracker,
            TIER1_ASES, tier2_ases, rare_as_pool
        )
        result = tracker.announce_prefix(peer_ip, prefix, last_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': last_path,
            **result
        })
        current_time += random.uniform(0.5, 2.0)

    # Generate burst of related edit distances
    # Target: ED 3-4 clustered together
    target_eds = []
    base_ed = random.choice([3, 4])
    target_eds.append(base_ed)

    # Add related edit distances
    for _ in range(random.randint(1, 3)):
        if random.random() < 0.6:
            # Stay close to base
            target_eds.append(base_ed + random.choice([-1, 0, 1]))
        else:
            # Slightly further
            target_eds.append(random.choice([2, 3, 4, 5]))

    for target_ed in target_eds:
        if target_ed < 1:
            target_ed = 1

        new_path, actual_ed = generate_path_with_target_edit_distance(
            last_path, target_ed, tier2_ases, rare_as_pool
        )

        result = tracker.announce_prefix(peer_ip, prefix, new_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': new_path,
            'target_ed': target_ed,
            'actual_ed': actual_ed,
            **result
        })

        last_path = new_path
        current_time += random.uniform(0.1, 1.0)

    return events


def generate_independent_duplicates(
        prefix: str,
        peer_ip: str,
        tracker: PrefixStateTrackerV5,
        as_path: List[int],
        count: int = 2) -> List[dict]:
    """
    FIX #4: Generate duplicates independently of stability.
    Any prefix can have duplicates.
    """
    events = []
    current_time = 0.0

    for i in range(count):
        result = tracker.announce_prefix(peer_ip, prefix, as_path, current_time)
        events.append({
            'time': current_time,
            'action': 'announce',
            'prefix': prefix,
            'as_path': as_path,
            'duplicate_index': i,
            **result
        })
        current_time += random.uniform(0.001, 0.1)

    return events


# =============================================================================
# SECTION 8: MASTER TRAFFIC GENERATOR V5
# =============================================================================

def generate_enhanced_normal_traffic_v5(
        tracker: PrefixStateTrackerV5,
        peer_ip: str,
        tier1_ases: List[int],
        tier2_ases: List[int],
        rare_as_pool: List[int],
        prefixes: List[str],
        target_events: int = 20) -> List[dict]:
    """
    V5 Traffic Generator with FIXED correlations.

    KEY CHANGES:
    1. NADAS: W→A sequences with new ASes
    2. imp_wd_dpath decoupled from path length (70% substitutions)
    3. Partial flap-withdrawal coupling (50-60%)
    4. Independent duplicates
    5. Co-located imp_wd_spath + withdrawals
    6. Edit distance bursts
    """
    all_events = []

    for _ in range(target_events):
        prefix = random.choice(prefixes)
        profile = tracker.get_or_create_profile(prefix)

        # Select origin AS based on profile
        if profile.activity_level == 'unstable':
            origin_as = random.choice(rare_as_pool[:1500])
        elif profile.activity_level == 'high':
            origin_as = random.choice(rare_as_pool[:3000] if random.random() < 0.6 else tier2_ases)
        elif profile.activity_level == 'normal':
            origin_as = random.choice(tier2_ases if random.random() < 0.7 else rare_as_pool[:2000])
        else:
            origin_as = random.choice(tier2_ases if random.random() < 0.8 else tier1_ases)

        # === PATTERN SELECTION ===
        pattern_roll = random.random()

        if profile.is_flapping and profile.flap_intensity > 0 and pattern_roll < 0.25:
            # Flapping with partial withdrawal (FIX #3)
            events = generate_flapping_sequence_v5(
                prefix, peer_ip, tracker, origin_as,
                tier1_ases, tier2_ases, rare_as_pool,
                flap_count=profile.flap_intensity
            )
            all_events.extend(events)
            profile.flap_intensity = max(0, profile.flap_intensity - random.randint(1, 2))

        elif profile.has_explicit_withdrawals and profile.withdrawal_count > 0 and pattern_roll < 0.45:
            # Withdrawal → NADAS sequence (FIX #1)
            events = generate_withdrawal_nadas_sequence(
                prefix, peer_ip, tracker, origin_as,
                tier1_ases, tier2_ases, rare_as_pool
            )
            all_events.extend(events)
            profile.withdrawal_count -= 1

            # FIX #5: Sometimes add imp_wd_spath near withdrawal
            if random.random() < profile.imp_wd_spath_near_withdrawal:
                events = generate_imp_wd_spath_near_withdrawal(
                    prefix, peer_ip, tracker, origin_as,
                    tier2_ases, rare_as_pool
                )
                all_events.extend(events)

        elif random.random() < profile.edit_distance_burst_probability and pattern_roll < 0.60:
            # Edit distance burst (FIX #6)
            events = generate_edit_distance_burst(
                prefix, peer_ip, tracker, origin_as,
                tier2_ases, rare_as_pool
            )
            all_events.extend(events)

        elif random.random() < profile.duplicate_probability:
            # Independent duplicates (FIX #4)
            as_path = generate_as_path_v5(
                origin_as, prefix, tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )
            events = generate_independent_duplicates(
                prefix, peer_ip, tracker, as_path,
                count=random.randint(2, 4)
            )
            all_events.extend(events)

        else:
            # Simple announcement(s) with imp_wd handling
            as_path = generate_as_path_v5(
                origin_as, prefix, tracker,
                tier1_ases, tier2_ases, rare_as_pool
            )

            result = tracker.announce_prefix(peer_ip, prefix, as_path, 0.0)
            all_events.append({
                'time': 0.0,
                'action': 'announce',
                'prefix': prefix,
                'as_path': as_path,
                **result
            })

            # Extra announcements based on profile
            extra_count = random.randint(0, profile.target_announcements - 1)
            last_path = as_path

            for _ in range(extra_count):
                roll = random.random()

                if roll < profile.imp_wd_spath_probability and len(last_path) > 2:
                    # Path shortening
                    new_path, ed, _, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'shorten', False)
                elif roll < profile.imp_wd_spath_probability + profile.imp_wd_dpath_probability:
                    # FIX #2: Different path - 70% use substitution (same length)
                    use_subst = random.random() < profile.imp_wd_uses_substitution_ratio
                    new_path, ed, _, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'dpath', use_subst)
                elif roll < profile.imp_wd_probability:
                    # General implicit withdrawal
                    new_path, ed, _, _ = vary_as_path_v5(last_path, tier2_ases, rare_as_pool, 'random', True)
                else:
                    # Duplicate (same path)
                    new_path = last_path.copy()
                    ed = 0

                result = tracker.announce_prefix(peer_ip, prefix, new_path, 0.0)
                all_events.append({
                    'time': 0.0,
                    'action': 'announce',
                    'prefix': prefix,
                    'as_path': new_path,
                    **result
                })

                last_path = new_path

    return all_events


# =============================================================================
# SECTION 9: MAIN FUNCTION
# =============================================================================

def main():
    """Test the V5 generator."""
    print("=" * 70)
    print("BGP TRAFFIC GENERATOR V5 - CORRELATION-AWARE")
    print("=" * 70)
    print()
    print("TARGET CORRELATIONS:")
    for (f1, f2), corr in REAL_CORRELATIONS.items():
        print(f"  {f1} ↔ {f2}: {corr:.3f}")
    print()
    print("KEY FIXES:")
    print("  1. Withdrawals → NADAS: W→A with NEW ASes")
    print("  2. imp_wd_dpath decoupled: 70% substitutions (same length)")
    print("  3. Partial flap-withdrawal: Only 50-60% of flaps create W")
    print("  4. Independent duplicates: Any prefix can have dups")
    print("  5. Co-located imp_wd_spath + withdrawals")
    print("  6. Edit distance bursts: ED 3-4 cluster together")
    print("=" * 70)

    # Test generation
    tracker = PrefixStateTrackerV5()
    prefixes = [f"192.0.{i}.0/24" for i in range(1, 101)]
    peer_ip = "10.0.0.1"

    events = generate_enhanced_normal_traffic_v5(
        tracker=tracker,
        peer_ip=peer_ip,
        tier1_ases=TIER1_ASES,
        tier2_ases=TIER2_ASES,
        rare_as_pool=RARE_AS_POOL,
        prefixes=prefixes,
        target_events=500
    )

    print(f"\nGenerated {len(events)} events")
    tracker.print_stats()

    # Calculate observed correlations
    print("\nOBSERVED EVENT DISTRIBUTION:")
    event_counts = defaultdict(int)
    for e in events:
        if e['action'] == 'withdraw':
            event_counts['withdrawals'] += 1
        else:
            event_counts['announcements'] += 1
            if e.get('is_nadas'):
                event_counts['nadas'] += 1
            if e.get('is_flap'):
                event_counts['flaps'] += 1
            if e.get('is_duplicate'):
                event_counts['duplicates'] += 1
            if e.get('is_imp_wd'):
                event_counts['imp_wd'] += 1
            if e.get('is_imp_wd_spath'):
                event_counts['imp_wd_spath'] += 1
            if e.get('is_imp_wd_dpath'):
                event_counts['imp_wd_dpath'] += 1

    for event_type, count in sorted(event_counts.items()):
        print(f"  {event_type}: {count}")


if __name__ == "__main__":
    main()

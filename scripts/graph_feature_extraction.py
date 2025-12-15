"""
BGP AS-Level Graph Feature Extraction Module

This module constructs AS-level graphs from BGP data and extracts comprehensive
graph-based features for network topology analysis and anomaly detection.

Author: Enhanced BGP Traffic Generation Project
Date: 2025-11-18
"""

import pandas as pd
import numpy as np
import networkx as nx
from typing import Dict, List, Tuple, Union, Optional
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')


class ASGraphFeatureExtractor:
    """
    Extract graph-based features from AS-level topology constructed from BGP AS_PATH data.

    Features extracted include:
    - Basic topology metrics (nodes, edges, diameter)
    - Centrality measures (eigenvector, harmonic, PageRank, degree, eccentricity)
    - Connectivity measures (algebraic connectivity, node connectivity, effective graph resistance)
    - Clustering coefficients (triangles, square clustering)
    - Robustness metrics (percolation threshold, spanning trees, bridges)
    - Advanced metrics (assortativity, symmetry ratio, natural connectivity)
    """

    def __init__(self):
        """Initialize the feature extractor."""
        self.graph = None
        self.weighted_graph = None
        self.as_path_counts = defaultdict(int)

    def parse_as_path(self, as_path_str: str) -> List[int]:
        """
        Parse AS_PATH string to list of ASNs.

        Args:
            as_path_str: AS_PATH string (e.g., "65001 65002 65003")

        Returns:
            List of ASNs as integers
        """
        if pd.isna(as_path_str) or not as_path_str:
            return []

        # Handle AS_SET (enclosed in {}) by taking first AS
        as_path_str = str(as_path_str).strip()
        asns = []

        for part in as_path_str.split():
            part = part.strip('{}')
            if part.isdigit():
                asns.append(int(part))

        return asns

    def extract_all_ases_from_dataframe(self, df: pd.DataFrame, as_path_column: str = 'AS_Path') -> List[int]:
        """
        Extract all unique ASes from DataFrame's AS_PATH column.

        This is useful when you want to ensure all ASes from your topology are included
        in the graph, even if some don't appear in multi-hop paths.

        Args:
            df: DataFrame containing BGP data with AS_PATH column
            as_path_column: Name of column containing AS_PATH data

        Returns:
            Sorted list of unique ASNs
        """
        all_ases = set()

        for idx, row in df.iterrows():
            if as_path_column not in row:
                continue

            as_path = self.parse_as_path(row[as_path_column])
            all_ases.update(as_path)

        return sorted(list(all_ases))

    def build_graph_from_dataframe(self, df: pd.DataFrame, as_path_column: str = 'AS_Path',
                                   label_column: Optional[str] = 'Label',
                                   label_strategy: str = 'weighted',
                                   topology_ases: Optional[List[int]] = None,
                                   ensure_all_ases: bool = True) -> nx.Graph:
        """
        Build AS-level undirected graph from BGP data DataFrame.

        Args:
            df: DataFrame containing BGP data with AS_PATH column
            as_path_column: Name of column containing AS_PATH data
            label_column: Name of column containing label data (optional)
            label_strategy: Strategy for assigning labels ('majority', 'conservative', 'weighted')
            topology_ases: Optional list of all ASes in the topology to ensure all are included
            ensure_all_ases: If True (default), automatically extract and include all ASes from data

        Returns:
            NetworkX undirected graph
        """
        self.graph = nx.Graph()
        self.weighted_graph = nx.Graph()
        self.as_path_counts = defaultdict(int)
        self.label_strategy = label_strategy

        # Track edge weights (frequency of AS pair in AS_PATHs)
        edge_weights = defaultdict(int)

        # Store DataFrame for label extraction
        self.df = df
        self.label_column = label_column

        # If topology is provided, add all ASes as nodes first
        # Otherwise, if ensure_all_ases is True, extract all ASes from data
        if topology_ases is not None:
            for asn in topology_ases:
                self.graph.add_node(asn)
                self.weighted_graph.add_node(asn)
        elif ensure_all_ases:
            all_ases = self.extract_all_ases_from_dataframe(df, as_path_column)
            for asn in all_ases:
                self.graph.add_node(asn)
                self.weighted_graph.add_node(asn)

        for idx, row in df.iterrows():
            if as_path_column not in row:
                continue

            as_path = self.parse_as_path(row[as_path_column])

            # Include single-AS paths (origin ASes)
            if len(as_path) < 1:
                continue

            # Add nodes for all ASes in path
            for asn in as_path:
                if not self.graph.has_node(asn):
                    self.graph.add_node(asn)
                    self.weighted_graph.add_node(asn)

            # Add edges between consecutive ASes (undirected)
            for i in range(len(as_path) - 1):
                source = as_path[i]
                target = as_path[i + 1]

                # Create canonical edge (smaller ASN first)
                edge = tuple(sorted([source, target]))
                edge_weights[edge] += 1

                if not self.graph.has_edge(source, target):
                    self.graph.add_edge(source, target)

            # Track AS path frequency for weighted analysis
            path_tuple = tuple(as_path)
            self.as_path_counts[path_tuple] += 1

        # Build weighted graph
        for (u, v), weight in edge_weights.items():
            self.weighted_graph.add_edge(u, v, weight=weight)

        print(f"Graph constructed: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")

        return self.graph

    def build_graph_from_csv(self, csv_path: str, as_path_column: str = 'AS_Path',
                            label_column: Optional[str] = 'Label',
                            label_strategy: str = 'weighted',
                            topology_ases: Optional[List[int]] = None,
                            ensure_all_ases: bool = True) -> nx.Graph:
        """
        Build AS-level graph from CSV file containing BGP data.

        Args:
            csv_path: Path to CSV file
            as_path_column: Name of column containing AS_PATH data
            label_column: Name of column containing label data (optional)
            label_strategy: Strategy for assigning labels ('majority', 'conservative', 'weighted')
            topology_ases: Optional list of all ASes in the topology to ensure all are included
            ensure_all_ases: If True (default), automatically extract and include all ASes from data

        Returns:
            NetworkX undirected graph
        """
        df = pd.read_csv(csv_path)
        return self.build_graph_from_dataframe(df, as_path_column, label_column, label_strategy,
                                               topology_ases, ensure_all_ases)

    def extract_label(self) -> str:
        """
        Extract label from DataFrame based on configured strategy.

        Returns:
            Label string based on strategy
        """
        if self.df is None or self.label_column is None:
            return 'unknown'

        if self.label_column not in self.df.columns:
            return 'unknown'

        labels = self.df[self.label_column].value_counts()

        if labels.empty:
            return 'unknown'

        # Apply label strategy (matching feature_exctration.ipynb)
        if self.label_strategy == 'majority':
            # Majority vote
            return labels.idxmax()

        elif self.label_strategy == 'conservative':
            # If any abnormal, label as abnormal
            if any(label != 'normal' for label in labels.index):
                abnormal_labels = [label for label in labels.index if label != 'normal']
                return abnormal_labels[0]
            else:
                return 'normal'

        elif self.label_strategy == 'weighted':
            # Weight by count of each label
            total = labels.sum()
            abnormal_weight = sum(count for label, count in labels.items() if label != 'normal') / total
            if abnormal_weight > 0.3:  # Threshold for abnormal classification
                abnormal_labels = [label for label in labels.index if label != 'normal']
                return abnormal_labels[0] if abnormal_labels else 'normal'
            else:
                return 'normal'

        return 'unknown'

    def print_graph_summary(self) -> None:
        """
        Print a comprehensive summary of the constructed graph including topology stats.

        This provides better formatted output than the basic print statement.
        """
        if self.graph is None:
            print("No graph has been constructed yet.")
            return

        # Basic graph info
        num_nodes = self.graph.number_of_nodes()
        num_edges = self.graph.number_of_edges()

        # Calculate density
        max_edges = num_nodes * (num_nodes - 1) / 2
        density = num_edges / max_edges if max_edges > 0 else 0

        # Check connectivity
        is_connected = nx.is_connected(self.graph)

        print("\n" + "="*60)
        print("📊 AS-Level Graph Summary")
        print("="*60)
        print(f"Nodes (ASes):      {num_nodes}")
        print(f"Edges (Links):     {num_edges}")
        print(f"Graph Density:     {density:.4f}")
        print(f"Connected:         {'Yes' if is_connected else 'No'}")

        if not is_connected:
            num_components = nx.number_connected_components(self.graph)
            largest_cc_size = len(max(nx.connected_components(self.graph), key=len))
            print(f"Components:        {num_components}")
            print(f"Largest Component: {largest_cc_size} nodes")

        # Only show label information if label column was specified
        if self.label_column is not None and self.df is not None:
            label = self.extract_label()
            print(f"\n🏷️  Traffic Label:    {label.upper()}")

            if self.label_column in self.df.columns:
                label_dist = self.df[self.label_column].value_counts()
                print(f"\nLabel Distribution in Data:")
                for lbl, count in label_dist.items():
                    pct = (count / len(self.df)) * 100
                    print(f"  {lbl}: {count} ({pct:.1f}%)")

        print("="*60 + "\n")

    def extract_basic_metrics(self) -> Dict[str, Union[int, float]]:
        """
        Extract basic graph metrics.

        Returns:
            Dictionary containing:
            - num_nodes: Number of nodes (ASes)
            - num_edges: Number of edges (AS connections)
            - diameter: Longest shortest path
            - num_triangles: Total number of triangles
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Use largest connected component for diameter
        if nx.is_connected(self.graph):
            G = self.graph
        else:
            # Use largest connected component
            largest_cc = max(nx.connected_components(self.graph), key=len)
            G = self.graph.subgraph(largest_cc).copy()

        metrics['num_nodes'] = self.graph.number_of_nodes()
        metrics['num_edges'] = self.graph.number_of_edges()

        try:
            metrics['diameter'] = nx.diameter(G)
        except:
            metrics['diameter'] = -1  # Graph disconnected or single node

        # Count triangles
        triangles = nx.triangles(self.graph)
        metrics['num_triangles'] = sum(triangles.values()) // 3  # Each triangle counted 3 times

        return metrics

    def extract_centrality_metrics(self) -> Dict[str, Union[float, Dict[int, float]]]:
        """
        Extract centrality-based metrics.

        Returns:
            Dictionary containing:
            - eigenvector_centrality_avg: Average eigenvector centrality
            - harmonic_centrality_avg: Average harmonic centrality
            - pagerank_avg: Average PageRank score
            - degree_centrality_avg: Average degree centrality
            - eccentricity_avg: Average eccentricity
            - plus per-node dictionaries for detailed analysis
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Use largest connected component for metrics requiring connectivity
        if nx.is_connected(self.graph):
            G = self.graph
        else:
            largest_cc = max(nx.connected_components(self.graph), key=len)
            G = self.graph.subgraph(largest_cc).copy()

        # Eigenvector centrality
        try:
            eig_cent = nx.eigenvector_centrality(G, max_iter=1000)
            metrics['eigenvector_centrality_avg'] = np.mean(list(eig_cent.values()))
            metrics['eigenvector_centrality_max'] = np.max(list(eig_cent.values()))
            metrics['eigenvector_centrality_per_node'] = eig_cent
        except:
            metrics['eigenvector_centrality_avg'] = 0.0
            metrics['eigenvector_centrality_max'] = 0.0
            metrics['eigenvector_centrality_per_node'] = {}

        # Harmonic centrality
        harm_cent = nx.harmonic_centrality(G)
        metrics['harmonic_centrality_avg'] = np.mean(list(harm_cent.values()))
        metrics['harmonic_centrality_max'] = np.max(list(harm_cent.values()))
        metrics['harmonic_centrality_per_node'] = harm_cent

        # PageRank
        pagerank = nx.pagerank(G)
        metrics['pagerank_avg'] = np.mean(list(pagerank.values()))
        metrics['pagerank_max'] = np.max(list(pagerank.values()))
        metrics['pagerank_per_node'] = pagerank

        # Degree centrality
        deg_cent = nx.degree_centrality(self.graph)
        metrics['degree_centrality_avg'] = np.mean(list(deg_cent.values()))
        metrics['degree_centrality_max'] = np.max(list(deg_cent.values()))
        metrics['degree_centrality_per_node'] = deg_cent

        # Eccentricity
        try:
            ecc = nx.eccentricity(G)
            metrics['eccentricity_avg'] = np.mean(list(ecc.values()))
            metrics['eccentricity_max'] = np.max(list(ecc.values()))
            metrics['eccentricity_per_node'] = ecc
        except:
            metrics['eccentricity_avg'] = -1
            metrics['eccentricity_max'] = -1
            metrics['eccentricity_per_node'] = {}

        return metrics

    def extract_connectivity_metrics(self) -> Dict[str, float]:
        """
        Extract connectivity-based metrics.

        Returns:
            Dictionary containing:
            - algebraic_connectivity: Second smallest eigenvalue of Laplacian
            - node_connectivity: Minimum nodes to disconnect graph
            - effective_graph_resistance: Sum of resistance distances
            - natural_connectivity: Robustness measure
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Use largest connected component
        if nx.is_connected(self.graph):
            G = self.graph
        else:
            largest_cc = max(nx.connected_components(self.graph), key=len)
            G = self.graph.subgraph(largest_cc).copy()

        # Algebraic connectivity (Fiedler value)
        try:
            metrics['algebraic_connectivity'] = nx.algebraic_connectivity(G)
        except:
            metrics['algebraic_connectivity'] = 0.0

        # Node connectivity
        try:
            metrics['node_connectivity'] = nx.node_connectivity(G)
        except:
            metrics['node_connectivity'] = 0

        # Effective graph resistance
        try:
            # EGR = n * sum(1/λi) for non-zero eigenvalues of Laplacian
            laplacian = nx.laplacian_matrix(G).todense()
            eigenvalues = np.linalg.eigvalsh(laplacian)
            eigenvalues = eigenvalues[eigenvalues > 1e-10]  # Filter near-zero

            if len(eigenvalues) > 0:
                metrics['effective_graph_resistance'] = G.number_of_nodes() * np.sum(1.0 / eigenvalues)
            else:
                metrics['effective_graph_resistance'] = float('inf')
        except:
            metrics['effective_graph_resistance'] = -1.0

        # Natural connectivity
        try:
            # Natural connectivity = ln(avg(e^λi)) where λi are adjacency eigenvalues
            adj_matrix = nx.adjacency_matrix(G).todense()
            eigenvalues = np.linalg.eigvalsh(adj_matrix)
            metrics['natural_connectivity'] = np.log(np.mean(np.exp(eigenvalues)))
        except:
            metrics['natural_connectivity'] = 0.0

        return metrics

    def extract_clustering_metrics(self) -> Dict[str, float]:
        """
        Extract clustering and assortativity metrics.

        Returns:
            Dictionary containing:
            - assortativity: Degree assortativity coefficient
            - square_clustering_avg: Average square clustering coefficient
            - avg_clustering: Average clustering coefficient (triangles)
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Assortativity
        try:
            metrics['assortativity'] = nx.degree_assortativity_coefficient(self.graph)
        except:
            metrics['assortativity'] = 0.0

        # Square clustering coefficient (4-cycles)
        try:
            square_clust = nx.square_clustering(self.graph)
            metrics['square_clustering_avg'] = np.mean(list(square_clust.values()))
            metrics['square_clustering_max'] = np.max(list(square_clust.values()))
            metrics['square_clustering_per_node'] = square_clust
        except:
            metrics['square_clustering_avg'] = 0.0
            metrics['square_clustering_max'] = 0.0
            metrics['square_clustering_per_node'] = {}

        # Average clustering coefficient (triangles)
        metrics['avg_clustering'] = nx.average_clustering(self.graph)

        return metrics

    def extract_robustness_metrics(self) -> Dict[str, Union[int, float]]:
        """
        Extract robustness and structural metrics.

        Returns:
            Dictionary containing:
            - num_spanning_trees: Number of spanning trees (complexity)
            - num_bridges: Number of critical edges
            - num_articulation_points: Number of critical nodes
            - largest_component_size: Size of largest connected component
            - num_components: Number of disconnected components
            - percolation_threshold: Estimated percolation threshold
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Number of connected components
        components = list(nx.connected_components(self.graph))
        metrics['num_components'] = len(components)

        # Largest connected component size
        metrics['largest_component_size'] = len(max(components, key=len))

        # Bridges (critical edges)
        bridges = list(nx.bridges(self.graph))
        metrics['num_bridges'] = len(bridges)

        # Articulation points (critical nodes)
        articulation_points = list(nx.articulation_points(self.graph))
        metrics['num_articulation_points'] = len(articulation_points)

        # Number of spanning trees (Kirchhoff's theorem)
        try:
            if nx.is_connected(self.graph):
                # Use Kirchhoff's matrix-tree theorem
                # Number of spanning trees = any cofactor of Laplacian
                G = self.graph
                laplacian = nx.laplacian_matrix(G).todense()

                # Remove first row and column (cofactor)
                cofactor = laplacian[1:, 1:]

                # Determinant gives number of spanning trees
                num_trees = int(round(np.linalg.det(cofactor)))
                metrics['num_spanning_trees'] = num_trees
            else:
                metrics['num_spanning_trees'] = 0
        except:
            metrics['num_spanning_trees'] = -1

        # Percolation threshold estimation
        try:
            # Approximate: Pc ≈ <k> / (<k²> - <k>)
            degrees = [d for n, d in self.graph.degree()]
            k_avg = np.mean(degrees)
            k2_avg = np.mean([d**2 for d in degrees])

            denominator = k2_avg - k_avg
            if denominator > 0:
                metrics['percolation_threshold'] = k_avg / denominator
            else:
                metrics['percolation_threshold'] = 1.0
        except:
            metrics['percolation_threshold'] = -1.0

        return metrics

    def extract_advanced_metrics(self) -> Dict[str, float]:
        """
        Extract advanced graph metrics.

        Returns:
            Dictionary containing:
            - symmetry_ratio: Graph symmetry measure
            - weighted_spectral_radius: Largest eigenvalue of weighted adjacency
            - avg_global_efficiency: Average inverse shortest path length
            - mean_degree_neighborhood: Average neighbor degree
            - num_cliques: Total number of maximal cliques
            - max_clique_size: Size of largest clique
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        metrics = {}

        # Use largest connected component for metrics requiring connectivity
        if nx.is_connected(self.graph):
            G = self.graph
        else:
            largest_cc = max(nx.connected_components(self.graph), key=len)
            G = self.graph.subgraph(largest_cc).copy()

        # Symmetry ratio (automorphism-based, approximated by degree distribution entropy)
        try:
            degrees = [d for n, d in self.graph.degree()]
            degree_counts = Counter(degrees)
            total = sum(degree_counts.values())

            # Normalized entropy as symmetry proxy
            entropy = -sum((count/total) * np.log(count/total) for count in degree_counts.values())
            max_entropy = np.log(len(degree_counts))

            if max_entropy > 0:
                metrics['symmetry_ratio'] = entropy / max_entropy
            else:
                metrics['symmetry_ratio'] = 0.0
        except:
            metrics['symmetry_ratio'] = 0.0

        # Weighted spectral radius
        try:
            if self.weighted_graph is not None:
                adj_matrix = nx.adjacency_matrix(self.weighted_graph, weight='weight').todense()
                eigenvalues = np.linalg.eigvals(adj_matrix)
                metrics['weighted_spectral_radius'] = float(np.max(np.abs(eigenvalues)).real)
            else:
                metrics['weighted_spectral_radius'] = 0.0
        except:
            metrics['weighted_spectral_radius'] = 0.0

        # Average global efficiency
        try:
            metrics['avg_global_efficiency'] = nx.global_efficiency(G)
        except:
            metrics['avg_global_efficiency'] = 0.0

        # Mean degree of neighborhood
        try:
            neighbor_degrees = nx.average_neighbor_degree(self.graph)
            metrics['mean_degree_neighborhood_avg'] = np.mean(list(neighbor_degrees.values()))
            metrics['mean_degree_neighborhood_max'] = np.max(list(neighbor_degrees.values()))
        except:
            metrics['mean_degree_neighborhood_avg'] = 0.0
            metrics['mean_degree_neighborhood_max'] = 0.0

        # Number of maximal cliques
        try:
            cliques = list(nx.find_cliques(self.graph))
            metrics['num_cliques'] = len(cliques)
            metrics['max_clique_size'] = max(len(c) for c in cliques) if cliques else 0
        except:
            metrics['num_cliques'] = 0
            metrics['max_clique_size'] = 0

        return metrics

    def extract_node_specific_metrics(self) -> pd.DataFrame:
        """
        Extract per-node metrics for detailed analysis.

        Returns:
            DataFrame with columns:
            - asn: Autonomous System Number
            - degree: Node degree
            - harmonic_centrality: Harmonic centrality
            - pagerank: PageRank score
            - eigenvector_centrality: Eigenvector centrality
            - eccentricity: Eccentricity
            - square_clustering: Square clustering coefficient
            - node_clique_number: Size of largest clique containing node
            - proximity: Average distance to other nodes
            - mediation_centrality: Betweenness centrality (mediation)
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        # Use largest connected component for metrics requiring connectivity
        if nx.is_connected(self.graph):
            G = self.graph
        else:
            largest_cc = max(nx.connected_components(self.graph), key=len)
            G = self.graph.subgraph(largest_cc).copy()

        node_data = []

        # Pre-compute metrics
        try:
            harmonic_cent = nx.harmonic_centrality(G)
        except:
            harmonic_cent = {n: 0.0 for n in G.nodes()}

        try:
            pagerank = nx.pagerank(G)
        except:
            pagerank = {n: 1.0/G.number_of_nodes() for n in G.nodes()}

        try:
            eig_cent = nx.eigenvector_centrality(G, max_iter=1000)
        except:
            eig_cent = {n: 0.0 for n in G.nodes()}

        try:
            eccentricity = nx.eccentricity(G)
        except:
            eccentricity = {n: -1 for n in G.nodes()}

        try:
            square_clust = nx.square_clustering(self.graph)
        except:
            square_clust = {n: 0.0 for n in self.graph.nodes()}

        try:
            betweenness = nx.betweenness_centrality(G)
        except:
            betweenness = {n: 0.0 for n in G.nodes()}

        try:
            node_clique_num = nx.node_clique_number(self.graph)
        except:
            node_clique_num = {n: 1 for n in self.graph.nodes()}

        # Compute proximity (average shortest path length from node)
        proximity = {}
        try:
            for node in G.nodes():
                lengths = nx.single_source_shortest_path_length(G, node)
                if len(lengths) > 1:
                    proximity[node] = np.mean(list(lengths.values()))
                else:
                    proximity[node] = 0.0
        except:
            proximity = {n: 0.0 for n in G.nodes()}

        # Collect data for all nodes
        for node in self.graph.nodes():
            node_data.append({
                'asn': node,
                'degree': self.graph.degree(node),
                'harmonic_centrality': harmonic_cent.get(node, 0.0),
                'pagerank': pagerank.get(node, 0.0),
                'eigenvector_centrality': eig_cent.get(node, 0.0),
                'eccentricity': eccentricity.get(node, -1),
                'square_clustering': square_clust.get(node, 0.0),
                'node_clique_number': node_clique_num.get(node, 1),
                'proximity': proximity.get(node, 0.0),
                'mediation_centrality': betweenness.get(node, 0.0)
            })

        return pd.DataFrame(node_data)

    def extract_all_features(self) -> Dict[str, Union[int, float]]:
        """
        Extract all graph-level features in one call.

        Returns:
            Dictionary containing all graph-level metrics (excluding per-node details)
        """
        if self.graph is None:
            raise ValueError("Graph not built. Call build_graph_from_* first.")

        all_features = {}

        print("Extracting basic metrics...")
        all_features.update(self.extract_basic_metrics())

        print("Extracting centrality metrics...")
        centrality = self.extract_centrality_metrics()
        # Only keep aggregated values, not per-node dictionaries
        all_features.update({k: v for k, v in centrality.items() if not k.endswith('_per_node')})

        print("Extracting connectivity metrics...")
        all_features.update(self.extract_connectivity_metrics())

        print("Extracting clustering metrics...")
        clustering = self.extract_clustering_metrics()
        all_features.update({k: v for k, v in clustering.items() if not k.endswith('_per_node')})

        print("Extracting robustness metrics...")
        all_features.update(self.extract_robustness_metrics())

        print("Extracting advanced metrics...")
        all_features.update(self.extract_advanced_metrics())

        # Extract label only if label column was specified
        if self.label_column is not None:
            print("Extracting label...")
            all_features['label'] = self.extract_label()

        return all_features


def extract_features_from_csv(csv_path: str,
                              as_path_column: str = 'AS_Path',
                              label_column: Optional[str] = 'Label',
                              label_strategy: str = 'weighted',
                              topology_ases: Optional[List[int]] = None,
                              ensure_all_ases: bool = True,
                              output_csv: Optional[str] = None,
                              print_summary: bool = True) -> pd.DataFrame:
    """
    Convenience function to extract all graph features from a CSV file.

    Args:
        csv_path: Path to CSV file containing BGP data
        as_path_column: Name of column containing AS_PATH data
        label_column: Name of column containing label data (None to skip)
        label_strategy: Strategy for label assignment ('majority', 'conservative', 'weighted')
        topology_ases: Optional list of all ASes in the topology to ensure all are included
        ensure_all_ases: If True (default), automatically extract and include all ASes from data
        output_csv: Optional path to save results as CSV
        print_summary: If True (default), print graph summary after construction

    Returns:
        DataFrame with graph features (1 row for the entire graph)
    """
    extractor = ASGraphFeatureExtractor()
    extractor.build_graph_from_csv(csv_path, as_path_column, label_column, label_strategy,
                                   topology_ases, ensure_all_ases)

    # Print summary if requested
    if print_summary:
        extractor.print_graph_summary()

    features = extractor.extract_all_features()

    # Convert to DataFrame
    df = pd.DataFrame([features])

    if output_csv:
        df.to_csv(output_csv, index=False)
        print(f"Graph features saved to {output_csv}")

    return df


def extract_node_features_from_csv(csv_path: str,
                                   as_path_column: str = 'AS_Path',
                                   label_column: Optional[str] = 'Label',
                                   label_strategy: str = 'weighted',
                                   topology_ases: Optional[List[int]] = None,
                                   ensure_all_ases: bool = True,
                                   output_csv: Optional[str] = None,
                                   print_summary: bool = True) -> pd.DataFrame:
    """
    Convenience function to extract per-node features from a CSV file.

    Args:
        csv_path: Path to CSV file containing BGP data
        as_path_column: Name of column containing AS_PATH data
        label_column: Name of column containing label data (None to skip)
        label_strategy: Strategy for label assignment ('majority', 'conservative', 'weighted')
        topology_ases: Optional list of all ASes in the topology to ensure all are included
        ensure_all_ases: If True (default), automatically extract and include all ASes from data
        output_csv: Optional path to save results as CSV
        print_summary: If True (default), print graph summary after construction

    Returns:
        DataFrame with per-node features
    """
    extractor = ASGraphFeatureExtractor()
    extractor.build_graph_from_csv(csv_path, as_path_column, label_column, label_strategy,
                                   topology_ases, ensure_all_ases)

    # Print summary if requested
    if print_summary:
        extractor.print_graph_summary()

    node_df = extractor.extract_node_specific_metrics()

    if output_csv:
        node_df.to_csv(output_csv, index=False)
        print(f"Node features saved to {output_csv}")

    return node_df


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 2:
        print("Usage: python graph_feature_extraction.py <bgp_data.csv> [as_path_column] [label_column] [label_strategy]")
        print("Example: python graph_feature_extraction.py ../Data_Set/bgp_updates_analysis.csv AS_Path Label weighted")
        print("\nLabel strategies: 'majority', 'conservative', 'weighted'")
        print("  - majority: Most frequent label wins")
        print("  - conservative: Any abnormal label marks window as abnormal")
        print("  - weighted: Abnormal if >30% of updates are abnormal")
        sys.exit(1)

    csv_path = sys.argv[1]
    as_path_col = sys.argv[2] if len(sys.argv) > 2 else 'AS_Path'
    label_col = sys.argv[3] if len(sys.argv) > 3 else 'Label'
    label_strategy = sys.argv[4] if len(sys.argv) > 4 else 'weighted'

    print(f"Loading BGP data from {csv_path}...")
    print(f"Using AS_PATH column: {as_path_col}")
    print(f"Using Label column: {label_col}")
    print(f"Label strategy: {label_strategy}")
    print("-" * 80)

    # Extract graph-level features
    graph_features = extract_features_from_csv(
        csv_path,
        as_path_column=as_path_col,
        label_column=label_col,
        label_strategy=label_strategy,
        output_csv='graph_features.csv'
    )

    print("\n" + "=" * 80)
    print("GRAPH-LEVEL FEATURES")
    print("=" * 80)
    print(graph_features.T.to_string())

    # Extract per-node features
    node_features = extract_node_features_from_csv(
        csv_path,
        as_path_column=as_path_col,
        label_column=label_col,
        label_strategy=label_strategy,
        output_csv='node_features.csv'
    )

    print("\n" + "=" * 80)
    print("PER-NODE FEATURES (Top 10 by degree)")
    print("=" * 80)
    print(node_features.sort_values('degree', ascending=False).head(10).to_string(index=False))
